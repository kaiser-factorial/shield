/**
 * Streaming support for the SDK client wrappers.
 *
 * Canary checking on streamed responses used to be skipped entirely — the
 * response body only exists as it's consumed. The tap below closes that gap
 * without buffering anything itself: it wraps the stream's own async
 * iterator so text deltas accumulate as the CALLER consumes them, and the
 * output check runs when the stream ends (or is abandoned early, on whatever
 * accumulated by then). Everything else on the stream object is untouched.
 *
 * Tool calls in a raw stream are the second gap, and the more serious one.
 * A non-streaming response is a finished object: the wrapper reads its
 * tool_use blocks, evaluates them, and can strip the blocked ones before the
 * caller ever sees them. A raw `create({ stream: true })` stream has no such
 * object — the tool call arrives in fragments (a start event, a run of
 * partial-JSON deltas, a stop event) — so until now the policy simply never
 * ran on it. An app that streams got scanning but no gating, which looks
 * exactly like gating that works.
 *
 * The assemblers below rebuild each call from its fragments and hand it over
 * the moment it is complete, which is *before* the caller can act on it: a
 * tool call is executed by the caller after the stream yields it, not by the
 * SDK. So evaluating at completion is genuinely in time. Under
 * `enforceToolPolicy` a blocked call throws `ShieldBlockedToolError` out of
 * the iterator, which is the streaming equivalent of stripping the block.
 */

import type { ToolCall } from "./output.js";

/** Rebuilds tool calls from the fragments a raw stream delivers them in. */
export interface ToolAssembler {
  /** Feed one stream event; returns any calls this event completed. */
   
  push(ev: any): ToolCall[];
  /** Calls still open when the stream ended — a truncated stream still shows intent. */
  flush(): ToolCall[];
}

export interface StreamTapOptions {
  /** Text carried by one event, "" for events that carry none. */
   
  text(ev: any): string;
  /** Fresh assembler per iteration; omit for streams that cannot carry tools. */
  tools?: () => ToolAssembler;
  /** Called once with everything that accumulated, on end or abandonment. */
  onText(text: string): void;
  /** Called per assembled call. Throwing here aborts the stream — that is how
   *  enforcement is expressed on a stream. */
  onToolCall?(call: ToolCall): void;
}

 
export function tapEventStream(stream: any, opts: StreamTapOptions): any {
  if (!stream || typeof stream[Symbol.asyncIterator] !== "function") return stream;
  const makeIter = stream[Symbol.asyncIterator].bind(stream);
  Object.defineProperty(stream, Symbol.asyncIterator, {
    configurable: true,
    value: () => {
      const it = makeIter();
      const tools = opts.tools ? opts.tools() : null;
      let buf = "";
      let finished = false;

      const finish = () => {
        if (finished) return;
        finished = true;
        try { opts.onText(buf); } catch { /* observation must never break streaming */ }
        // A stream cut off mid-call still shows what the model was reaching
        // for; report it rather than dropping it. This runs after the text
        // check so a truncated response is never left unscanned.
        if (tools && opts.onToolCall) {
          let open: ToolCall[] = [];
          try { open = tools.flush(); } catch { /* ignore */ }
          for (const c of open) {
            try { opts.onToolCall(c); } catch { /* the stream is already over */ }
          }
        }
      };

      return {
        async next() {
          let r;
          try {
            r = await it.next();
          } catch (e) {
            // A stream that fails partway still emitted text, and that text can
            // still contain the canary. Without this the partial output was
            // never checked — the one case where a leak is most likely to slip
            // through is a response that broke off mid-answer.
            finish();
            throw e;
          }
          if (r.done) { finish(); return r; }

          // A malformed chunk must not throw into the consumer's loop.
          try { buf += opts.text(r.value) ?? ""; } catch { /* ignore */ }

          if (tools && opts.onToolCall) {
            let completed: ToolCall[] = [];
            try { completed = tools.push(r.value); } catch { /* ignore */ }
            // Deliberately NOT swallowed: onToolCall throws to block, and that
            // has to reach the caller. Assembly errors above are ignored;
            // a policy decision is not an error to hide.
            for (const c of completed) opts.onToolCall(c);
          }
          return r;
        },
        async return(v?: unknown) {
          finish();
          return it.return ? it.return(v) : { done: true, value: v };
        },
        async throw(e?: unknown) {
          // Same reasoning as the catch above: abandoning via throw() still
          // leaves accumulated text worth checking. `return()` already did this;
          // the two paths disagreeing was an oversight, not a decision.
          finish();
          if (it.throw) return it.throw(e);
          throw e;
        },
        [Symbol.asyncIterator]() { return this; },
      };
    },
  });
  return stream;
}

/** Parse assembled argument JSON, keeping the raw string when it doesn't parse. */
function parseArgs(raw: string): unknown {
  const t = raw.trim();
  if (!t) return {};
  try { return JSON.parse(t); } catch { return t; }
}

/**
 * Anthropic raw stream: content_block_start(tool_use) → a run of
 * content_block_delta(input_json_delta) → content_block_stop, keyed by index.
 */
export function anthropicToolAssembler(): ToolAssembler {
  const open = new Map<number, { name: string; id?: string; json: string }>();
  return {
     
    push(ev: any): ToolCall[] {
      if (ev?.type === "content_block_start" && ev.content_block?.type === "tool_use") {
        open.set(ev.index, { name: ev.content_block.name, id: ev.content_block.id, json: "" });
        return [];
      }
      if (ev?.type === "content_block_delta" && ev.delta?.type === "input_json_delta") {
        const slot = open.get(ev.index);
        if (slot) slot.json += ev.delta.partial_json ?? "";
        return [];
      }
      if (ev?.type === "content_block_stop") {
        const slot = open.get(ev.index);
        if (!slot) return [];
        open.delete(ev.index);
        return [{ name: slot.name, input: parseArgs(slot.json), id: slot.id }];
      }
      return [];
    },
    flush(): ToolCall[] {
      const rest = [...open.values()].map((s) => ({ name: s.name, input: parseArgs(s.json), id: s.id }));
      open.clear();
      return rest;
    },
  };
}

/**
 * OpenAI chat-completions raw stream: delta.tool_calls fragments keyed by
 * index, finished by finish_reason "tool_calls" (or by the stream ending).
 */
export function openAIChatToolAssembler(): ToolAssembler {
  const open = new Map<number, { name: string; id?: string; json: string }>();
  const drain = (): ToolCall[] => {
    const out = [...open.values()]
      .filter((s) => s.name)
      .map((s) => ({ name: s.name, input: parseArgs(s.json), id: s.id }));
    open.clear();
    return out;
  };
  return {
     
    push(ev: any): ToolCall[] {
      const choice = ev?.choices?.[0];
      const frags = choice?.delta?.tool_calls;
      if (Array.isArray(frags)) {
        for (const f of frags) {
          const i = typeof f?.index === "number" ? f.index : 0;
          const slot = open.get(i) ?? { name: "", json: "" };
          if (f?.id) slot.id = f.id;
          if (f?.function?.name) slot.name += f.function.name;
          if (f?.function?.arguments) slot.json += f.function.arguments;
          open.set(i, slot);
        }
      }
      // finish_reason arrives on its own final chunk, after every fragment.
      return choice?.finish_reason === "tool_calls" ? drain() : [];
    },
    flush: drain,
  };
}

/**
 * OpenAI Responses API raw stream: output_item.added(function_call) → a run of
 * function_call_arguments.delta → function_call_arguments.done, keyed by item id.
 */
export function openAIResponsesToolAssembler(): ToolAssembler {
  const open = new Map<string, { name: string; id?: string; json: string }>();
  return {
     
    push(ev: any): ToolCall[] {
      if (ev?.type === "response.output_item.added" && ev.item?.type === "function_call") {
        const key = ev.item.id ?? ev.item.call_id ?? String(ev.output_index ?? 0);
        open.set(key, { name: ev.item.name ?? "", id: ev.item.call_id ?? ev.item.id, json: "" });
        return [];
      }
      if (ev?.type === "response.function_call_arguments.delta") {
        const slot = open.get(ev.item_id);
        if (slot) slot.json += ev.delta ?? "";
        return [];
      }
      if (ev?.type === "response.function_call_arguments.done") {
        const slot = open.get(ev.item_id);
        if (!slot) return [];
        open.delete(ev.item_id);
        // The done event carries the complete arguments; prefer it over our
        // accumulation, which a dropped delta would leave short.
        return [{ name: slot.name, input: parseArgs(ev.arguments ?? slot.json), id: slot.id }];
      }
      return [];
    },
    flush(): ToolCall[] {
      const rest = [...open.values()]
        .filter((s) => s.name)
        .map((s) => ({ name: s.name, input: parseArgs(s.json), id: s.id }));
      open.clear();
      return rest;
    },
  };
}
