/**
 * ShieldAnthropicClient — drop-in wrapper around the Anthropic SDK.
 *
 * Uses structural typing (duck typing) for the inner client so it works
 * regardless of which version of @anthropic-ai/sdk the caller has installed.
 *
 * Usage:
 *   import Anthropic from "@anthropic-ai/sdk";
 *   import { shieldAnthropic } from "prompt-shield";
 *   const client = shieldAnthropic(new Anthropic(), { appLabel: "my-app" });
 *
 *   // Then use exactly as before — the return type is the type you passed in:
 *   const res = await client.messages.create({ ... });
 *
 * Coverage is deny-by-default (see coverage.ts): `messages.create/parse/
 * stream` are shielded, `messages.countTokens` and `models` pass through, and
 * anything else that could carry a prompt to the model (`beta`, `completions`,
 * `messages.batches`, `withOptions`) throws ShieldCoverageError unless you
 * list it in `passthrough`.
 */

import {
  generateCanary,
  hardenSystemPrompt,
  securityBoilerplate,
  wrapUntrusted,
  type InjectionScan,
} from "./shield.js";
import { tapEventStream, anthropicToolAssembler } from "./stream.js";
import { guarded, nestedPassthrough } from "./coverage.js";
import { createShield, type Shield } from "./instance.js";
import { ShieldBlockedToolError, type ToolCall } from "./output.js";

// Structural interface — matches the Anthropic SDK without importing it
 
export interface AnthropicMessagesLike {
  create(params: any, options?: any): Promise<any>;
  parse?(params: any, options?: any): Promise<any>;
  stream?(params: any, options?: any): any;
  countTokens?(params: any, options?: any): Promise<any>;
}

export interface AnthropicLike {
  messages: AnthropicMessagesLike;
}

/** The messages surface as seen through the wrapper: covered methods are always present. */
export interface ShieldedAnthropicMessages extends AnthropicMessagesLike {
  parse(params: any, options?: any): Promise<any>;
  stream(params: any, options?: any): any;
}
 

export interface ShieldAnthropicOptions {
  /** Wrap user message content in <untrusted_user_message> blocks.
   *  Enable when messages contain external content (fetched pages, transcripts). */
  wrapUserMessages?: boolean;
  /** Wrap tool_result content in <untrusted_tool_result> blocks (default true).
   *  Tool results are machine-fetched external content — the main indirect
   *  injection vector in agentic apps — so unlike user messages this is on
   *  by default. Detection scanning of tool results is always on. */
  wrapToolResults?: boolean;
  /** Wrap the text inside document blocks in <untrusted_document> (default
   *  true). A document is external content in the same way a tool result is;
   *  sources shield cannot read (base64 PDFs, remote URLs, uploaded files)
   *  cannot be wrapped and raise `content_not_scanned` instead. */
  wrapDocuments?: boolean;
  /** Source label for emitted events, e.g. "voicelogger" or "bulwork". */
  appLabel?: string;
  /** Print the startup banner (default true). The shield_started heartbeat
   *  event is emitted either way. */
  announce?: boolean;
  /** Fixed canary token. By default one is derived per system prompt from a
   *  per-process salt (or SHIELD_CANARY_SALT). Pin it when you need identical
   *  system prompts across workers for prompt caching. */
  canary?: string;
  /** SDK surfaces to forward WITHOUT shielding, by path relative to the client
   *  ("beta", "messages.batches"). Accessing any uncovered surface not listed
   *  here throws ShieldCoverageError — deliberately, so an unprotected call
   *  path can't hide behind the startup banner. */
  passthrough?: string[];
  /** Wire the shared JSONL file log on construction when running under Node
   *  (default true). Set false if you route events elsewhere via onShieldEvent. */
  fileLogger?: boolean;
  /** Use an existing Shield instance (createShield) for config, sinks, output
   *  scanning and tool policy. When omitted one is created from these options. */
  shield?: Shield;
  /** When the tool policy BLOCKS a requested tool call, strip it from the
   *  response (non-streaming calls) instead of only logging (default false). */
  enforceToolPolicy?: boolean;
}

// Client-level attributes that never carry a prompt to the model.
const CLIENT_ALLOW = ["models", "apiKey", "authToken", "baseURL", "timeout", "maxRetries", "fetch", "idempotencyHeader"] as const;
// messages.* attributes that never carry a prompt to the model.
const MESSAGES_ALLOW = ["countTokens"] as const;

 
function extractText(content: any): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .filter((b: { type: string }) => b && b.type === "text")
      .map((b: { text: string }) => b.text)
      .join(" ");
  }
  return String(content ?? "");
}

/**
 * Text carried inside tool_result blocks of a user message. Tool results are
 * where fetched pages, file contents, and search output enter the context —
 * the primary indirect-injection channel — so they get their own extraction
 * (and their own event source qualifier) instead of riding along with typed
 * user text.
 */
 
function extractToolResultText(content: any): string {
  if (!Array.isArray(content)) return "";
  return content
    .filter((b) => b && b.type === "tool_result")
    .map((b) => (typeof b.content === "string" ? b.content : extractText(b.content)))
    .filter(Boolean)
    .join(" ");
}

/**
 * Text carried by `document` blocks with an inline text source. Uploaded
 * files and pasted documents are external content in exactly the same way
 * tool results are; before v1.5 they were never scanned.
 */
 
function extractDocumentText(content: any): string {
  if (!Array.isArray(content)) return "";
  return content
    .filter((b) => b && b.type === "document" && b.source && b.source.type === "text" && typeof b.source.data === "string")
    .map((b) => b.source.data as string)
    .join(" ");
}

/**
 * Document sources shield cannot read: a PDF or image as base64, a remote
 * URL, an uploaded file id. The bytes never reach the pattern layer, so a
 * document block is NOT evidence that the document was checked.
 *
 * Returns a short description per unreadable source, for the
 * `content_not_scanned` event. Silence here would be the worst outcome: an
 * operator reading a clean log would reasonably conclude the PDF was scanned
 * and found harmless, when in fact it was never opened.
 */
 
function unscannableDocuments(content: any): string[] {
  if (!Array.isArray(content)) return [];
  const out: string[] = [];
  for (const b of content) {
    if (!b || b.type !== "document" || !b.source) continue;
    const kind = b.source.type;
    if (kind === "text") continue;
    if (kind === "base64") out.push(`base64 ${b.source.media_type ?? "document"}`);
    else if (kind === "url") out.push(`remote url ${String(b.source.url ?? "").slice(0, 120)}`);
    else if (kind === "file") out.push(`uploaded file ${String(b.source.file_id ?? "")}`);
    else out.push(`document source "${String(kind)}"`);
  }
  return out;
}

/**
 * Wrap the text inside document blocks as <untrusted_document>. A document is
 * external content in exactly the way a tool result is; it was being scanned
 * but not fenced, so an instruction inside it still read to the model as part
 * of the user's own message.
 */
 
function wrapDocumentBlocks(content: any): any {
  if (!Array.isArray(content)) return content;
  return content.map((b) =>
    b && b.type === "document" && b.source?.type === "text" && typeof b.source.data === "string"
      ? { ...b, source: { ...b.source, data: wrapUntrusted(b.source.data, "document") } }
      : b,
  );
}

/**
 * Wrap the text inside tool_result blocks as <untrusted_tool_result> while
 * preserving block structure (string content stays a string, image parts
 * inside array-form content are untouched).
 */
 
function wrapToolResultBlocks(content: any): any {
  if (!Array.isArray(content)) return content;
  return content.map((b) => {
    if (!b || b.type !== "tool_result") return b;
    if (typeof b.content === "string") {
      return { ...b, content: wrapUntrusted(b.content, "tool_result") };
    }
    if (Array.isArray(b.content)) {
      return {
        ...b,
        content: b.content.map((p: { type?: string; text?: string }) =>
          p && p.type === "text" && typeof p.text === "string"
            ? { ...p, text: wrapUntrusted(p.text, "tool_result") }
            : p,
        ),
      };
    }
    return b;
  });
}

/**
 * Harden a `system` param of any legal shape.
 * - string (or absent): append boilerplate as before.
 * - array of blocks: append the boilerplate as a NEW text block so existing
 *   blocks — including cache_control markers — are preserved.
 * - anything else: pass through untouched rather than destroy it.
 */
 
function hardenSystemParam(system: any, fixedCanary?: string): { system: any; canary: string } {
  if (system == null || typeof system === "string") {
    const { prompt, canary } = hardenSystemPrompt(typeof system === "string" ? system : "", fixedCanary);
    return { system: prompt, canary };
  }
  if (Array.isArray(system)) {
    const seed = system
      .filter((b) => b && b.type === "text" && typeof b.text === "string")
      .map((b) => b.text)
      .join("\n");
    const canary = fixedCanary ?? generateCanary(seed);
    return { system: [...system, { type: "text", text: securityBoilerplate(canary) }], canary };
  }
  return { system, canary: fixedCanary ?? generateCanary(String(system)) };
}

/**
 * Wrap the text of a user message while PRESERVING non-text blocks.
 */
 
function wrapUserContent(content: any): any {
  if (typeof content === "string") return wrapUntrusted(content, "user_message");
  if (Array.isArray(content)) {
    return content.map((b) =>
      b && b.type === "text" && typeof b.text === "string"
        ? { ...b, text: wrapUntrusted(b.text, "user_message") }
        : b,
    );
  }
  return content;
}

/** Text carried by a raw Anthropic stream event (create({stream:true})). */
 
function anthropicDeltaText(ev: any): string {
  return ev?.type === "content_block_delta" && ev.delta?.type === "text_delta"
    ? (ev.delta.text ?? "")
    : "";
}

 
function responseToolCalls(response: any): ToolCall[] {
  if (!response || typeof response !== "object" || !Array.isArray(response.content)) return [];
  return response.content
    .filter((b: { type?: string }) => b && b.type === "tool_use")
    .map((b: { name: string; input: unknown; id?: string }) => ({ name: b.name, input: b.input, id: b.id }));
}

 
function responseText(response: any): string {
  if (response && typeof response === "object" && Array.isArray(response.content)) {
    return response.content
      .filter((b: { type: string }) => b && b.type === "text")
      .map((b: { text: string }) => b.text ?? "")
      .join("");
  }
  return "";
}

interface Prepared {
  prepared: Record<string, unknown>;
  canary: string;
  inputScans: InjectionScan[];
  untrustedInputSeen: boolean;
}

class AnthropicShield {
  readonly shield: Shield;

  constructor(
    private readonly inner: AnthropicLike,
    private readonly opts: ShieldAnthropicOptions,
  ) {
    this.shield = opts.shield ?? createShield({
      app: opts.appLabel,
      canary: opts.canary,
      fileLogger: opts.fileLogger,
      banner: opts.announce,
    });
  }

  private get appLabel(): string {
    return this.shield.app;
  }

  /** Output-side check: canary, secrets, PII, exfil, echo. */
  observeOutput(outputText: string, p: Pick<Prepared, "canary" | "inputScans">): void {
    if (!outputText) return;
    this.shield.scanOutput(outputText, { canary: p.canary, inputScans: p.inputScans });
  }

  /** Tool-side check: evaluate each requested tool call; optionally strip blocked ones. */
   
  observeToolCalls(response: any, p: Pick<Prepared, "inputScans" | "untrustedInputSeen">, enforce = false): any {
    const calls = responseToolCalls(response);
    if (calls.length === 0) return response;
    const blocked = new Set<string | undefined>();
    for (const call of calls) {
      const d = this.shield.checkToolCall(call, { untrustedInputSeen: p.untrustedInputSeen, inputScans: p.inputScans });
      if (d.decision === "block") blocked.add(call.id);
    }
    if (!enforce || blocked.size === 0) return response;
    return {
      ...response,
      content: response.content.filter((b: { type?: string; id?: string }) => !(b && b.type === "tool_use" && blocked.has(b.id))),
    };
  }

  /**
   * Evaluate a tool call assembled from a stream. Blocking a streamed call
   * cannot mean stripping it — earlier events are already with the caller —
   * so under enforcement it throws, ending the iteration before the call can
   * be acted on. Without enforcement it is logged like any other gated call.
   */
  observeStreamToolCall(call: ToolCall, p: Pick<Prepared, "inputScans" | "untrustedInputSeen">): void {
    const d = this.shield.checkToolCall(call, {
      untrustedInputSeen: p.untrustedInputSeen,
      inputScans: p.inputScans,
    });
    if (d.decision === "block" && this.opts.enforceToolPolicy) {
      throw new ShieldBlockedToolError(call, d.reasons);
    }
  }

  prepare(params: Record<string, unknown>): Prepared {
    const { system: hardenedSystem, canary } = hardenSystemParam(params["system"], this.opts.canary ?? this.shield.config.canary);
    const inputScans: InjectionScan[] = [];
    let untrustedInputSeen = false;
    const scan = (text: string, channel?: string) => {
      if (!text) return;
      inputScans.push(this.shield.scanInput(text, { channel }));
    };

    const rawMessages = (params["messages"] as Array<Record<string, unknown>>) ?? [];
    const messages = rawMessages.map((m) => {
      if (!m || m["role"] !== "user") return m;
      scan(extractText(m["content"]));
      // Tool results and documents carry external content (fetched pages,
      // files, search output) — scan them always, with a source qualifier so
      // `shield logs` shows where the injection came in.
      const toolText = extractToolResultText(m["content"]);
      const docText = extractDocumentText(m["content"]);
      const unreadable = unscannableDocuments(m["content"]);
      // An unreadable document is still untrusted input — arguably more so,
      // since nothing here can vouch for it.
      if (toolText || docText || unreadable.length > 0) untrustedInputSeen = true;
      scan(toolText, "tool_result");
      scan(docText, "document");
      for (const what of unreadable) {
        this.shield.reportUnscanned(what, "document");
      }

      let content = m["content"];
      if (this.opts.wrapDocuments !== false) content = wrapDocumentBlocks(content);
      if (this.opts.wrapToolResults !== false) content = wrapToolResultBlocks(content);
      if (this.opts.wrapUserMessages) content = wrapUserContent(content);
      return content === m["content"] ? m : { ...m, content };
    });

    return { prepared: { ...params, system: hardenedSystem, messages }, canary, inputScans, untrustedInputSeen };
  }

  async create(params: Record<string, unknown>, options?: unknown) {
    const p = this.prepare(params);
    const response = await this.inner.messages.create(p.prepared, options);

    if (params["stream"] === true && !(response && typeof response === "object" && "content" in response)) {
      // create({stream: true}) returns a raw event stream — tap it so the
      // output check runs as the caller consumes it, and so tool calls are
      // rebuilt from their fragments and evaluated as each one completes.
      return tapEventStream(response, {
        text: anthropicDeltaText,
        tools: anthropicToolAssembler,
        onText: (text) => this.observeOutput(text, p),
        onToolCall: (call) => this.observeStreamToolCall(call, p),
      });
    }
    this.observeOutput(responseText(response), p);
    return this.observeToolCalls(response, p, this.opts.enforceToolPolicy);
  }

  async parse(params: Record<string, unknown>, options?: unknown) {
    const p = this.prepare(params);
    const parseFn = this.inner.messages.parse;
    if (!parseFn) throw new Error("This Anthropic client does not support messages.parse");
    const response = await parseFn.call(this.inner.messages, p.prepared, options);
    this.observeOutput(responseText(response), p);
    return this.observeToolCalls(response, p, this.opts.enforceToolPolicy);
  }

  /**
   * Shield-aware messages.stream(): hardens/scans like create, then checks
   * the streamed text on end and the final message's tool calls (logged,
   * never stripped — the stream has already been consumed).
   */
  stream(params: Record<string, unknown>, options?: unknown) {
    const p = this.prepare(params);
    const streamFn = this.inner.messages.stream;
    if (!streamFn) throw new Error("This Anthropic client does not support messages.stream");
    const stream = streamFn.call(this.inner.messages, p.prepared, options);

    try {
      if (stream && typeof stream.on === "function") {
        let buf = "";
        stream.on("text", (t: string) => { buf += t; });
        stream.on("end", () => this.observeOutput(buf, p));
        stream.on("finalMessage", (msg: unknown) => { try { this.observeToolCalls(msg, p, false); } catch { /* ignore */ } });
        return stream;
      }
    } catch { /* observation must never break streaming */ }
    // Not an event emitter (unusual client): fall back to tapping iteration.
    return tapEventStream(stream, {
      text: anthropicDeltaText,
      tools: anthropicToolAssembler,
      onText: (text) => this.observeOutput(text, p),
      onToolCall: (call) => this.observeStreamToolCall(call, p),
    });
  }
}

/**
 * Wrap an Anthropic client. Returns a proxy typed as the client you passed
 * in, so existing call sites type-check unchanged.
 */
export function shieldAnthropic<T extends AnthropicLike>(inner: T, opts: ShieldAnthropicOptions = {}): T {
  const shield = new AnthropicShield(inner, opts);
  const passthrough = opts.passthrough ?? [];

  return guarded(inner, {
    path: "client",
    allow: CLIENT_ALLOW,
    passthrough,
    intercept: {
      messages: (client: AnthropicLike) =>
        guarded(client.messages, {
          path: "client.messages",
          allow: MESSAGES_ALLOW,
          passthrough: nestedPassthrough(passthrough, "messages"),
          intercept: {
            create: () => (params: Record<string, unknown>, options?: unknown) => shield.create(params, options),
            parse: () => (params: Record<string, unknown>, options?: unknown) => shield.parse(params, options),
            stream: () => (params: Record<string, unknown>, options?: unknown) => shield.stream(params, options),
          },
        }),
    },
  });
}

/**
 * Class form of shieldAnthropic, kept for existing consumers:
 *   const client = new ShieldAnthropicClient(new Anthropic(), { appLabel });
 * The constructor returns the same proxy `shieldAnthropic` does.
 */
export class ShieldAnthropicClient implements AnthropicLike {
  declare readonly messages: ShieldedAnthropicMessages;
  constructor(inner: AnthropicLike, opts: ShieldAnthropicOptions = {}) {
    return shieldAnthropic(inner, opts) as unknown as ShieldAnthropicClient;
  }
}
