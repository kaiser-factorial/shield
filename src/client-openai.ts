/**
 * ShieldOpenAIClient — drop-in wrapper around the OpenAI SDK (also works with
 * any OpenAI-compatible client: OpenRouter, Groq, Ollama, etc.).
 *
 * Duck-typed: nothing from the `openai` package is imported, so the emitted
 * type declarations don't require it either.
 *
 * Usage:
 *   import OpenAI from "openai";
 *   import { shieldOpenAI } from "@local/shield";
 *   const openai = shieldOpenAI(new OpenAI({ apiKey }), { appLabel: "my-app" });
 *
 * Covered: `chat.completions.create/parse/stream/runTools` and
 * `responses.create/parse/stream`. Data-only surfaces (`embeddings`, `models`,
 * `files`, …) pass through. Anything else that could carry a prompt to the
 * model (`beta`, legacy `completions`, `batches`, `withOptions`) throws
 * ShieldCoverageError unless listed in `passthrough`.
 */

import {
  announceShield,
  detectInjection,
  scanDetail,
  generateCanary,
  hardenSystemPrompt,
  outputLeakedCanary,
  emitShieldEvent,
  securityBoilerplate,
  wrapUntrusted,
} from "./shield.js";
import { tapEventStream } from "./stream.js";
import { guarded, nestedPassthrough } from "./coverage.js";
import { initFileLogger } from "./logger.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
export interface OpenAICompletionsLike {
  create(params: any, options?: any): any;
  parse?(params: any, options?: any): any;
  stream?(params: any, options?: any): any;
  runTools?(params: any, options?: any): any;
}
export interface OpenAIResponsesLike {
  create(params: any, options?: any): any;
  parse?(params: any, options?: any): any;
  stream?(params: any, options?: any): any;
}
export interface OpenAILike {
  chat?: { completions: OpenAICompletionsLike };
  responses?: OpenAIResponsesLike;
}

/** Surfaces as seen through the wrapper: covered methods are always present. */
export interface ShieldedOpenAICompletions extends OpenAICompletionsLike {
  parse(params: any, options?: any): any;
  stream(params: any, options?: any): any;
  runTools(params: any, options?: any): any;
}
export interface ShieldedOpenAIResponses extends OpenAIResponsesLike {
  parse(params: any, options?: any): any;
  stream(params: any, options?: any): any;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

export interface ShieldOpenAIOptions {
  wrapUserMessages?: boolean;
  /** Wrap `role: "tool"` messages / `function_call_output` items in
   *  <untrusted_tool_result> tags (default true). Detection scanning of tool
   *  output is always on. */
  wrapToolResults?: boolean;
  appLabel?: string;
  /** Print the startup banner (default true). The shield_started heartbeat
   *  event is emitted either way. */
  announce?: boolean;
  /** Fixed canary token (see ShieldAnthropicOptions.canary). */
  canary?: string;
  /** SDK surfaces to forward WITHOUT shielding, by path relative to the client
   *  ("beta", "completions"). Uncovered surfaces not listed here throw
   *  ShieldCoverageError at access time. */
  passthrough?: string[];
  /** Wire the shared JSONL file log on construction under Node (default true). */
  fileLogger?: boolean;
}

const CLIENT_ALLOW = [
  "embeddings", "models", "files", "images", "audio", "moderations", "fineTuning",
  "vectorStores", "uploads", "conversations", "containers",
  "apiKey", "baseURL", "organization", "project", "webhookSecret", "timeout", "maxRetries", "fetch",
] as const;
const CHAT_ALLOW: readonly string[] = [];
const COMPLETIONS_ALLOW = ["messages"] as const;
const RESPONSES_ALLOW = ["inputItems", "retrieve", "delete", "cancel"] as const;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function partsText(content: any, textTypes: readonly string[]): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .filter((p) => p && textTypes.includes(p.type) && typeof p.text === "string")
      .map((p) => p.text as string)
      .join(" ");
  }
  return "";
}

/**
 * Harden a system message's content of either legal shape.
 * - string: append boilerplate as before.
 * - array of parts: append the boilerplate as a NEW text part so existing
 *   parts are preserved instead of being flattened into one string.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function hardenSystemContent(content: any, fixedCanary?: string): { content: any; canary: string } {
  if (content == null || typeof content === "string") {
    const { prompt, canary } = hardenSystemPrompt(typeof content === "string" ? content : "", fixedCanary);
    return { content: prompt, canary };
  }
  if (Array.isArray(content)) {
    const seed = content
      .filter((p) => p && p.type === "text" && typeof p.text === "string")
      .map((p) => p.text)
      .join("\n");
    const canary = fixedCanary ?? generateCanary(seed);
    return { content: [...content, { type: "text", text: securityBoilerplate(canary) }], canary };
  }
  return { content, canary: fixedCanary ?? generateCanary(String(content)) };
}

/**
 * Wrap the text of a message while PRESERVING non-text parts
 * (image_url, input_audio, file, …).
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function wrapContentText(content: any, label: string, textTypes: readonly string[] = ["text"]): any {
  if (typeof content === "string") return wrapUntrusted(content, label);
  if (Array.isArray(content)) {
    return content.map((p) =>
      p && textTypes.includes(p.type) && typeof p.text === "string"
        ? { ...p, text: wrapUntrusted(p.text, label) }
        : p,
    );
  }
  return content;
}

/** Text carried by a streamed chat-completion chunk (create({stream:true})). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function chatDeltaText(ev: any): string {
  const choices = ev?.choices;
  if (!Array.isArray(choices) || choices.length === 0) return "";
  return choices[0]?.delta?.content ?? "";
}

/** Text carried by a Responses API stream event. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function responsesDeltaText(ev: any): string {
  return ev?.type === "response.output_text.delta" && typeof ev.delta === "string" ? ev.delta : "";
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function chatCompletionText(response: any): string {
  if (!response || !Array.isArray(response.choices)) return "";
  return response.choices.map((c: { message?: { content?: string | null } }) => c?.message?.content ?? "").join("");
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function responseOutputText(response: any): string {
  if (!response || typeof response !== "object") return "";
  if (typeof response.output_text === "string" && response.output_text) return response.output_text;
  if (!Array.isArray(response.output)) return "";
  return response.output
    .filter((item: { type?: string }) => item && item.type === "message")
    .flatMap((item: { content?: unknown }) => (Array.isArray(item.content) ? item.content : []))
    .filter((p: { type?: string; text?: unknown }) => p && p.type === "output_text" && typeof p.text === "string")
    .map((p: { text: string }) => p.text)
    .join("");
}

/**
 * Observe a helper stream (ChatCompletionStream / ResponseStream) without
 * consuming it. Prefer the emitter interface, which fires whether the caller
 * iterates or just awaits the final result; fall back to tapping iteration.
 * Several candidate event names may be listened to (SDK versions differ);
 * each keeps its own buffer and the fullest one is checked at the end, so a
 * delta reported under two names is never double-counted.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function observeHelperStream(
  stream: any,
  listeners: Array<{ name: string; extract: (arg: any) => string }>,
  iterExtract: (ev: any) => string,
  onDone: (text: string) => void,
): any {
  try {
    if (stream && typeof stream.on === "function") {
      const bufs = listeners.map(() => "");
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        onDone(bufs.reduce((a, b) => (b.length > a.length ? b : a), ""));
      };
      listeners.forEach((l, i) => {
        stream.on(l.name, (arg: unknown) => {
          try { bufs[i] += l.extract(arg) ?? ""; } catch { /* ignore */ }
        });
      });
      stream.on("end", finish);
      stream.on("abort", finish);
      return stream;
    }
  } catch { /* canary observation must never break streaming */ }
  return tapEventStream(stream, iterExtract, onDone);
}

class OpenAIShield {
  constructor(
    private readonly inner: OpenAILike,
    private readonly opts: ShieldOpenAIOptions,
  ) {}

  private get appLabel(): string {
    return this.opts.appLabel ?? "shield";
  }

  private scanAndEmit(text: string, source: string): void {
    if (!text) return;
    const scan = detectInjection(text);
    if (scan.flagged) {
      emitShieldEvent({
        type: "injection_detected",
        source,
        detail: scanDetail(text, scan),
        score: scan.score,
        patterns: scan.matches,
      });
    }
  }

  checkCanaryText(outputText: string, canary: string): void {
    if (!outputText || !outputLeakedCanary(outputText, canary)) return;
    emitShieldEvent({ type: "canary_leaked", source: this.appLabel, detail: outputText.slice(0, 200) });
    console.warn(`[shield] Canary leak detected in response from ${this.appLabel}`);
  }

  // ── chat.completions ──────────────────────────────────────────────────────

  prepareChat(params: Record<string, unknown>): { prepared: Record<string, unknown>; canary: string } {
    const appLabel = this.appLabel;
    const rawMessages = (params["messages"] as Array<Record<string, unknown>>) ?? [];
    // Harden the FIRST system (or developer — the newer OpenAI equivalent)
    // message in place; any later system messages pass through untouched.
    const sysIdx = rawMessages.findIndex((m) => m && (m["role"] === "system" || m["role"] === "developer"));
    const sysMsg = sysIdx >= 0 ? rawMessages[sysIdx] : undefined;
    const { content: hardenedSystem, canary } = hardenSystemContent(sysMsg?.["content"], this.opts.canary);

    const messages = rawMessages.map((m, i) => {
      if (i === sysIdx) return { ...m, content: hardenedSystem };
      if (!m) return m;
      if (m["role"] === "user") {
        this.scanAndEmit(partsText(m["content"], ["text"]), appLabel);
        if (this.opts.wrapUserMessages) return { ...m, content: wrapContentText(m["content"], "user_message") };
      }
      if (m["role"] === "tool") {
        // Tool results carry external content (fetched pages, files, search
        // output) — the primary indirect-injection channel. Always scan;
        // wrap unless explicitly disabled.
        this.scanAndEmit(partsText(m["content"], ["text"]), `${appLabel}:tool_result`);
        if (this.opts.wrapToolResults !== false) return { ...m, content: wrapContentText(m["content"], "tool_result") };
      }
      return m;
    });

    // No system/developer message in the request: the hardened prompt would
    // otherwise never reach the model (and the canary would be an orphan).
    if (sysIdx < 0) messages.unshift({ role: "system", content: hardenedSystem });

    return { prepared: { ...params, messages }, canary };
  }

  private completions(): OpenAICompletionsLike {
    const c = this.inner.chat?.completions;
    if (!c) throw new Error("This OpenAI client does not expose chat.completions");
    return c;
  }

  async chatCreate(params: Record<string, unknown>, options?: unknown) {
    const { prepared, canary } = this.prepareChat(params);
    const response = await this.completions().create(prepared, options);
    if (params["stream"] === true && !(response && typeof response === "object" && "choices" in response)) {
      return tapEventStream(response, chatDeltaText, (text) => this.checkCanaryText(text, canary));
    }
    this.checkCanaryText(chatCompletionText(response), canary);
    return response;
  }

  async chatParse(params: Record<string, unknown>, options?: unknown) {
    const { prepared, canary } = this.prepareChat(params);
    const fn = this.completions().parse;
    if (!fn) throw new Error("This OpenAI client does not support chat.completions.parse");
    const response = await fn.call(this.completions(), prepared, options);
    this.checkCanaryText(chatCompletionText(response), canary);
    return response;
  }

  chatStream(method: "stream" | "runTools", params: Record<string, unknown>, options?: unknown) {
    const { prepared, canary } = this.prepareChat(params);
    const fn = this.completions()[method];
    if (!fn) throw new Error(`This OpenAI client does not support chat.completions.${method}`);
    const stream = fn.call(this.completions(), prepared, options);
    return observeHelperStream(
      stream,
      [{ name: "content", extract: (delta) => (typeof delta === "string" ? delta : "") }],
      chatDeltaText,
      (text) => this.checkCanaryText(text, canary),
    );
  }

  // ── responses ─────────────────────────────────────────────────────────────

  /**
   * Responses API: `instructions` is the system prompt; `input` is a string
   * (user text) or a list of items — role messages, or `function_call_output`
   * items carrying tool results.
   */
  prepareResponses(params: Record<string, unknown>): { prepared: Record<string, unknown>; canary: string } {
    const appLabel = this.appLabel;
    const instr = params["instructions"];
    const { prompt: instructions, canary } = hardenSystemPrompt(typeof instr === "string" ? instr : "", this.opts.canary);

    let input = params["input"];
    if (typeof input === "string") {
      this.scanAndEmit(input, appLabel);
      if (this.opts.wrapUserMessages) input = wrapUntrusted(input, "user_message");
    } else if (Array.isArray(input)) {
      input = input.map((item: Record<string, unknown>) => {
        if (!item || typeof item !== "object") return item;
        const type = item["type"];
        if (type === "function_call_output" || type === "custom_tool_call_output") {
          const out = item["output"];
          this.scanAndEmit(partsText(out, ["input_text", "text"]), `${appLabel}:tool_result`);
          if (this.opts.wrapToolResults !== false) {
            return { ...item, output: wrapContentText(out, "tool_result", ["input_text", "text"]) };
          }
          return item;
        }
        if ((type === undefined || type === "message") && item["role"] === "user") {
          this.scanAndEmit(partsText(item["content"], ["input_text", "text"]), appLabel);
          if (this.opts.wrapUserMessages) {
            return { ...item, content: wrapContentText(item["content"], "user_message", ["input_text", "text"]) };
          }
        }
        return item;
      });
    }

    return { prepared: { ...params, instructions, input }, canary };
  }

  private responses(): OpenAIResponsesLike {
    const r = this.inner.responses;
    if (!r) throw new Error("This OpenAI client does not expose responses");
    return r;
  }

  async responsesCreate(params: Record<string, unknown>, options?: unknown) {
    const { prepared, canary } = this.prepareResponses(params);
    const response = await this.responses().create(prepared, options);
    if (params["stream"] === true && !(response && typeof response === "object" && "output" in response)) {
      return tapEventStream(response, responsesDeltaText, (text) => this.checkCanaryText(text, canary));
    }
    this.checkCanaryText(responseOutputText(response), canary);
    return response;
  }

  async responsesParse(params: Record<string, unknown>, options?: unknown) {
    const { prepared, canary } = this.prepareResponses(params);
    const fn = this.responses().parse;
    if (!fn) throw new Error("This OpenAI client does not support responses.parse");
    const response = await fn.call(this.responses(), prepared, options);
    this.checkCanaryText(responseOutputText(response), canary);
    return response;
  }

  responsesStream(params: Record<string, unknown>, options?: unknown) {
    const { prepared, canary } = this.prepareResponses(params);
    const fn = this.responses().stream;
    if (!fn) throw new Error("This OpenAI client does not support responses.stream");
    const stream = fn.call(this.responses(), prepared, options);
    return observeHelperStream(
      stream,
      [{ name: "event", extract: responsesDeltaText }, { name: "response.output_text.delta", extract: responsesDeltaText }],
      responsesDeltaText,
      (text) => this.checkCanaryText(text, canary),
    );
  }
}

/**
 * Wrap an OpenAI(-compatible) client. Returns a proxy typed as the client you
 * passed in, so existing call sites type-check unchanged.
 */
export function shieldOpenAI<T extends OpenAILike>(inner: T, opts: ShieldOpenAIOptions = {}): T {
  announceShield({
    appLabel: opts.appLabel,
    banner: opts.announce,
    wrapUserMessages: opts.wrapUserMessages,
  });
  if (opts.fileLogger !== false) void initFileLogger();

  const shield = new OpenAIShield(inner, opts);
  const passthrough = opts.passthrough ?? [];
  type P = Record<string, unknown>;

  return guarded(inner, {
    path: "client",
    allow: CLIENT_ALLOW,
    passthrough,
    intercept: {
      chat: (client: OpenAILike) =>
        client.chat && guarded(client.chat as object, {
          path: "client.chat",
          allow: CHAT_ALLOW,
          passthrough: nestedPassthrough(passthrough, "chat"),
          intercept: {
            completions: (chat: { completions: object }) =>
              guarded(chat.completions, {
                path: "client.chat.completions",
                allow: COMPLETIONS_ALLOW,
                passthrough: nestedPassthrough(nestedPassthrough(passthrough, "chat"), "completions"),
                intercept: {
                  create: () => (params: P, options?: unknown) => shield.chatCreate(params, options),
                  parse: () => (params: P, options?: unknown) => shield.chatParse(params, options),
                  stream: () => (params: P, options?: unknown) => shield.chatStream("stream", params, options),
                  runTools: () => (params: P, options?: unknown) => shield.chatStream("runTools", params, options),
                },
              }),
          },
        }),
      responses: (client: OpenAILike) =>
        client.responses && guarded(client.responses as object, {
          path: "client.responses",
          allow: RESPONSES_ALLOW,
          passthrough: nestedPassthrough(passthrough, "responses"),
          intercept: {
            create: () => (params: P, options?: unknown) => shield.responsesCreate(params, options),
            parse: () => (params: P, options?: unknown) => shield.responsesParse(params, options),
            stream: () => (params: P, options?: unknown) => shield.responsesStream(params, options),
          },
        }),
    },
  });
}

/**
 * Class form of shieldOpenAI, kept for existing consumers:
 *   const openai = new ShieldOpenAIClient(new OpenAI({ apiKey }));
 * The constructor returns the same proxy `shieldOpenAI` does.
 */
export class ShieldOpenAIClient implements OpenAILike {
  declare readonly chat: { completions: ShieldedOpenAICompletions };
  declare readonly responses: ShieldedOpenAIResponses;
  constructor(inner: OpenAILike, opts: ShieldOpenAIOptions = {}) {
    return shieldOpenAI(inner, opts) as unknown as ShieldOpenAIClient;
  }
}
