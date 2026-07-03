/**
 * ShieldAnthropicClient — drop-in wrapper around the Anthropic SDK.
 *
 * Uses structural typing (duck typing) for the inner client so it works
 * regardless of which version of @anthropic-ai/sdk the caller has installed.
 *
 * Usage:
 *   import Anthropic from "@anthropic-ai/sdk";
 *   import { ShieldAnthropicClient } from "@local/shield";
 *   const client = new ShieldAnthropicClient(new Anthropic());
 *
 *   // Then use exactly as before:
 *   const res = await client.messages.create({ ... });
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

// Structural interface — matches the Anthropic SDK without importing it
interface AnthropicMessages {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  create(params: any): Promise<any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  parse?(params: any): Promise<any>;
}

interface AnthropicLike {
  messages: AnthropicMessages;
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
  /** Source label for emitted events, e.g. "voicelogger" or "brick". */
  appLabel?: string;
  /** Print the startup banner (default true). The shield_started heartbeat
   *  event is emitted either way. */
  announce?: boolean;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractText(content: any): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .filter((b: { type: string }) => b.type === "text")
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
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractToolResultText(content: any): string {
  if (!Array.isArray(content)) return "";
  return content
    .filter((b) => b && b.type === "tool_result")
    .map((b) => (typeof b.content === "string" ? b.content : extractText(b.content)))
    .filter(Boolean)
    .join(" ");
}

/**
 * Wrap the text inside tool_result blocks as <untrusted_tool_result> while
 * preserving block structure (string content stays a string, image parts
 * inside array-form content are untouched).
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
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
 *   blocks — including cache_control markers — are preserved. (Previously an
 *   array-form system prompt was silently replaced with just the boilerplate.)
 * - anything else: pass through untouched rather than destroy it.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function hardenSystemParam(system: any): { system: any; canary: string } {
  if (system == null || typeof system === "string") {
    const { prompt, canary } = hardenSystemPrompt(typeof system === "string" ? system : "");
    return { system: prompt, canary };
  }
  if (Array.isArray(system)) {
    const seed = system
      .filter((b) => b && b.type === "text" && typeof b.text === "string")
      .map((b) => b.text)
      .join("\n");
    const canary = generateCanary(seed);
    return { system: [...system, { type: "text", text: securityBoilerplate(canary) }], canary };
  }
  return { system, canary: generateCanary(String(system)) };
}

/**
 * Wrap the text of a user message while PRESERVING non-text blocks.
 * (Previously the whole content array was flattened to a single wrapped
 * string, destroying images and tool_result blocks.)
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
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

export class ShieldAnthropicClient {
  constructor(
    private readonly inner: AnthropicLike,
    private readonly opts: ShieldAnthropicOptions = {},
  ) {
    announceShield({
      appLabel: opts.appLabel,
      banner: opts.announce,
      wrapUserMessages: opts.wrapUserMessages,
    });
  }

  get messages() {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this;
    return {
      create: (params: Record<string, unknown>) => self._create(params),
      parse: (params: Record<string, unknown>) => self._parse(params),
    };
  }

  private _prepare(params: Record<string, unknown>): { prepared: Record<string, unknown>; canary: string } {
    const appLabel = this.opts.appLabel ?? "shield";
    const { system: hardenedSystem, canary } = hardenSystemParam(params["system"]);

    const rawMessages = (params["messages"] as Array<Record<string, unknown>>) ?? [];
    const messages = rawMessages.map((m) => {
      if (m["role"] !== "user") return m;
      const text = extractText(m["content"]);
      const scan = detectInjection(text);
      if (scan.flagged) {
        emitShieldEvent({
          type: "injection_detected",
          source: appLabel,
          detail: scanDetail(text, scan),
          score: scan.score,
          patterns: scan.matches,
        });
      }

      // Tool results carry external content (fetched pages, files, search
      // output) — scan them always, with a source qualifier so `shield logs`
      // shows where the injection came in.
      const toolText = extractToolResultText(m["content"]);
      if (toolText) {
        const toolScan = detectInjection(toolText);
        if (toolScan.flagged) {
          emitShieldEvent({
            type: "injection_detected",
            source: `${appLabel}:tool_result`,
            detail: scanDetail(toolText, toolScan),
            score: toolScan.score,
            patterns: toolScan.matches,
          });
        }
      }

      let content = m["content"];
      if (this.opts.wrapToolResults !== false) content = wrapToolResultBlocks(content);
      if (this.opts.wrapUserMessages) content = wrapUserContent(content);
      return content === m["content"] ? m : { ...m, content };
    });

    return { prepared: { ...params, system: hardenedSystem, messages }, canary };
  }

  private async _create(params: Record<string, unknown>) {
    const appLabel = this.opts.appLabel ?? "shield";
    const { prepared, canary } = this._prepare(params);
    const response = await this.inner.messages.create(prepared);

    if (response && typeof response === "object" && "content" in response && Array.isArray(response.content)) {
      const outputText = response.content
        .filter((b: { type: string }) => b.type === "text")
        .map((b: { type: string; text: string }) => b.text)
        .join("");
      if (outputLeakedCanary(outputText, canary)) {
        emitShieldEvent({ type: "canary_leaked", source: appLabel, detail: outputText.slice(0, 200) });
        console.warn(`[shield] Canary leak detected in response from ${appLabel}`);
      }
    }

    return response;
  }

  private async _parse(params: Record<string, unknown>) {
    const appLabel = this.opts.appLabel ?? "shield";
    const { prepared, canary } = this._prepare(params);
    const parseFn = this.inner.messages.parse;
    if (!parseFn) throw new Error("This Anthropic client does not support messages.parse");
    const response = await parseFn.call(this.inner.messages, prepared);

    if (response && typeof response === "object" && "content" in response && Array.isArray(response.content)) {
      const outputText = response.content
        .filter((b: { type: string }) => b.type === "text")
        .map((b: { type: string; text: string }) => b.text)
        .join("");
      if (outputLeakedCanary(outputText, canary)) {
        emitShieldEvent({ type: "canary_leaked", source: appLabel, detail: outputText.slice(0, 200) });
        console.warn(`[shield] Canary leak detected in response from ${appLabel}`);
      }
    }

    return response;
  }
}
