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
  detectInjection,
  hardenSystemPrompt,
  outputLeakedCanary,
  emitShieldEvent,
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
  /** Source label for emitted events, e.g. "voicelogger" or "brick". */
  appLabel?: string;
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

export class ShieldAnthropicClient {
  constructor(
    private readonly inner: AnthropicLike,
    private readonly opts: ShieldAnthropicOptions = {},
  ) {}

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
    const base = typeof params["system"] === "string" ? params["system"] : "";
    const { prompt: hardenedSystem, canary } = hardenSystemPrompt(base);

    const rawMessages = (params["messages"] as Array<Record<string, unknown>>) ?? [];
    const messages = rawMessages.map((m) => {
      if (m["role"] !== "user") return m;
      const text = extractText(m["content"]);
      const scan = detectInjection(text);
      if (scan.flagged) {
        emitShieldEvent({
          type: "injection_detected",
          source: appLabel,
          detail: text.slice(0, 200),
          score: scan.score,
          patterns: scan.matches,
        });
      }
      if (this.opts.wrapUserMessages) {
        return { ...m, content: wrapUntrusted(text, "user_message") };
      }
      return m;
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
