/**
 * ShieldOpenAIClient — drop-in wrapper around OpenAI SDK (also works with any
 * OpenAI-compatible client: OpenRouter, Groq, Ollama, etc.).
 *
 * Usage:
 *   // Before:
 *   const openai = new OpenAI({ apiKey });
 *
 *   // After:
 *   import { ShieldOpenAIClient } from "@local/shield";
 *   const openai = new ShieldOpenAIClient(new OpenAI({ apiKey }));
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

import type OpenAI from "openai";
import type { ChatCompletion } from "openai/resources/chat/completions.js";

type ChatCompletionParams = Parameters<OpenAI["chat"]["completions"]["create"]>[0];
type ChatMessage = ChatCompletionParams["messages"][number];

function messageText(m: ChatMessage): string {
  if (typeof m.content === "string") return m.content;
  if (Array.isArray(m.content)) {
    return (m.content as Array<{ type: string; text?: string }>)
      .filter((p) => p.type === "text" && typeof p.text === "string")
      .map((p) => p.text as string)
      .join(" ");
  }
  return "";
}

export interface ShieldOpenAIOptions {
  wrapUserMessages?: boolean;
  /** Wrap `role: "tool"` message content in <untrusted_tool_result> tags
   *  (default true). Tool results are machine-fetched external content — the
   *  main indirect injection vector in agentic apps — so unlike user messages
   *  this is on by default. Detection scanning of tool messages is always on. */
  wrapToolResults?: boolean;
  appLabel?: string;
  /** Print the startup banner (default true). The shield_started heartbeat
   *  event is emitted either way. */
  announce?: boolean;
}

/**
 * Harden a system message's content of either legal shape.
 * - string: append boilerplate as before.
 * - array of parts: append the boilerplate as a NEW text part so existing
 *   parts are preserved instead of being flattened into one string.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function hardenSystemContent(content: any): { content: any; canary: string } {
  if (content == null || typeof content === "string") {
    const { prompt, canary } = hardenSystemPrompt(typeof content === "string" ? content : "");
    return { content: prompt, canary };
  }
  if (Array.isArray(content)) {
    const seed = content
      .filter((p) => p && p.type === "text" && typeof p.text === "string")
      .map((p) => p.text)
      .join("\n");
    const canary = generateCanary(seed);
    return { content: [...content, { type: "text", text: securityBoilerplate(canary) }], canary };
  }
  return { content, canary: generateCanary(String(content)) };
}

/**
 * Wrap the text of a user message while PRESERVING non-text parts
 * (image_url, input_audio, file, …). Previously the whole content array was
 * flattened to a single wrapped string.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function wrapContentText(content: any, label: string): any {
  if (typeof content === "string") return wrapUntrusted(content, label);
  if (Array.isArray(content)) {
    return content.map((p) =>
      p && p.type === "text" && typeof p.text === "string"
        ? { ...p, text: wrapUntrusted(p.text, label) }
        : p,
    );
  }
  return content;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function wrapUserContent(content: any): any {
  return wrapContentText(content, "user_message");
}

export class ShieldOpenAIClient {
  constructor(
    private readonly inner: OpenAI,
    private readonly opts: ShieldOpenAIOptions = {},
  ) {
    announceShield({
      appLabel: opts.appLabel,
      banner: opts.announce,
      wrapUserMessages: opts.wrapUserMessages,
    });
  }

  get chat() {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this;
    const inner = this.inner.chat;
    return {
      ...inner,
      completions: {
        ...inner.completions,
        create: (params: ChatCompletionParams) => self._create(params),
      },
    };
  }

  private _prepare(params: ChatCompletionParams): { prepared: ChatCompletionParams; canary: string } {
    const appLabel = this.opts.appLabel ?? "shield";
    // Harden the FIRST system (or developer — the newer OpenAI equivalent)
    // message in place; any later system messages pass through untouched.
    // Multiple system messages are legal, and replacing them all with the
    // hardened first one (the old behavior) silently destroyed their content.
    const sysIdx = params.messages.findIndex(
      (m) => m.role === "system" || (m as { role?: string }).role === "developer",
    );
    const sysMsg = sysIdx >= 0 ? params.messages[sysIdx] : undefined;
    const { content: hardenedSystem, canary } = hardenSystemContent(sysMsg?.content);

    const messages: ChatMessage[] = params.messages.map((m, i) => {
      if (i === sysIdx) return { ...m, content: hardenedSystem } as ChatMessage;
      if (m.role === "user") {
        const text = messageText(m);
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
        if (this.opts.wrapUserMessages) {
          return { ...m, content: wrapUserContent(m.content) } as ChatMessage;
        }
      }
      if (m.role === "tool") {
        // Tool results carry external content (fetched pages, files, search
        // output) — the primary indirect-injection channel. Always scan;
        // wrap unless explicitly disabled.
        const text = messageText(m);
        const scan = detectInjection(text);
        if (scan.flagged) {
          emitShieldEvent({
            type: "injection_detected",
            source: `${appLabel}:tool_result`,
            detail: scanDetail(text, scan),
            score: scan.score,
            patterns: scan.matches,
          });
        }
        if (this.opts.wrapToolResults !== false) {
          return { ...m, content: wrapContentText(m.content, "tool_result") } as ChatMessage;
        }
      }
      return m;
    });

    // No system/developer message in the request: the hardened prompt would
    // otherwise never reach the model (and the canary would be an orphan) —
    // prepend it.
    if (sysIdx < 0) {
      messages.unshift({ role: "system", content: hardenedSystem } as ChatMessage);
    }

    return { prepared: { ...params, messages }, canary };
  }

  private _checkCanaryText(outputText: string, canary: string): void {
    if (!outputText || !outputLeakedCanary(outputText, canary)) return;
    const appLabel = this.opts.appLabel ?? "shield";
    emitShieldEvent({ type: "canary_leaked", source: appLabel, detail: outputText.slice(0, 200) });
    console.warn(`[shield] Canary leak detected in response from ${appLabel}`);
  }

  private async _create(params: ChatCompletionParams) {
    const { prepared, canary } = this._prepare(params);
    const response = await this.inner.chat.completions.create(prepared);

    if ("choices" in response) {
      const completion = response as ChatCompletion;
      const outputText = completion.choices
        .map((c) => c.message?.content ?? "")
        .join("");
      this._checkCanaryText(outputText, canary);
    } else if (params.stream === true) {
      // create({stream: true}) returns a chunk stream — tap it so the canary
      // check runs as the caller consumes it (previously unchecked).
      return tapEventStream(response, openaiDeltaText, (text) => this._checkCanaryText(text, canary));
    }

    return response;
  }
}

/** Text carried by a streamed chat-completion chunk (create({stream:true})). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function openaiDeltaText(ev: any): string {
  const choices = ev?.choices;
  if (!Array.isArray(choices) || choices.length === 0) return "";
  return choices[0]?.delta?.content ?? "";
}
