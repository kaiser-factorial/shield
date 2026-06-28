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
  detectInjection,
  hardenSystemPrompt,
  outputLeakedCanary,
  emitShieldEvent,
  wrapUntrusted,
} from "./shield.js";

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
  appLabel?: string;
}

export class ShieldOpenAIClient {
  constructor(
    private readonly inner: OpenAI,
    private readonly opts: ShieldOpenAIOptions = {},
  ) {}

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
    const sysMsg = params.messages.find((m) => m.role === "system");
    const base = sysMsg ? messageText(sysMsg) : "";
    const { prompt: hardenedSystem, canary } = hardenSystemPrompt(base);

    const messages: ChatMessage[] = params.messages.map((m) => {
      if (m.role === "system") return { ...m, content: hardenedSystem } as ChatMessage;
      if (m.role === "user") {
        const text = messageText(m);
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
          return { ...m, content: wrapUntrusted(text, "user_message") } as ChatMessage;
        }
      }
      return m;
    });

    return { prepared: { ...params, messages }, canary };
  }

  private async _create(params: ChatCompletionParams) {
    const appLabel = this.opts.appLabel ?? "shield";
    const { prepared, canary } = this._prepare(params);
    const response = await this.inner.chat.completions.create(prepared);

    if ("choices" in response) {
      const completion = response as ChatCompletion;
      const outputText = completion.choices
        .map((c) => c.message?.content ?? "")
        .join("");
      if (outputLeakedCanary(outputText, canary)) {
        emitShieldEvent({ type: "canary_leaked", source: appLabel, detail: outputText.slice(0, 200) });
        console.warn(`[shield] Canary leak detected in response from ${appLabel}`);
      }
    }

    return response;
  }
}
