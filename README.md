# @local/shield

Prompt injection defense library. Plugs into TypeScript and Python apps that call LLMs, providing detection, semantic wrapping, canary tokens, and a unified event log across all apps.

## What it does

**Detect** — 24 regex patterns covering role-hijacking, instruction override, jailbreaks, data exfiltration attempts, and indirect injection markers. Returns a severity score and matched patterns.

**Wrap** — Tags untrusted content (web pages, file uploads, voice transcripts, search results) with `<untrusted_*>` XML boundaries so the model treats it as data, not instructions.

**Harden** — Prepends a stable anti-injection boilerplate and embeds a canary token into the system prompt. If the canary appears in the model's output, an injection likely leaked through.

**Log** — All shield events (detections, canary leaks, blocked messages) write to `~/.shield/events.jsonl`, shared across TS and Python apps. Query with the CLI.

## Install

```bash
# TypeScript
npm install file:../shield   # or github:kaiser-factorial/shield

# Python
pip install -e ../shield-py
```

## TypeScript usage

### Harden a system prompt

```ts
import { hardenSystemPrompt, SYSTEM_CANARY } from '@local/shield';

const { hardenedPrompt, canary } = hardenSystemPrompt(BASE_SYSTEM_PROMPT);
// Pass hardenedPrompt to your LLM call
// Check canary in the response to detect leakage
```

### Wrap untrusted content

```ts
import { wrapUntrusted, detectInjection } from '@local/shield';

const scan = detectInjection(userSuppliedText);
if (scan.flagged) console.warn('Injection attempt:', scan.patterns);

const safe = wrapUntrusted(userSuppliedText, 'web_page');
// safe = <untrusted_web_page>\n...\n</untrusted_web_page>
```

### Drop-in Anthropic client wrapper

```ts
import { ShieldAnthropicClient } from '@local/shield';
import Anthropic from '@anthropic-ai/sdk';

const client = new ShieldAnthropicClient(new Anthropic(), { appLabel: 'my-app' });
// Use exactly like the Anthropic client — detection, hardening, and canary
// checks happen automatically on every call.
const msg = await client.messages.create({ ... });
```

### Drop-in OpenAI/OpenRouter wrapper

```ts
import { ShieldOpenAIClient } from '@local/shield';
import OpenAI from 'openai';

const client = new ShieldOpenAIClient(new OpenAI(), { appLabel: 'my-app' });
const completion = await client.chat.completions.create({ ... });
```

### File logger (Node.js)

```ts
import { initFileLogger } from '@local/shield';

initFileLogger(); // call once at startup — wires events → ~/.shield/events.jsonl
```

### React hook

```tsx
import { ShieldProvider, useInjectionScan } from '@local/shield/react';

function App() {
  return <ShieldProvider><YourApp /></ShieldProvider>;
}

function MessageInput() {
  const { scan } = useInjectionScan();
  const result = scan(userMessage);
  if (result.flagged) { /* warn the user */ }
}
```

## Python usage

```python
from shield import ShieldAnthropicClient, detect_injection, wrap_untrusted, harden_system_prompt
import anthropic

client = ShieldAnthropicClient(anthropic.Anthropic(), app_label="my-app")

prompt, canary = harden_system_prompt(BASE_PROMPT)
scan = detect_injection(user_text)
safe = wrap_untrusted(user_text, "voice_transcript")
```

## CLI

```bash
npx shield logs              # tail ~/.shield/events.jsonl
npx shield logs --limit 20
npx shield logs --type injection_detected
npx shield logs --source brick
npx shield scan "ignore previous instructions and..."
npx shield clear
```

## Event log

All events share `~/.shield/events.jsonl` — Python and TypeScript apps write to the same file. Fields:

```jsonc
{
  "timestamp": "2026-06-28T16:00:00.000Z",
  "type": "injection_detected" | "canary_leaked" | "message_blocked",
  "source": "brick" | "group-chat" | "voicelogger" | "wearabLLM",
  "severity": "low" | "medium" | "high",
  "patterns": ["role_hijack", "..."],
  "snippet": "first 120 chars of flagged text"
}
```

## Apps wired up

| App | Language | Integration |
|---|---|---|
| `group-chat` | TypeScript | `hardenSystemPrompt` on every bot call; `detectInjection` on user messages; Gemini history sanitized |
| `brick` | TypeScript | `ShieldAnthropicClient`; page title wrapped as `untrusted_page_title` |
| `voicelogger-cli` | TypeScript | `ShieldAnthropicClient`; transcript wrapped as `untrusted_voice_transcript` |
| `wearabLLM` | Python | `ShieldAnthropicClient`; voice input wrapped and scanned |

## Updating group-chat's vendored copy

`group-chat` keeps a copy of shield in `packages/shield/` for CI. A cron job handles syncing automatically when changes are pushed to this repo. To sync manually:

```bash
rsync -a ~/Projects/shield/{src,bin,package.json,tsconfig.json} \
  ~/Projects/group-chat/packages/shield/
cd ~/Projects/group-chat && git add packages/shield && git commit -m "sync shield" && git push
```
