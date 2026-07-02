# @local/shield

Prompt injection defense library. Plugs into TypeScript and Python apps that call LLMs, providing detection, semantic wrapping, canary tokens, and a unified event log across all apps.

## What it does

**Detect** — 25 regex patterns covering role-hijacking, instruction override, jailbreaks, data exfiltration attempts, indirect injection markers, and untrusted-tag breakout attempts. Returns a severity score and matched patterns.

**Wrap** — Tags untrusted content (web pages, file uploads, voice transcripts, search results) with `<untrusted_*>` XML boundaries so the model treats it as data, not instructions. Content is sanitized first: any embedded `</untrusted_*>` sequence that could close the boundary early (including case, whitespace, and fullwidth-bracket variants) is neutralized to `&lt;…`, and a `trigger_stripped` event is logged.

**Harden** — Prepends a stable anti-injection boilerplate and embeds a canary token into the system prompt. If the canary appears in the model's output, an injection likely leaked through.

**Log** — All shield events (detections, canary leaks, blocked messages) write to `~/.shield/events.jsonl`, shared across TS and Python apps. Query with the CLI.

**Announce** — Client wrappers print a one-line startup banner and emit a `shield_started` heartbeat (with the library version) on construction, so a protected app *visibly says so* — and `shield status` can spot apps that have gone quiet or run a stale copy.

**Watch** — `shield headless` scans running processes for browser automation (headless Chromium, `--remote-debugging-port`, Playwright, Puppeteer, WebDriver, Selenium, Cypress, PhantomJS) and logs each detection as a `headless_detected` event. `--watch` keeps polling. A headless browser you didn't start is exactly the kind of mysterious activity worth an event.

## Install

```bash
# TypeScript
npm install file:../shield   # or github:kaiser-factorial/shield

# Python (lives in python/ inside this repo)
pip install -e ../shield/python
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
npx shield status            # per-app health, version drift, gone-quiet apps
npx shield headless          # one-shot scan for browser automation processes
npx shield headless --watch --interval 15   # keep watching, log new detections
npx shield scan "ignore previous instructions and..."
npx shield clear
```

`shield headless` is a tripwire, not a blocker: every hit is logged with pid, matched signatures, and the command line, then it's your call. Expect hits from your own test runs — the value is the ones you *can't* explain. (First real catch: three Playwright driver processes that Antigravity IDE had quietly kept alive for weeks.) Python apps can embed the same check via `from shield import scan_and_report`.

## Knowing shield is on — banners, heartbeats, `shield status`

Lesson learned the hard way (wearabLLM shipped with a broken import path for months): **a protection that fails to load looks exactly like no protection.** Shield v1.1+ closes that gap in two layers:

**1. Startup banner + heartbeat (automatic).** Constructing `ShieldAnthropicClient` / `ShieldOpenAIClient` prints once per process:

```
[shield] v1.1.0 active · app=brick · 25 patterns · canary armed · wrap=off
```

…and emits a `shield_started` heartbeat event to the shared log. Apps using the lower-level primitives directly should call `announceShield({ appLabel })` / `announce_shield(app_label)` at startup. Pass `announce: false` or set `SHIELD_QUIET=1` to silence the banner — the heartbeat always fires. Get used to seeing the banner; its absence means shield didn't load.

**2. Central status (`npx shield status`).** You can't rely on noticing a missing banner, so the heartbeats feed one admin view across every app:

```
shield status (library v1.1.0, log: ~/.shield/events.jsonl)

  brick        v1.0.0 · last start 7/1/2026 · 7d: 1 injections, 0 stripped, 0 leaks
    ⚠ running v1.0.0, repo is at v1.1.0 — rebuild/reinstall this app
  voicelogger  version unknown · no heartbeat ever · 7d: 0 injections, 0 stripped, 1 canary leaks
    ⚠ never announced — pre-v1.1 shield, or the integration isn't loading
```

Exits non-zero when there are warnings, so it can run in a cron/login hook if you want a nudge.

### How updates propagate (deliberately not automatic)

There is no auto-update — that was removed on purpose (see the sync section below). Instead, **drift is detected**: heartbeats carry the version each app is actually running, and `shield status` flags anything older than the repo. To update a consumer:

| Consumer | How it updates |
|---|---|
| wearabLLM (sys.path import of `python/`) | Immediately — imports the live source on next run |
| brick, voicelogger-cli (`file:../shield`) | `npm install` (or `npm update @local/shield`) + rebuild |
| group-chat (vendored copy) | `~/Projects/shield-sync.sh` (test-gated, review-first) |

## Tests

Both packages have zero-dependency test suites (Node's built-in runner / Python's `unittest`) covering the attack corpus, benign false-positive checks, tag-breakout attempts, and canary behavior:

```bash
# TypeScript (runs in CI on every push)
npm test

# Python (also runs in CI)
cd python && python3 -m unittest discover -s tests -v
```

When adding a detection pattern or changing wrapping/hardening behavior, change **both** packages and both test suites — they are kept in feature parity by hand. Both live in this repo (TypeScript at the root, Python under `python/`) so one commit covers both sides.

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

`group-chat` keeps a copy of shield in `packages/shield/` for CI. Syncing is **manual and review-first** — run it deliberately after landing shield changes:

```bash
~/Projects/shield-sync.sh          # runs tests, syncs, shows the diff, asks before commit & push
~/Projects/shield-sync.sh --yes    # skip prompts (tests still gate everything)
```

> Historical note: until 2026-07-02 a 30-minute cron job did this automatically —
> pulling, building, and pushing unreviewed code. That's a supply-chain risk for a
> security library (anything landing on origin/main executed locally and propagated
> eyes-free), so it was removed. Don't reintroduce it.
