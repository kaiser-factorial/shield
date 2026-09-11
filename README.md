# @local/shield

Prompt injection defense library. Plugs into TypeScript and Python apps that call LLMs, providing detection, semantic wrapping, canary tokens, and a unified event log across all apps.

## What it does

**Detect** — 30 regex patterns covering role-hijacking, instruction override, jailbreaks, system-prompt exposure, chat-delimiter spoofing, exfiltration setup (markdown-image beacons, "send this to…"), indirect injection markers, and untrusted-tag breakout attempts. Input is normalized first (NFKC, zero-width characters stripped, letter-spaced words rejoined) so `ig​nore`, fullwidth `ｉｇｎｏｒｅ`, and `i-g-n-o-r-e` don't slip past. Every pattern is bounded (linear time on adversarial whitespace — see v1.5.0 notes) and inputs over 512 KB are head/tail-scanned with `truncated: true`. Returns a severity score, matched patterns, and per-match excerpts (±60 chars of context, line number, offset) so flagged events are triageable even when the payload is buried deep in a long page. It is a tripwire, not a gate: translation, encoding, and paraphrase still evade it — measured at **93.2% precision / 74.5% recall** on the committed benchmark corpus, with a pluggable detector slot for what regexes can't reach.

**Wrap** — Tags untrusted content (web pages, file uploads, voice transcripts, search results) with `<untrusted_*>` XML boundaries so the model treats it as data, not instructions. Content is sanitized first: any embedded `</untrusted_*>` sequence that could close the boundary early (including case, whitespace, zero-width padding, and fullwidth-bracket variants) is neutralized to `&lt;…`, and a `trigger_stripped` event is logged. Labels are normalized to `[a-z0-9_]` so a caller-supplied label can't forge markup.

**Harden** — Appends a stable anti-injection boilerplate and embeds a canary token (`SHLD-` + 13 base-36 chars) into the system prompt. If the canary appears in the model's output, an injection likely leaked through. The leak check also catches lightly obfuscated echoes (spacing, dashes, case changes) and — via the client wrappers — runs on **streaming** responses too, as the stream is consumed. The per-process canary salt requires a CSPRNG (`crypto.randomUUID`/`getRandomValues` in TS, `secrets` in Python); shield fails loudly rather than arming a guessable canary. Set `SHIELD_CANARY_SALT` (≥16 chars, from a secret store) on horizontally scaled deployments so every worker produces the same hardened prompt and prompt caching keeps working; or pass `canary` to a wrapper to pin the token outright. Absence of a leak event is not proof of safety — heavy transformations (base64, translation) still slip through.

**Log** — All shield events (detections, canary leaks, blocked messages) go through an in-process event bus (`onShieldEvent` / `on_event`, with `replay` for late subscribers) and, by default, append to `~/.shield/events.jsonl` (override with `SHIELD_LOG_DIR`), shared across TS and Python apps. The client wrappers wire the file sink themselves under Node, writes are synchronous, and events emitted before the sink attached are replayed — so a script that exits right after a detection, or an app that constructs its client before calling `initFileLogger()`, no longer loses events. Query with the CLI. The log holds snippets of flagged user content, so the dir/file are created owner-only (`0700`/`0600`; older installs are tightened on first write). The CLI strips terminal control and bidi-override characters from logged text before printing, so a flagged payload can't smuggle ANSI escape codes into your terminal when you review events.

**Watch the output** — The other half. Every response that passes through a wrapper (or `shield.scanOutput(text)` directly) is scanned for leaked credentials (AWS/GitHub/OpenAI/Anthropic/Slack/Google/Stripe key shapes, JWTs, private-key blocks, connection strings, generic `api_key=` assignments, plus any app-specific values you register as `secrets`), PII (email, phone, SSN, Luhn-valid card numbers, IBAN), exfiltration channels (markdown/HTML image beacons and URLs with opaque query strings to hosts outside your `allowedHosts`, `mailto:`), *echo* (the model reproducing an instruction the input scan flagged), and *refusal* (the model saying it was asked to do something it declined). A refusal on its own is weak signal and scores below the flag threshold; a refusal that follows a **flagged input** scores 0.7, because it is what a probe that nearly worked looks like from the outside. Findings emit `output_flagged` with masked excerpts; registered secrets are never written to a log, and any excerpt that would carry one is withheld.

**Gate tool calls** — Requested tool calls (`tool_use` blocks, chat `tool_calls`, Responses `function_call` items) are evaluated against a `toolPolicy`: allow/deny lists, side-effecting tools requested after untrusted input was seen (the "lethal trifecta" precondition), argument rules, and host allow-lists for URLs in arguments. Decisions emit `tool_call_gated`; with `enforceToolPolicy: true` the wrapper strips *blocked* calls from non-streaming responses. `shield.checkToolCall(call, ctx)` does the same for your own agent loop.

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
import { shieldAnthropic } from '@local/shield';
import Anthropic from '@anthropic-ai/sdk';

const client = shieldAnthropic(new Anthropic(), { appLabel: 'my-app' });
// `client` has the same TypeScript type as what you passed in. Use it exactly
// like the Anthropic client — detection, hardening, and canary checks happen
// automatically on messages.create / parse / stream.
const msg = await client.messages.create({ ... });
// (new ShieldAnthropicClient(inner, opts) still works and returns the same proxy.)

// Tool results (fetched pages, file contents, search output) are the main
// indirect-injection channel in agentic apps, so since v1.3 they are always
// scanned and wrapped as <untrusted_tool_result> by default. Detections show
// up in the log with a `:tool_result` source qualifier. Opt out of the
// wrapping (scanning stays on) with:
//   new ShieldAnthropicClient(inner, { wrapToolResults: false })
// Python: ShieldAnthropicClient(inner, wrap_tool_results=False)
```

### Drop-in OpenAI/OpenRouter wrapper

```ts
import { shieldOpenAI } from '@local/shield';
import OpenAI from 'openai';

const client = shieldOpenAI(new OpenAI(), { appLabel: 'my-app' });
const completion = await client.chat.completions.create({ ... });   // also .parse / .stream / .runTools
const response = await client.responses.create({ instructions, input }); // Responses API: also .parse / .stream
```

### Instances: `createShield(config)`

For anything beyond one app on one laptop, build an instance and hand it to the wrappers. It owns its config, sinks and event buffer; events still forward to the shared log unless you say otherwise.

```ts
import { createShield, shieldAnthropic } from '@local/shield';

const shield = createShield({
  app: 'support-bot',
  secrets: [process.env.DB_PASSWORD!],            // never emitted, never logged
  output: { allowedHosts: ['example.com'] },       // links elsewhere with opaque queries ⇒ exfil:beacon-url
  toolPolicy: {
    deny: ['run_shell'],
    sideEffects: ['send_email', 'http_post'],      // flagged when requested after untrusted input
    blockSideEffectsAfterUntrusted: true,
    argumentRules: [{ pattern: /\.\.\//, action: 'block', reason: 'path traversal' }],
    allowedHosts: ['api.example.com'],
  },
  redact: 'hash',                                  // log a hash of excerpts instead of user content
  sinks: [(ev) => otel.emit(ev)],                  // console, webhook, OpenTelemetry…
  forwardToGlobal: true,                           // default: also reaches ~/.shield/events.jsonl
});

const client = shieldAnthropic(new Anthropic(), { shield, enforceToolPolicy: true });

// Or use the pipeline in your own loop:
const inScan  = shield.scanInput(pageText, { channel: 'tool_result' });
const outScan = shield.scanOutput(reply, { inputScans: [inScan] });
const verdict = shield.checkToolCall({ name: 'send_email', input: args }, { untrustedInputSeen: true });
if (verdict.decision === 'block') { /* don't run it */ }
```

Python: `create_shield(app=..., secrets=[...], allowed_hosts=[...], tool_policy=ToolPolicy(...), sinks=[...])` and `shield_anthropic(client, shield=sh, enforce_tool_policy=True)`; `sh.scan_input / scan_output / check_tool_call`.

### Adding your own detection: `detectors`

The pattern layer is a tripwire. It catches known phrasings and misses
paraphrase, translation and anything novel — the benchmark below reports that
honestly. The detector slot is where you add what regexes can't do: a local
classifier, an embedding-similarity check, your own term list, an LLM judge.

```ts
import { createShield, type Detector } from '@local/shield';

const termList: Detector = {
  name: 'terms',
  sides: ['input'],                                  // default: both sides
  scan: (text) => text.includes('project raven')
    ? [{ label: 'codename', weight: 0.8, excerpt: 'project raven' }]
    : [],
};

const judge: Detector = {
  name: 'judge',
  sides: ['output'],
  scan: async (text, ctx) => {                        // async: output side only
    if (!ctx.baseline?.flagged) return [];            // skip the cheap-clear case
    const verdict = await askSmallModel(text);
    return verdict.bad ? [{ label: 'llm', weight: 0.7 }] : [];
  },
};

const shield = createShield({ app: 'support-bot', detectors: [termList, judge] });
```

Findings arrive namespaced as `detector:<name>:<label>` in `scan.matches`, and
combine with the pattern score the same way patterns combine with each other:
the strongest signal wins, each extra signal adds a little.

**Sync and async are not interchangeable, and the difference is deliberate.**
Sync detectors run everywhere, including inside the SDK wrappers. Async ones
run in `scanInputAsync` / `scanOutputAsync`, and on the output side are also
fired off by `scanOutput`, arriving later as their own event — output scanning
never gates anything, so a late answer is still useful. Input scanning feeds
the tool-call decision, so `scanInput` **skips** async detectors and warns
once rather than deciding without them. A detector that throws or rejects is
reported and dropped; it never takes the scan down with it.

Python is the same shape: `Detector(name=..., scan=fn, sides=("input",))` and
`create_shield(detectors=[...])`, with `scan_input_async` / `scan_output_async`.

### How good is the detection? `npm run bench`

Measured, not asserted. `bench/corpus.jsonl` holds 101 hand-written samples —
55 attacks across nine families, 46 benign of which 20 are deliberately
attack-shaped ("Can you act as a translator?", "Disregard my last message, I
pasted the wrong log"). Both test suites score the pattern layer against it
and fail below the floors in `bench/baseline.json`.

| metric | current | floor |
|---|---|---|
| precision | 93.2% | 90% |
| recall | 74.5% | 72% |
| F1 | 82.8% | 80% |

Recall is well under 1.0 on purpose. The corpus includes translated,
base64-encoded and purely paraphrased attacks that no regex catches, and a
corpus-shape test blocks "improving" the score by deleting them. **Raise
recall with a detector, not with a pattern that memorises the corpus.**

```bash
npm run bench                            # the report, with per-family misses
npm run bench:corpus                     # regenerate corpus.jsonl after editing
SHIELD_CORPUS=/path/to.jsonl npm run bench   # measure against your own corpus
cd python && python3 -m unittest tests.test_benchmark -v
```

Both languages read the same corpus and the same floors, so the two
implementations cannot drift apart without one of them failing.

### Coverage is deny-by-default

A protection that silently doesn't apply looks exactly like no protection, so
the wrappers refuse to hand you an unshielded path by accident. Data-only
surfaces (`models`, `embeddings`, `files`, `messages.countTokens`, …) pass
through. Anything that could carry a prompt to the model and isn't covered
(`beta`, legacy `completions`, `messages.batches`, `withOptions`) throws
`ShieldCoverageError` at access time. Opt a surface out by name if you really
need it unshielded:

```ts
shieldOpenAI(new OpenAI(), { passthrough: ['beta'] });
# Python: shield_openai(OpenAI(), passthrough=["beta"])
```

Other wrapper options: `wrapUserMessages`, `wrapToolResults` (default on),
`canary` (pin the token), `fileLogger: false` (don't attach the JSONL sink),
`announce: false`. Anthropic `document` blocks with inline text are scanned
too (source qualifier `:document`); Python async clients (`AsyncOpenAI`,
`AsyncAnthropic`) are canary-checked as well.

### File logger (Node.js)

```ts
import { initFileLogger, onShieldEvent } from '@local/shield';

await initFileLogger(); // wires events → ~/.shield/events.jsonl (wrappers do this for you)
onShieldEvent((ev) => myLogger.warn(ev), { replay: true }); // or route them anywhere
```

### React hook

```tsx
import { ShieldProvider, useShield } from '@local/shield/react';

function App() {
  return <ShieldProvider><YourApp /></ShieldProvider>;
}

function MessageInput() {
  const { scan } = useShield();
  const result = scan(userMessage);
  if (result.flagged) { /* warn the user */ }
}
```

## Python usage

```python
from shield import shield_anthropic, shield_openai, detect_injection, wrap_untrusted, harden_system_prompt, on_event
import anthropic

client = shield_anthropic(anthropic.Anthropic(), app_label="my-app")   # or ShieldAnthropicClient(...)
on_event(lambda ev: my_logger.warning(ev), replay=True)                  # optional: route events yourself

prompt, canary = harden_system_prompt(BASE_PROMPT)
scan = detect_injection(user_text)
safe = wrap_untrusted(user_text, "voice_transcript")
```

## CLI

```bash
npx shield logs              # tail ~/.shield/events.jsonl
npx shield logs --limit 20
npx shield logs --type injection_detected   # or output_flagged, tool_call_gated, canary_leaked …
npx shield logs --source bulwork
npx shield status            # per-app health, version drift, gone-quiet apps
npx shield headless          # one-shot scan for browser automation processes
npx shield headless --watch --interval 15   # keep watching, log new detections
npx shield scan "ignore previous instructions and..."
npx shield clear
```

`shield headless` is a tripwire, not a blocker: every hit is logged with pid, matched signatures, and the command line, then it's your call. Expect hits from your own test runs — the value is the ones you *can't* explain. (First real catches: three Playwright drivers Antigravity IDE had kept alive for weeks, and a transient Puppeteer headless Chrome from a Vercel plugin bootstrap.) Python apps can embed the same check via `from shield import scan_and_report`.

### Continuous watching + notifications (LaunchAgent)

`--notify` posts a macOS notification (with sound) for each new detection. For always-on coverage, install the LaunchAgent — it survives reboots, polls every 30s, notifies, and appends to `~/.shield/headless-watch.log`:

```bash
sed -e "s|__NODE__|$(which node)|g" -e "s|__SHIELD_REPO__|$PWD|g" -e "s|__HOME__|$HOME|g" \
    launchd/com.shield.headless-watch.plist > ~/Library/LaunchAgents/com.shield.headless-watch.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.shield.headless-watch.plist
```

It's read-only monitoring (scans `ps`, writes events, executes nothing it finds) — safe to run permanently, unlike the auto-sync cron this repo removed. Uninstall with `launchctl bootout gui/$(id -u)/com.shield.headless-watch`. Note: the plist is a template; re-run the `sed` if node or the repo moves.

## Knowing shield is on — banners, heartbeats, `shield status`

Lesson learned the hard way (wearabLLM shipped with a broken import path for months): **a protection that fails to load looks exactly like no protection.** Shield v1.1+ closes that gap in two layers:

**1. Startup banner + heartbeat (automatic).** Constructing `ShieldAnthropicClient` / `ShieldOpenAIClient` prints once per process:

```
[shield] v1.5.0 active · app=bulwork · 30 patterns · canary armed · wrap=off
```

…and emits a `shield_started` heartbeat event to the shared log. Apps using the lower-level primitives directly should call `announceShield({ appLabel })` / `announce_shield(app_label)` at startup. Pass `announce: false` or set `SHIELD_QUIET=1` to silence the banner — the heartbeat always fires. Get used to seeing the banner; its absence means shield didn't load.

**2. Central status (`npx shield status`).** You can't rely on noticing a missing banner, so the heartbeats feed one admin view across every app:

```
shield status (library v1.1.0, log: ~/.shield/events.jsonl)

  bulwork      v1.0.0 · last start 7/1/2026 · 7d: 1 injections, 0 stripped, 0 leaks
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
| bulwork, voicelogger-cli (`file:../shield`) | `npm install` (or `npm update @local/shield`) + rebuild |
| group-chat (vendored copy) | `~/Projects/shield-sync.sh` (test-gated, review-first) |

## Tests

Both packages have zero-dependency test suites (Node's built-in runner / Python's `unittest`) covering the attack corpus, benign false-positive checks, tag-breakout attempts, canary behavior, the detector API, and the detection benchmark (118 TypeScript tests, 98 Python):

```bash
# TypeScript (runs in CI on every push)
npm test

# Python (also runs in CI)
cd python && python3 -m unittest discover -s tests -v
```

When adding a detection pattern or changing wrapping/hardening behavior, change **both** packages and both test suites — they are kept in feature parity by hand, and CI fails if `package.json`, `pyproject.toml`, and the two `SHIELD_VERSION` constants disagree (`npm run check:versions`). Both live in this repo (TypeScript at the root, Python under `python/`) so one commit covers both sides.

## Event log

All events share `~/.shield/events.jsonl` — Python and TypeScript apps write to the same file. Fields:

```jsonc
{
  "timestamp": "2026-06-28T16:00:00.000Z",
  "type": "injection_detected" | "canary_leaked" | "output_flagged" | "tool_call_gated" | "trigger_stripped" | "shield_started" | "headless_detected",
  "direction": "input" | "output" | "tool",  // v1.6+, which side of the model the event concerns
  "source": "bulwork",                  // app label; ":tool_result" qualifier when the hit came via a tool result
  "score": 0.9,                         // 0–1 risk score (injection events)
  "patterns": ["ignore-instructions"],  // matched pattern labels
  "detail": "[ignore-instructions @L12] \"…context around the match…\""  // ±60 chars around each match, capped at 300
}
```

Environment variables: `SHIELD_LOG_DIR` (log location), `SHIELD_CANARY_SALT`
(stable canaries across processes), `SHIELD_QUIET` (no banner).

## Requirements

Node ≥ 20 (`globalThis.crypto`; synchronous log writes need ≥ 20.16) or any
evergreen browser via the `browser` export condition / `@local/shield/browser`.
Python ≥ 3.10. Zero runtime dependencies on either side.

## Apps wired up

| App | Language | Integration |
|---|---|---|
| `group-chat` | TypeScript | `hardenSystemPrompt` on every bot call; `detectInjection` on user messages; Gemini history sanitized |
| `bulwork` | TypeScript | `ShieldAnthropicClient`; page title wrapped as `untrusted_page_title` |
| `voicelogger-cli` | TypeScript | `ShieldAnthropicClient`; transcript wrapped as `untrusted_voice_transcript` |
| `wearabLLM` | Python | `ShieldAnthropicClient`; voice input wrapped and scanned |

> Note: this table may be stale for `bulwork` — its current source uses shield's
> lower-level primitives with dynamic per-call source strings, not a static
> `ShieldAnthropicClient` app label as described above. Worth reconciling later.

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
