# shield handoff

**State as of 2026-09-11:** v1.8.0. Every code item from the September review
has now shipped. What remains needs a decision from you (package names) or is
not code (docs playbook, connected-surface audit).

**v1.8.0 (enforcement gaps):** raw-stream tool-call evaluation, per-tool
argument schemas, document wrapping plus a `content_not_scanned` signal, and
lint + type-check in CI. Files: `src/stream.ts`, `python/shield/stream_tools.py`,
`src/output.ts`, `python/shield/output.py`, `eslint.config.js`.

**v1.7.0 (detectors + benchmark):** a pluggable `Detector` slot behind the
scans, a `refusal` output category, and a committed precision/recall floor
measured over `bench/corpus.jsonl` in both languages. Files:
`src/detectors.ts`, `python/shield/detectors.py`, `bench/`,
`test/benchmark.test.ts`, `test/detectors.test.ts`.

**v1.6.0 (output pipeline + instance API):** `scanOutput` / `scan_output`
inspects model output for credential shapes, registered app secrets, PII,
exfiltration channels (image beacons, opaque-query URLs to unlisted hosts,
mailto) and *echo* of input-flagged patterns → `output_flagged` events with
masked excerpts. `evaluateToolCall` / `evaluate_tool_call` applies a
`ToolPolicy` (allow/deny, side-effect tools after untrusted input, argument
rules, host allow-list) → `tool_call_gated`; wrappers check `tool_use` /
`tool_calls` / `function_call` on every response and strip BLOCKED calls
when `enforceToolPolicy` is on. `createShield(config)` / `create_shield`
gives an instance with its own app label, thresholds, secrets, output and
tool policy, sinks, redaction (`excerpt|hash|none`) and recent buffer;
events forward to the module bus (and the JSONL log) by default. Wrappers
take `shield:` to share one. Events carry `direction`. `shield status`
counts output flags and gated tool calls. Files: `src/output.ts`,
`src/instance.ts`, `python/shield/output.py`, `python/shield/instance.py`.

**Previously (v1.5.0):** See `docs/REVIEW-2026-09.md` for the
review that drove this release and for what's still open (the output-side
pipeline and the `createShield(config)` instance API from §2/§4 of that doc).

**v1.5.0 (review fixes):** two detection regexes were quadratic on
whitespace (`system-colon`, `untrusted-tag-breakout`) — 40k newlines took
31 s in Python; all patterns are now bounded and inputs > 512 KB are
head/tail-scanned (`truncated`). Input is NFKC-normalized with zero-width
chars stripped and letter-spaced words rejoined before matching; four
patterns added (`encode-above`, `chat-delimiter-spoof`,
`markdown-image-exfil`, `exfil-send-to`) and three everyday phrasings
(`act-as`, `roleplay-as`, `what-is-your-system`) dropped below the
threshold — 30 patterns. Event durability: the bus keeps a replay buffer,
the file sink writes synchronously (`process.getBuiltinModule`), wrappers
attach it themselves, `SHIELD_LOG_DIR` overrides the location, home dir
comes from `os.homedir()`, and `readEvents` skips malformed lines. Python
gained the same bus (`on_event`/`off_event`/`read_events`). Wrappers are
rebuilt on a deny-by-default proxy: `parse`/`stream`/`runTools`, the OpenAI
Responses API, Anthropic `document` blocks, and Python async clients are
covered; anything else that could carry a prompt throws
`ShieldCoverageError` unless opted out via `passthrough`. New
`shieldAnthropic`/`shieldOpenAI` (`shield_*` in Python) return the input
type. Canary is 64-bit base-36, `SHIELD_CANARY_SALT` / `canary` option pin
it across workers, and the salt is resolved lazily (import never throws).
Labels are sanitized, zero-width tag breakouts neutralized, bidi overrides
stripped in the CLI, timestamps compared as instants, `engines: node>=20`,
browser export condition, CI matrices, a cross-language version check, and
the launchd plist is a template.

**Previously (v1.4.0):** Monorepo (TS at root, Python under
`python/`), both languages at feature parity with test suites in CI. The
auto-sync cron is gone — syncing is manual and review-first, on purpose.

**v1.4.0 (canary hardening):** the leak check now catches lightly
obfuscated echoes (spacing/dashes/case are stripped before comparing) and
runs on streaming responses: `messages.stream()` is now exposed by the TS
Anthropic wrapper (canary-checked on end), the Python `stream()` context
manager checks the SDK's accumulated snapshot on exit, and
`create(stream=True)` event/chunk streams are tapped so the check runs as
the caller consumes them — nothing is buffered or force-consumed by
shield itself. The TS canary salt now requires a CSPRNG
(`crypto.randomUUID`/`getRandomValues`) and throws instead of silently
falling back to `Math.random()` (Python always used `secrets`). Heavy
transformations (base64, translation) still evade the canary — absence
of a leak event is not proof of safety. Also in 1.4.0: `onShieldEvent`
returns an unsubscribe fn (new `offShieldEvent` too) and the React
provider cleans up on unmount — previously every remount stacked another
handler for the life of the process, each calling setState on an
unmounted component.

**v1.3.0 (security-review fixes):** tool results (Anthropic `tool_result`
blocks, OpenAI `role:"tool"` messages) are now always scanned and — by
default — wrapped as `<untrusted_tool_result>` (`wrapToolResults` /
`wrap_tool_results` to opt out of wrapping only); tool-side detections log
with a `:tool_result` source qualifier. `shield logs` / `headless` strip
terminal control chars from attacker-controlled text before printing
(ANSI/OSC escape injection). `~/.shield` is created `0700`/`0600` and
legacy perms are tightened on first write. The DAN pattern split in two:
`jailbreak-dan` matches all-caps `DAN` only (people named Dan no longer
flag) and `do-anything-now` catches the spelled-out phrase in any case —
26 patterns now. Injection events carry per-match excerpts (±60 chars of
context around what tripped the pattern) as `detail`, instead of the
head of the message, so deep-in-the-page hits are triageable. OpenAI
wrappers no longer clobber extra system messages (only the first
system/developer message is hardened; later ones pass through intact)
and `role: "developer"` is hardened in place instead of being ignored.
Consumers need a rebuild / `npm install` to pick this up —
`shield status` will flag the drift.

---

## what shield is

Prompt-injection defense library for LLM apps. Three-layer model plus
observability:

1. **DETECT** — 30 weighted regex patterns (`detectInjection` /
   `detect_injection`). A tripwire, not a gate: trivially bypassed by
   translation/encoding/rephrasing, so callers decide whether to block.
2. **WRAP** — `wrapUntrusted` tags external content in `<untrusted_*>` XML
   boundaries. Content is sanitized first so embedded `</untrusted_*>`
   sequences (any case, whitespace, fullwidth `＜`) can't close the
   boundary early. A `trigger_stripped` event fires when sanitization
   actually changed something — high-signal, someone tried to break out.
3. **HARDEN** — `hardenSystemPrompt` appends anti-injection boilerplate +
   canary token. Canary = djb2(per-process random salt + base prompt):
   stable within a process (prompt-cache-friendly), not derivable by
   someone who knows the system prompt. Canary in model output ⇒
   `canary_leaked` event.
4. **ANNOUNCE / STATUS** — client wrappers print a startup banner and emit
   a `shield_started` heartbeat (carrying the version) on construction.
   `npx shield status` aggregates heartbeats per app: version drift vs the
   repo, apps gone quiet, 7-day injection/strip/leak counts. Exits
   non-zero on warnings.
5. **HEADLESS WATCH** (v1.2.x) — `npx shield headless [--watch] [--notify]`
   scans running processes for browser automation (headless flags,
   `--remote-debugging-port`, Playwright/Puppeteer/WebDriver/Selenium/
   Cypress/PhantomJS) and logs `headless_detected` events; `--notify`
   posts macOS notifications. A LaunchAgent
   (`launchd/com.shield.headless-watch.plist`, installed at
   `~/Library/LaunchAgents/`) runs it permanently every 30s. Real catches
   on day one: Antigravity IDE had kept three Playwright drivers alive
   since mid-June (whole IDE + an 11-day-hung agent script killed
   2026-07-02), and a Vercel plugin bootstrap's transient Puppeteer
   headless Chrome.

All events from every app (TS + Python) land in `~/.shield/events.jsonl`.

---

## file map  (`~/Projects/shield/`)

| path | what it is |
|---|---|
| `src/shield.ts` | core: patterns, normalization, wrap/sanitize, harden/canary, announce, event bus |
| `src/coverage.ts` | deny-by-default proxy + `ShieldCoverageError` for the wrappers |
| `src/output.ts` | output-side detectors (secrets/PII/exfil/echo) + tool-call policy |
| `src/instance.ts` | `createShield(config)` instance: sinks, redaction, output/tool policy |
| `src/index.browser.ts` | browser entry (no fs/child_process) — `browser` export condition |
| `src/client-anthropic.ts` | drop-in Anthropic wrapper (duck-typed, no SDK import) |
| `src/client-openai.ts` | drop-in OpenAI-compatible wrapper (chat.completions + responses) |
| `src/logger.ts` | JSONL file logger + `summarizeStatus` (pure, tested) |
| `src/headless.ts` | automation-process signatures + scanner (`python/shield/headless.py` mirrors) |
| `src/react.ts` | `ShieldProvider` / `useInjectionScan` hook |
| `bin/shield-cli.ts` | CLI: `logs`, `status`, `scan`, `clear` |
| `test/*.test.ts` | node:test suites (106 tests) — `npm test` |
| `python/shield/` | Python port, same API in snake_case |
| `python/tests/` | unittest suites (86 tests) — `cd python && python3 -m unittest discover -s tests` |
| `~/Projects/shield-sync.sh` | manual sync → group-chat (see below) |

**Parity rule:** every behavior change lands in BOTH languages and both
test suites, same commit. A test pins `SHIELD_VERSION` to
package.json/pyproject on each side, and `npm run check:versions` (in CI)
fails if the two sides disagree.

---

## consumers and how they update

| app | link | update path |
|---|---|---|
| bulwork | `file:../shield` | `npm install` + `npm run build` (done for 1.1.0) |
| voicelogger-cli (`ledger_root/`) | `file:../../shield` | `npm install` (runs via tsx, no build) (done) |
| group-chat | vendored `packages/shield/` | `~/Projects/shield-sync.sh` (done; see pending) |
| wearabLLM v1 (`bridge.py`) | `sys.path` insert → `../../../shield/python` | imports live source — updates instantly |

There is **no auto-update by design** — drift is *detected* instead:
heartbeats carry each app's running version and `shield status` flags
stale ones.

---

## security decisions — do not quietly undo these

- **No auto-sync cron.** Until 2026-07-02 a 30-min cron auto-pulled
  origin/main, ran the build (= executed whatever landed on the remote),
  and auto-pushed group-chat. Removed: that's a supply-chain hole for a
  security library. `shield-sync.sh` is now manual — test-gated, shows the
  diff, prompts separately before commit and push (`--yes` skips prompts,
  never the tests). Crontab backup: `~/.shield/crontab-backup-2026-07-02.txt`.
- **Scan raw text BEFORE wrapping.** Wrapped output legitimately contains
  `<untrusted_*>` tags, which the `untrusted-tag-breakout` pattern flags.
- **Old shield-py folder** is backed up at
  `~/Projects/BACKUPS/shield-py-pre-monorepo-2026-07-02` — deletable once
  confident nothing else referenced it.

**The wearabLLM lesson** (drives the whole v1.1 design): its shield import
path pointed at a directory that never existed — the "protection" was dead
on arrival and nothing noticed. *A protection that fails to load looks
exactly like no protection.* Hence banners + heartbeats + central status.

---

## pending / immediate next steps

1. **Consumers need a rebuild for v1.8.0** — bulwork / voicelogger-cli
   (`npm install` + build), group-chat (`shield-sync.sh`), wearabLLM (live
   import, nothing to do). `shield status` flags anything still on an older version.
   Once rebuilt, pass a `createShield({...})` instance with each app's
   `secrets`, `output.allowedHosts` and `toolPolicy` — the defaults scan
   but gate nothing (no policy ⇒ every tool call allowed, no allow-list ⇒
   plain links aren't findings). Streaming callers should also catch
   `ShieldBlockedToolError` if they turn on `enforceToolPolicy` — that is
   the one behaviour change in v1.8.0 that a caller can notice.
2. **Run bulwork and voicelogger once** after rebuilding — heartbeats fire
   at app startup, so `shield status` shows "never announced" until then.
3. Optional: add `npx shield status` to shell profile for a login-time
   nudge (read-only — safe to automate, unlike the old cron).

---

## shipped in v1.7.0

- **Semantic detector slot** — `Detector` in `src/detectors.ts` /
  `python/shield/detectors.py`, passed as `createShield({ detectors: [...] })`.
  Sync detectors run everywhere including inside the SDK wrappers; async ones
  (an LLM judge) run in `scanInputAsync` / `scanOutputAsync` and are fired off
  by `scanOutput`. Async detectors are deliberately *skipped* by the
  synchronous input scan, with a one-time warning: that scan gates tool calls
  and a verdict arriving afterwards would be unsound. A detector that throws
  is isolated, never propagated.
- **Refusal telemetry** — a `refusal` output category. A refusal that follows
  a flagged input scores 0.7 (`refusal:<kind>:after-flagged-input`, a probing
  signal); an unprompted one scores 0.35, below the flag threshold.
- **Detection benchmark** — `bench/corpus.jsonl` (101 hand-written samples:
  55 attacks over 9 families, 46 benign of which 20 are attack-shaped) scored
  by `test/benchmark.test.ts` and `python/tests/test_benchmark.py` against the
  floors in `bench/baseline.json`. Both languages read the same corpus, so
  they cannot drift apart without one failing. Current measurement:
  **precision 93.2%, recall 74.5%, F1 82.8%**, identical in TS and Python.
  `npm run bench` prints the report; `SHIELD_CORPUS=/path` measures against
  your own corpus; `npm run bench:corpus` regenerates the file.

  The floors are floors, not targets. Recall is deliberately well under 1.0:
  the corpus includes translated, base64-encoded and purely paraphrased
  attacks no regex catches, and deleting them to inflate the number is
  blocked by a corpus-shape test. The way to raise recall is a detector, not
  a pattern that memorises the corpus. Widening three patterns during this
  work (stacked qualifiers in `ignore`/`disregard`, a looser noun phrase in
  `exfil-send-to`) took recall from 65.5% to 74.5% with no new false
  positives.

---

## shipped in v1.8.0

- **Raw-stream tool calls are now evaluated** — the real gap, and the one
  that most looked like working protection while doing nothing. A raw
  `create({stream: true})` stream delivers a tool call in fragments; nothing
  reassembled them, so the policy never ran on a streamed call at all.
  Assemblers for all three event shapes (Anthropic content blocks, OpenAI
  chat deltas, OpenAI Responses items) rebuild each call and evaluate it the
  moment it completes — before the caller can act on it, since the caller
  executes the tool after the stream yields it. Under `enforceToolPolicy` a
  blocked call raises `ShieldBlockedToolError` out of the iterator, which is
  what "strip the block" means when earlier events are already delivered. A
  truncated stream still reports the call it was assembling.
- **Per-tool argument schemas** — `ToolPolicy.schemas`. Deliberately not JSON
  Schema (zero dependencies); the `format` values cover what an injected
  model reaches for: `path` (traversal including `%2e%2e%2f`, absolute paths,
  NUL bytes), `url` (non-http schemes, host allow-list including the
  `https://good.example@evil.example/` userinfo trick), `email`. Undeclared
  arguments are rejected by default. Arguments that never parsed as JSON are
  a violation, not a silent pass.
- **Document blocks** — text documents are now wrapped as
  `<untrusted_document>`, not just scanned. Sources shield cannot read
  (base64 PDFs, remote URLs, uploaded file ids) raise `content_not_scanned`
  with score 0, and count as untrusted input for the tool policy. The point
  is that silence reads as "checked, clean"; a log that cannot tell "we
  looked and it was fine" from "we never opened it" is not a security log.
- **Lint + type-check in CI** — eslint (type-aware) and ruff + mypy, all
  clean, all gating. Both configs are deliberately narrow: the goal is
  catching defects, not enforcing style. pyupgrade was excluded after it
  proposed 83 `Optional[X]` rewrites with no security value. Two real mypy
  findings were fixed rather than suppressed.

---

## outstanding

- **Split entry points / publish** — `/node`, `/react`, `/anthropic`,
  `/openai` subpaths and real npm/PyPI names. **Needs your decision on the
  names**; today everything ships under `@local/shield` and installs via
  `file:`. This is the only remaining blocker to using shield from an
  arbitrary app without a path reference.
- **Toolkit docs** (`docs/` playbook): threat model; the "lethal trifecta"
  rule (untrusted input + private data + exfiltration channel); MCP/plugin
  hygiene — the carta-cap-table plugin injecting `<EXTREMELY_IMPORTANT>`
  directives into Claude sessions is the motivating case study; personal
  opsec basics.
- **Startup self-check** — beyond announcing, verify the boilerplate
  actually reached the system prompt (e.g. a cheap round-trip assertion).
- **Audit connected surface** in Claude/MCP sessions — every connector is
  both an injection source and target; trim to what's used.
