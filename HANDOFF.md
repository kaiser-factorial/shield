# shield handoff

**State as of 2026-09-11:** v1.9.0. Every code item from the September review
has shipped, and both packages are renamed and release-ready as
**`prompt-shield`**. Nothing is published yet — `RELEASING.md` has the
checklist, and the two upload commands need your credentials.

**v1.9.0 (packaging):** renamed to `prompt-shield` on both registries (the
Python *import* stays `shield`), added `/node`, `/react`, `/anthropic`,
`/openai` subpath exports, a PyPI-facing `python/README.md`, a `LICENSE`, and
packaging smoke tests that run against a real install rather than the repo.

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

**Previously (v1.5.0):** See `docs/REVIEW-2026-09.md` for the review that
drove this whole run of releases. Everything it raised has since shipped —
§2 (`createShield`) and §4 (the output pipeline) in v1.6.0, the detection
items in v1.7.0, the enforcement gaps in v1.8.0. Read it for the reasoning
and the reproductions, not for open work.

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

Prompt-injection defense library for LLM apps. Four layers plus
observability — the first three act on what goes IN to the model, the fourth
on what comes back OUT and what the model then asks to do:

1. **DETECT** — 30 weighted regex patterns (`detectInjection` /
   `detect_injection`). A tripwire, not a gate: trivially bypassed by
   translation/encoding/rephrasing, so callers decide whether to block.
   Measured on `bench/corpus.jsonl`: **93.2% precision, 74.5% recall**,
   identical in both languages and gated in CI. Recall is under 1.0 on
   purpose — the corpus carries attacks no regex catches. Raise it with a
   detector, never with a pattern that memorises the corpus.
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
4. **WATCH THE OUTPUT AND THE TOOL CALLS** (v1.6.0+) — `scanOutput` /
   `scan_output` inspects responses for credential shapes, registered app
   secrets, PII, exfiltration channels, echoed injections and refusals.
   `checkToolCall` / `check_tool_call` evaluates what the model asks to run
   against a `ToolPolicy`: allow/deny lists, side-effecting tools requested
   after untrusted input (the lethal trifecta), argument rules, per-tool
   argument schemas, host allow-lists. Streamed tool calls are reassembled
   from their fragments and evaluated before the caller can act on them.
   Content shield could not read (base64 PDFs, remote URLs) raises
   `content_not_scanned` rather than passing silently.
5. **DETECTORS** (v1.7.0) — a pluggable slot for what regexes cannot do:
   a classifier, a term list, an LLM judge. Sync detectors run everywhere;
   async ones run on the output side and in the `*Async` scans. The regex
   layer's honest rate is in `bench/` and gated in CI.
6. **ANNOUNCE / STATUS** — client wrappers print a startup banner and emit
   a `shield_started` heartbeat (carrying the version) on construction.
   `npx shield status` aggregates heartbeats per app: version drift vs the
   repo, apps gone quiet, 7-day injection/strip/leak counts. Exits
   non-zero on warnings.
7. **HEADLESS WATCH** (v1.2.x) — `npx shield headless [--watch] [--notify]`
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
| `src/output.ts` | output-side detectors (secrets/PII/exfil/echo/refusal), tool-call policy, argument schemas, `ShieldBlockedToolError` |
| `src/instance.ts` | `createShield(config)` instance: sinks, redaction, output/tool policy, detectors |
| `src/detectors.ts` | the pluggable `Detector` slot (sync + async, isolated failures) |
| `src/stream.ts` | stream tap: output text AND tool-call reassembly for raw streams |
| `src/index.ts` / `src/index.browser.ts` | root entry; browser entry (no fs/child_process) |
| `src/node.ts`, `src/anthropic.ts`, `src/openai.ts` | subpath entries (`prompt-shield/node` etc.) |
| `src/client-anthropic.ts` | drop-in Anthropic wrapper (duck-typed, no SDK import) |
| `src/client-openai.ts` | drop-in OpenAI-compatible wrapper (chat.completions + responses) |
| `src/logger.ts` | JSONL file logger + `summarizeStatus` (pure, tested) |
| `src/headless.ts` | automation-process signatures + scanner (`python/shield/headless.py` mirrors) |
| `src/react.ts` | `ShieldProvider`, `useShield`, `useInjectionScan` |
| `bin/shield-cli.ts` | CLI: `logs`, `status`, `scan`, `clear`, `headless` |
| `bench/corpus.jsonl`, `bench/baseline.json` | 101-sample detection corpus + the committed precision/recall floor |
| `scripts/make-corpus.mjs` | regenerates the corpus (`npm run bench:corpus`) |
| `scripts/check-versions.mjs` | fails CI if the two manifests and `core.py` disagree |
| `scripts/smoke-package.mjs`, `scripts/smoke_package.py` | packaging smoke tests — run against an INSTALLED package, never the repo |
| `eslint.config.js` | type-aware eslint; ruff + mypy config live in `python/pyproject.toml` |
| `RELEASING.md` | the publish checklist (nothing is published yet) |
| `LICENSE` | MIT — added as the conventional default, **confirm before publishing** |
| `README.md` / `python/README.md` | root is TypeScript-first; the Python one is what PyPI shows |
| `test/*.test.ts` | node:test suites (146 tests) — `npm test` |
| `python/shield/` | Python port, same API in snake_case |
| `python/tests/` | unittest suites (126 tests) — `cd python && python3 -m unittest discover -s tests` |
| `~/Projects/shield-sync.sh` | manual sync → group-chat (see below) |

**Parity rule:** every behavior change lands in BOTH languages and both
test suites, same commit. A test pins `SHIELD_VERSION` to
package.json/pyproject on each side, and `npm run check:versions` (in CI)
fails if the two sides disagree. Since v1.7.0 the two implementations also
score the SAME benchmark corpus against the SAME floor, so detection cannot
drift between them without one side failing.

**What CI enforces** (`.github/workflows/ci.yml`): eslint + `tsc --noEmit` +
146 tests + the benchmark floor on Node 20 and 22; ruff + mypy + 126 tests +
the same floor on Python 3.10 and 3.12; and the cross-language version check.

---

## consumers and how they update

| app | link | update path |
|---|---|---|
| bulwork | `file:../shield` | `npm install` + `npm run build` |
| voicelogger-cli (`ledger_root/`) | `file:../../shield` | `npm install` (runs via tsx, no build) |
| group-chat | vendored `packages/shield/` | `~/Projects/shield-sync.sh` |
| wearabLLM v1 (`bridge.py`) | `sys.path` insert → `../../../shield/python` | imports live source — updates instantly |

Every one of these is a path or vendored install, which is exactly what
publishing fixes. **Once `prompt-shield` is on the registries, move them to
`npm install prompt-shield` / `pip install prompt-shield`** and the
`file:` links go away. Note the npm package name changed from
`@local/shield` to `prompt-shield` in v1.9.0, so those installs are a rename
for the consumer, not just a version bump.

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

1. **Publish** (see `RELEASING.md`). Everything is prepared and rehearsed;
   what needs you is confirming the licence and running the two upload
   commands with your credentials. Unscoped npm names are first-come, and
   both names were unclaimed as of 2026-09-11.
2. **Then update the consumers to v1.9.0** — bulwork / voicelogger-cli
   (`npm install` + build), group-chat (`shield-sync.sh`), wearabLLM (live
   import, nothing to do). `shield status` flags anything on an older
   version. Three things a consumer must know:
   - The npm package is now **`prompt-shield`**, not `@local/shield`. The
     Python import is unchanged (`from shield import ...`).
   - Pass a `createShield({...})` instance with each app's `secrets`,
     `output.allowedHosts` and `toolPolicy`. The defaults scan but gate
     nothing: no policy means every tool call is allowed, and no
     allow-list means plain links are not findings.
   - Streaming callers that turn on `enforceToolPolicy` should catch
     `ShieldBlockedToolError`. That is the one behaviour change since
     v1.7.0 a caller can actually notice.
3. **Run bulwork and voicelogger once** after rebuilding — heartbeats fire
   at app startup, so `shield status` shows "never announced" until then.
4. Optional: add `npx shield status` to shell profile for a login-time
   nudge (read-only — safe to automate, unlike the old cron).

---

## shipped in v1.9.0

- **Renamed to `prompt-shield`** on both registries. The Python *import*
  stays `shield`: only the distribution name changed, so no consumer's
  `from shield import ...` line moves, and a dashed name is not a legal
  Python identifier anyway. The npm name IS a rename for consumers.
- **Split entry points** — `/node`, `/anthropic`, `/openai` added to the
  existing `/react`, `/browser`, `/shield`. The root still carries
  everything; the subpaths let an app pull in only what it uses and keep a
  bundler from following `fs` into a browser build.
- **Packaging smoke tests** — `scripts/smoke-package.mjs` (14 checks) and
  `scripts/smoke_package.py` (12 checks). Both run against an INSTALLED
  package from outside the repo, which is the only way they mean anything:
  in the source tree relative paths resolve even when `exports` is wrong,
  and Python finds the source on `sys.path` even when a module is missing
  from the wheel. The npm one also asserts `/anthropic` does not re-export
  the OpenAI wrapper — a subpath that is secretly an alias for the root is
  not a narrowing, and nothing else would catch that.
- **`LICENSE` (MIT), registry metadata, `python/README.md`, `RELEASING.md`.**
  The Python readme was needed regardless: hatchling refuses to build
  without one inside the package root, and PyPI should not show a
  TypeScript-first page.
- The lockfile was regenerated. It had still been advertising
  `@local/shield` at 1.7.0 after the rename; `npm ci` tolerated it, but a
  lockfile naming a different package than its manifest is wrong on its own
  terms, and the packaging smoke tests could not have caught it (a packed
  tarball does not contain the lockfile).

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

## outstanding

Nothing here is blocked on code. The first two are duplicated in "pending"
above because they are the active thread; the rest have sat here across
several releases because they need a decision, a live service, or an
afternoon of writing rather than a patch.

- **Publish** — prepared and rehearsed; `RELEASING.md` is the checklist.
  Two things need you: confirm the licence (MIT was added as the
  conventional default, not your explicit choice — see the top of
  RELEASING.md), and run `npm publish` / `twine upload` with your
  credentials. Both names were unclaimed as of 2026-09-11, and unscoped npm
  names are first-come.
- **Update consumers after publishing** — bulwork, voicelogger-cli and
  group-chat move from `file:` / vendored installs to the published
  packages, under the new npm name.
- **Toolkit docs** (`docs/` playbook): threat model; the "lethal trifecta"
  rule (untrusted input + private data + exfiltration channel); MCP/plugin
  hygiene — the carta-cap-table plugin injecting `<EXTREMELY_IMPORTANT>`
  directives into Claude sessions is the motivating case study; personal
  opsec basics.
- **Startup self-check** — beyond announcing, verify the boilerplate
  actually reached the system prompt (e.g. a cheap round-trip assertion).
- **Audit connected surface** in Claude/MCP sessions — every connector is
  both an injection source and target; trim to what's used.
