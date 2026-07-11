# shield handoff

**State as of 2026-07-02:** v1.2.0. Monorepo (TS at root, Python under
`python/`), both languages at feature parity with test suites in CI. All
four consumer apps rebuilt. The auto-sync cron is gone — syncing is
manual and review-first, on purpose.

---

## what shield is

Prompt-injection defense library for LLM apps. Three-layer model plus
observability:

1. **DETECT** — 25 weighted regex patterns (`detectInjection` /
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
| `src/shield.ts` | core: patterns, wrap/sanitize, harden/canary, announce, event bus |
| `src/client-anthropic.ts` | drop-in Anthropic wrapper (duck-typed, no SDK import) |
| `src/client-openai.ts` | drop-in OpenAI-compatible wrapper |
| `src/logger.ts` | JSONL file logger + `summarizeStatus` (pure, tested) |
| `src/headless.ts` | automation-process signatures + scanner (`python/shield/headless.py` mirrors) |
| `src/react.ts` | `ShieldProvider` / `useInjectionScan` hook |
| `bin/shield-cli.ts` | CLI: `logs`, `status`, `scan`, `clear` |
| `test/*.test.ts` | node:test suites (32 tests) — `npm test` |
| `python/shield/` | Python port, same API in snake_case |
| `python/tests/` | unittest suites (26 tests) — `cd python && python3 -m unittest discover -s tests` |
| `~/Projects/shield-sync.sh` | manual sync → group-chat (see below) |

**Parity rule:** every behavior change lands in BOTH languages and both
test suites, same commit. A test pins `SHIELD_VERSION` to
package.json/pyproject on each side.

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

1. **Push group-chat** — sync commit `36e144d` is local-only.
2. **Run bulwork and voicelogger once** — heartbeats fire at app startup,
   not install, so `shield status` shows "never announced" for them until
   their first post-rebuild run. After that, any "never announced" warning
   is a real alarm.
3. Optional: add `npx shield status` to shell profile for a login-time
   nudge (read-only — safe to automate, unlike the old cron).

---

## roadmap (discussed, not started)

- **Tool-call/output-side policy** — the biggest gap. Shield only guards
  input + canary today; nothing constrains what a model *does* after
  reading untrusted content (tool calls, exfiltration). This is where real
  damage happens in agentic apps.
- **Toolkit docs** (`docs/` playbook): threat model; the "lethal trifecta"
  rule (untrusted input + private data + exfiltration channel); MCP/plugin
  hygiene — the carta-cap-table plugin injecting `<EXTREMELY_IMPORTANT>`
  directives into Claude sessions is the motivating case study; personal
  opsec basics.
- **Detection benchmarking** — measure the regex layer's honest catch rate
  against a public injection-payload corpus; document it as telemetry, not
  a gate.
- **Startup self-check** — beyond announcing, verify the boilerplate
  actually reached the system prompt (e.g. a cheap round-trip assertion).
- **Audit connected surface** in Claude/MCP sessions — every connector is
  both an injection source and target; trim to what's used.
