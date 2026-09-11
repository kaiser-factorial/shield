#!/usr/bin/env node
/**
 * shield CLI — inspect injection events and test detection
 *
 * Commands:
 *   shield logs [--limit N] [--type TYPE] [--source SRC]   print recent events
 *   shield scan <text>                                       scan text for injections
 *   shield clear                                             wipe the event log
 */

import { readEvents, summarizeStatus, initFileLogger, sanitizeForTerminal, LOG_FILE } from "../src/logger.js";
import { detectInjection, SHIELD_VERSION, type ShieldEvent } from "../src/shield.js";
import { scanHeadlessProcesses, reportHeadless } from "../src/headless.js";
import { existsSync, writeFileSync } from "fs";

const RESET = "\x1b[0m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const GREEN = "\x1b[32m";
const CYAN = "\x1b[36m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";

function colorScore(score: number): string {
  if (score >= 0.8) return `${RED}${score.toFixed(2)}${RESET}`;
  if (score >= 0.5) return `${YELLOW}${score.toFixed(2)}${RESET}`;
  return `${GREEN}${score.toFixed(2)}${RESET}`;
}

function typeLabel(t: string): string {
  switch (t) {
    case "injection_detected": return `${RED}⚡ inject${RESET}`;
    case "canary_leaked":      return `${RED}🐤 canary${RESET}`;
    case "trigger_stripped":   return `${YELLOW}✂ trigger${RESET}`;
    case "shield_started":     return `${GREEN}✓ start${RESET}`;
    case "headless_detected":  return `${YELLOW}👻 headless${RESET}`;
    case "output_flagged":     return `${RED}📤 output${RESET}`;
    case "tool_call_gated":    return `${RED}🛠 tool${RESET}`;
    default:                   return t;
  }
}

const args = process.argv.slice(2);
const cmd = args[0];

const EVENT_TYPES: ReadonlyArray<ShieldEvent["type"]> = [
  "injection_detected", "canary_leaked", "output_flagged", "tool_call_gated",
  "trigger_stripped", "shield_started", "headless_detected",
];

/** Positive integer flag value, or the default; rejects junk loudly. */
function intFlag(name: string, dflt: number, min = 1): number {
  const i = args.indexOf(name);
  if (i < 0) return dflt;
  const raw = args[i + 1];
  const n = Number(raw);
  if (!raw || !Number.isInteger(n) || n < min) {
    console.error(`${name} expects an integer >= ${min}, got ${JSON.stringify(raw ?? "")}`);
    process.exit(2);
  }
  return n;
}

if (!cmd || cmd === "help" || cmd === "--help") {
  console.log(`
${BOLD}shield${RESET} — prompt injection defense CLI

${BOLD}COMMANDS${RESET}
  ${CYAN}shield logs${RESET}                     Show recent injection events
    ${DIM}--limit N${RESET}                      Show last N events (default 50)
    ${DIM}--type TYPE${RESET}                    Filter: injection_detected | canary_leaked | output_flagged | tool_call_gated | trigger_stripped | shield_started | headless_detected
    ${DIM}--source SRC${RESET}                   Filter by source substring

  ${CYAN}shield status${RESET}                   Per-app health: last heartbeat, version drift, 7-day counts
  ${CYAN}shield headless${RESET}                 Scan running processes for browser automation
    ${DIM}--watch${RESET}                        Keep watching; log each new detection as an event
    ${DIM}--interval N${RESET}                   Poll every N seconds in watch mode (default 15)
    ${DIM}--notify${RESET}                       macOS notification on each new detection
  ${CYAN}shield scan <text>${RESET}              Scan text for injection patterns
  ${CYAN}shield clear${RESET}                    Wipe the event log

${BOLD}LOG FILE${RESET}
  ${DIM}${LOG_FILE || "(unavailable — set SHIELD_LOG_DIR)"}${RESET}
`);
  process.exit(0);
}

if (cmd === "logs") {
  const typeIdx = args.indexOf("--type");
  const sourceIdx = args.indexOf("--source");

  const limit = intFlag("--limit", 50);
  let type: ShieldEvent["type"] | undefined;
  if (typeIdx >= 0) {
    const raw = args[typeIdx + 1] ?? "";
    if (!(EVENT_TYPES as readonly string[]).includes(raw)) {
      console.error(`--type must be one of: ${EVENT_TYPES.join(", ")}`);
      process.exit(2);
    }
    type = raw as ShieldEvent["type"];
  }
  const source = sourceIdx >= 0 ? args[sourceIdx + 1] : undefined;

  const events = await readEvents({ limit, type, source });

  if (events.length === 0) {
    console.log(`${DIM}No events found.${RESET}`);
    process.exit(0);
  }

  for (const ev of events) {
    const ts = new Date(ev.timestamp).toLocaleString();
    const score = ev.score !== undefined ? `score=${colorScore(ev.score)} ` : "";
    const patterns = ev.patterns?.length ? `[${ev.patterns.join(",")}] ` : "";
    // detail/source echo attacker-controlled text — never print raw control chars
    console.log(`${DIM}${ts}${RESET} ${typeLabel(ev.type)} ${CYAN}${sanitizeForTerminal(ev.source)}${RESET} ${score}${patterns}`);
    if (ev.detail) console.log(`  ${DIM}${sanitizeForTerminal(ev.detail).slice(0, 120)}${RESET}`);
  }

  process.exit(0);
}

if (cmd === "status") {
  const events = await readEvents({});
  const apps = summarizeStatus(events);

  if (apps.length === 0) {
    console.log(`${DIM}No events logged yet. Apps announce themselves on startup once they use`);
    console.log(`shield v1.1+ client wrappers (or call announceShield/announce_shield).${RESET}`);
    process.exit(0);
  }

  console.log(`${BOLD}shield status${RESET} ${DIM}(library v${SHIELD_VERSION}, log: ${LOG_FILE})${RESET}\n`);

  const STALE_MS = 7 * 24 * 60 * 60 * 1000;
  let warnings = 0;

  for (const app of apps) {
    const bits: string[] = [];
    bits.push(app.version ? `v${app.version}` : `${DIM}version unknown${RESET}`);
    bits.push(app.lastStarted
      ? `last start ${new Date(app.lastStarted).toLocaleString()}`
      : `${DIM}no heartbeat ever${RESET}`);
    bits.push(`7d: ${app.injections7d} injections, ${app.stripped7d} stripped, ` +
      (app.leaks7d > 0 ? `${RED}${app.leaks7d} canary leaks${RESET}` : `0 leaks`) +
      (app.outputFlagged7d > 0 ? `, ${RED}${app.outputFlagged7d} output flags${RESET}` : "") +
      (app.toolGated7d > 0 ? `, ${RED}${app.toolGated7d} tool calls gated${RESET}` : "") +
      (app.headless7d > 0 ? `, ${YELLOW}${app.headless7d} headless${RESET}` : ""));
    console.log(`  ${CYAN}${app.app}${RESET}  ${bits.join(`  ${DIM}·${RESET}  `)}`);

    if (app.version && app.version !== SHIELD_VERSION) {
      console.log(`    ${YELLOW}⚠ running v${app.version}, repo is at v${SHIELD_VERSION} — rebuild/reinstall this app${RESET}`);
      warnings++;
    }
    if (!app.lastStarted) {
      console.log(`    ${YELLOW}⚠ never announced — pre-v1.1 shield, or the integration isn't loading${RESET}`);
      warnings++;
    } else if (Date.now() - new Date(app.lastStarted).getTime() > STALE_MS) {
      console.log(`    ${DIM}quiet: no heartbeat in over 7 days (app not run, or shield stopped loading)${RESET}`);
    }
    if (app.leaks7d > 0) {
      console.log(`    ${RED}⚠ canary leaked in the last 7 days — inspect: shield logs --type canary_leaked --source ${app.app}${RESET}`);
      warnings++;
    }
    if (app.outputFlagged7d > 0) {
      console.log(`    ${RED}⚠ model output flagged (secrets/PII/exfil/echo) — inspect: shield logs --type output_flagged --source ${app.app}${RESET}`);
      warnings++;
    }
    if (app.toolGated7d > 0) {
      console.log(`    ${RED}⚠ tool calls flagged/blocked by policy — inspect: shield logs --type tool_call_gated --source ${app.app}${RESET}`);
      warnings++;
    }
  }

  console.log(warnings === 0
    ? `\n${GREEN}All quiet.${RESET}`
    : `\n${YELLOW}${warnings} warning(s) above.${RESET}`);
  process.exit(warnings === 0 ? 0 : 1);
}

if (cmd === "headless") {
  const watch = args.includes("--watch");
  const notify = args.includes("--notify");
  const intervalSec = intFlag("--interval", 15, 2);

  // Detections must land in the shared log — and the one-shot path exits
  // right after scanning, so wait for the sink to be ready first.
  await initFileLogger();

  const seenPids = new Set<number>();

  const sendNotification = async (fresh: Array<{ pid: number; labels: string[] }>) => {
    if (!notify || fresh.length === 0 || process.platform !== "darwin") return;
    const first = fresh[0]!;
    const msg = fresh.length === 1
      ? `pid=${first.pid} [${first.labels.join(",")}]`
      : `${fresh.length} new processes, e.g. pid=${first.pid} [${first.labels.join(",")}]`;
    const clean = msg.replace(/["\\]/g, ""); // keep osascript string literal safe
    const { execFile } = await import("child_process");
    execFile("osascript", [
      "-e",
      `display notification "${clean} — details: shield logs" with title "shield" subtitle "browser automation detected" sound name "Sosumi"`,
    ], () => { /* notification failure is never fatal */ });
  };

  const printProc = (p: { pid: number; ppid: number; command: string; labels: string[] }) => {
    // command lines come from `ps` — any process can name itself with escape codes
    console.log(
      `${DIM}${new Date().toLocaleTimeString()}${RESET} ${YELLOW}👻${RESET} pid=${p.pid} ` +
      `${YELLOW}[${p.labels.join(",")}]${RESET} ${sanitizeForTerminal(p.command).slice(0, 140)}`,
    );
  };

  const scanOnce = async (): Promise<number> => {
    const procs = await scanHeadlessProcesses();
    const fresh = procs.filter((p) => !seenPids.has(p.pid));
    for (const p of fresh) {
      seenPids.add(p.pid);
      reportHeadless(p);
      printProc(p);
    }
    void sendNotification(fresh);
    return fresh.length;
  };

  const first = await scanOnce();
  if (!watch) {
    if (first === 0) {
      console.log(`${GREEN}No browser automation running.${RESET}`);
      process.exit(0);
    }
    console.log(`\n${YELLOW}${first} automation process(es) found${RESET} ${DIM}(logged as headless_detected — see 'shield logs')${RESET}`);
    process.exit(1);
  }

  console.log(`${DIM}watching for browser automation every ${intervalSec}s — Ctrl-C to stop${RESET}`);
  setInterval(() => {
    void scanOnce();
  }, intervalSec * 1000);
  // Keep the process alive and stop execution falling through to the
  // unknown-command handler below.
  await new Promise(() => {});
}

if (cmd === "scan") {
  const text = args.slice(1).join(" ");
  if (!text) {
    console.error("Usage: shield scan <text to scan>");
    process.exit(1);
  }
  const result = detectInjection(text);
  const flag = result.flagged ? `${RED}FLAGGED${RESET}` : `${GREEN}CLEAN${RESET}`;
  console.log(`${flag} score=${colorScore(result.score)}`);
  if (result.matches.length) {
    console.log(`Patterns: ${result.matches.join(", ")}`);
  }
  process.exit(result.flagged ? 1 : 0);
}

if (cmd === "clear") {
  if (LOG_FILE && existsSync(LOG_FILE)) {
    writeFileSync(LOG_FILE, "", { encoding: "utf8", mode: 0o600 });
    console.log(`${GREEN}Event log cleared.${RESET}`);
  } else {
    console.log(`${DIM}Nothing to clear.${RESET}`);
  }
  process.exit(0);
}

console.error(`Unknown command: ${cmd}. Run 'shield help' for usage.`);
process.exit(1);
