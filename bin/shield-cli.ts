#!/usr/bin/env node
/**
 * shield CLI — inspect injection events and test detection
 *
 * Commands:
 *   shield logs [--limit N] [--type TYPE] [--source SRC]   print recent events
 *   shield scan <text>                                       scan text for injections
 *   shield clear                                             wipe the event log
 */

import { readEvents, LOG_FILE } from "../src/logger.js";
import { detectInjection } from "../src/shield.js";
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
    default:                   return t;
  }
}

const args = process.argv.slice(2);
const cmd = args[0];

if (!cmd || cmd === "help" || cmd === "--help") {
  console.log(`
${BOLD}shield${RESET} — prompt injection defense CLI

${BOLD}COMMANDS${RESET}
  ${CYAN}shield logs${RESET}                     Show recent injection events
    ${DIM}--limit N${RESET}                      Show last N events (default 50)
    ${DIM}--type TYPE${RESET}                    Filter: injection_detected | canary_leaked | trigger_stripped
    ${DIM}--source SRC${RESET}                   Filter by source substring

  ${CYAN}shield scan <text>${RESET}              Scan text for injection patterns
  ${CYAN}shield clear${RESET}                    Wipe the event log

${BOLD}LOG FILE${RESET}
  ${DIM}${LOG_FILE}${RESET}
`);
  process.exit(0);
}

if (cmd === "logs") {
  const limitIdx = args.indexOf("--limit");
  const typeIdx = args.indexOf("--type");
  const sourceIdx = args.indexOf("--source");

  const limit = limitIdx >= 0 ? Number(args[limitIdx + 1] || 50) : 50;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const type = typeIdx >= 0 ? (args[typeIdx + 1] as any) as import("../src/shield.js").ShieldEvent["type"] : undefined;
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
    console.log(`${DIM}${ts}${RESET} ${typeLabel(ev.type)} ${CYAN}${ev.source}${RESET} ${score}${patterns}`);
    if (ev.detail) console.log(`  ${DIM}${ev.detail.slice(0, 120)}${RESET}`);
  }

  process.exit(0);
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
  if (existsSync(LOG_FILE)) {
    writeFileSync(LOG_FILE, "", "utf8");
    console.log(`${GREEN}Event log cleared.${RESET}`);
  } else {
    console.log(`${DIM}Nothing to clear.${RESET}`);
  }
  process.exit(0);
}

console.error(`Unknown command: ${cmd}. Run 'shield help' for usage.`);
process.exit(1);
