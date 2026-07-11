/**
 * File-based event logger — persists ShieldEvents to ~/.shield/events.jsonl
 * so the `shield logs` CLI can read across all apps.
 *
 * Falls back silently if the home dir is unwritable (e.g. in browser contexts).
 */

import { onShieldEvent, type ShieldEvent } from "./shield.js";

const LOG_DIR = `${process.env.HOME ?? "~"}/.shield`;
const LOG_FILE = `${LOG_DIR}/events.jsonl`;

let initialized = false;
let fsModule: typeof import("fs") | null = null;

async function getFs(): Promise<typeof import("fs") | null> {
  if (fsModule !== null) return fsModule;
  try {
    fsModule = await import("fs");
    return fsModule;
  } catch {
    return null;
  }
}

async function ensureLogDir(): Promise<boolean> {
  const fs = await getFs();
  if (!fs) return false;
  try {
    // The log stores snippets of user messages and transcripts — owner-only.
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true, mode: 0o700 });
    return true;
  } catch {
    return false;
  }
}

/** Best-effort tighten of perms on a log dir/file created by older versions. */
async function tightenPermissions(): Promise<void> {
  const fs = await getFs();
  if (!fs) return;
  try {
    if (fs.existsSync(LOG_DIR)) fs.chmodSync(LOG_DIR, 0o700);
    if (fs.existsSync(LOG_FILE)) fs.chmodSync(LOG_FILE, 0o600);
  } catch {
    // Never throw from a logging side-effect
  }
}

async function appendEvent(event: ShieldEvent): Promise<void> {
  const fs = await getFs();
  if (!fs) return;
  try {
    if (!(await ensureLogDir())) return;
    fs.appendFileSync(LOG_FILE, JSON.stringify(event) + "\n", { encoding: "utf8", mode: 0o600 });
  } catch {
    // Never throw from a logging side-effect
  }
}

/**
 * Call once at app startup to wire shield events → ~/.shield/events.jsonl.
 * Safe to call multiple times (no-ops after first call).
 */
export function initFileLogger(): void {
  if (initialized) return;
  initialized = true;
  void tightenPermissions(); // fix up dirs/files created before v1.3.0
  onShieldEvent((ev) => void appendEvent(ev));
}

/**
 * Strip terminal control characters from attacker-controlled text before
 * printing it. Event `detail` holds raw snippets of flagged content (and
 * process command lines) — without this, a malicious page/transcript could
 * embed ANSI/OSC escape sequences that rewrite or hide what `shield logs`
 * shows on screen. Newlines/tabs become spaces so one event stays one line.
 */
export function sanitizeForTerminal(text: string): string {
  return text
    .replace(/[\n\t]/g, " ")
    // C0 controls (incl. ESC and \r), DEL, and C1 controls (incl. CSI/OSC 0x9B/0x9D)
    .replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g, "");
}

export interface ReadEventsOptions {
  limit?: number;
  type?: ShieldEvent["type"];
  since?: Date;
  source?: string;
}

/** Read events from the log file, newest-last. */
export async function readEvents(opts: ReadEventsOptions = {}): Promise<ShieldEvent[]> {
  const fs = await getFs();
  if (!fs) return [];
  try {
    if (!fs.existsSync(LOG_FILE)) return [];
    const lines = fs.readFileSync(LOG_FILE, "utf8").trim().split("\n").filter(Boolean);
    let events: ShieldEvent[] = lines.map((l) => JSON.parse(l) as ShieldEvent);

    if (opts.type) events = events.filter((e) => e.type === opts.type);
    if (opts.source) events = events.filter((e) => e.source.includes(opts.source!));
    if (opts.since) events = events.filter((e) => new Date(e.timestamp) >= opts.since!);
    if (opts.limit) events = events.slice(-opts.limit);

    return events;
  } catch {
    return [];
  }
}

// ── STATUS ───────────────────────────────────────────────────────────────────

export interface AppStatus {
  /** App name — the part of the event source before any ":" qualifier. */
  app: string;
  /** Shield version from the app's most recent shield_started heartbeat. */
  version: string | null;
  /** Timestamp of the most recent shield_started heartbeat. */
  lastStarted: string | null;
  /** Timestamp of the most recent event of any type. */
  lastEventAt: string | null;
  injections7d: number;
  leaks7d: number;
  stripped7d: number;
  headless7d: number;
}

/**
 * Aggregate the shared event log into a per-app health view for `shield status`.
 * Pure — pass `now` for deterministic tests.
 */
export function summarizeStatus(events: ShieldEvent[], now: Date = new Date()): AppStatus[] {
  const weekAgo = now.getTime() - 7 * 24 * 60 * 60 * 1000;
  const byApp = new Map<string, AppStatus>();

  for (const ev of events) {
    const app = ev.source.split(":")[0] ?? ev.source;
    let s = byApp.get(app);
    if (!s) {
      s = { app, version: null, lastStarted: null, lastEventAt: null, injections7d: 0, leaks7d: 0, stripped7d: 0, headless7d: 0 };
      byApp.set(app, s);
    }

    if (!s.lastEventAt || ev.timestamp > s.lastEventAt) s.lastEventAt = ev.timestamp;

    if (ev.type === "shield_started") {
      if (!s.lastStarted || ev.timestamp > s.lastStarted) {
        s.lastStarted = ev.timestamp;
        s.version = ev.detail.match(/^v(.+)$/)?.[1] ?? null;
      }
      continue;
    }

    if (new Date(ev.timestamp).getTime() >= weekAgo) {
      if (ev.type === "injection_detected") s.injections7d++;
      else if (ev.type === "canary_leaked") s.leaks7d++;
      else if (ev.type === "trigger_stripped") s.stripped7d++;
      else if (ev.type === "headless_detected") s.headless7d++;
    }
  }

  return [...byApp.values()].sort((a, b) => a.app.localeCompare(b.app));
}

export { LOG_FILE };
