/**
 * File-based event logger — persists ShieldEvents to a JSONL file
 * (default `~/.shield/events.jsonl`) so the `shield logs` CLI can read across
 * all apps.
 *
 * Node-only. In a browser (or any runtime without `process`), every function
 * here is a silent no-op — the module must stay importable there because the
 * package entrypoint re-exports readEvents / summarizeStatus / sanitizeForTerminal.
 *
 * Writes are synchronous once the fs module is resolved, and the module is
 * resolved synchronously on Node ≥ 20.16 (`process.getBuiltinModule`). That
 * matters: the previous implementation awaited a dynamic `import("fs")` per
 * event, so a process that emitted and then exited synchronously — the CLI's
 * own `shield headless` one-shot did exactly this — wrote nothing at all.
 */

import { onShieldEvent, type ShieldEvent } from "./shield.js";

type FsModule = typeof import("fs");

const IS_NODE = typeof process !== "undefined" && !!process.versions?.node;

// Synchronous builtin access where available (Node ≥ 20.16 / 22.3), so the
// first event can be written before the process has a chance to exit.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function builtin<T>(name: string): T | null {
  if (!IS_NODE) return null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const get = (process as any).getBuiltinModule as ((id: string) => unknown) | undefined;
  if (typeof get !== "function") return null;
  try { return get(`node:${name}`) as T; } catch { return null; }
}

/**
 * Resolve the log directory:
 *   1. `SHIELD_LOG_DIR` (any app that can't or shouldn't write to the home
 *      dir — containers, serverless, CI — points this somewhere writable)
 *   2. `os.homedir()` (honors HOME, USERPROFILE on Windows, and passwd as a
 *      last resort — the old `HOME ?? "~"` produced a literal `./~/.shield`
 *      when HOME was unset)
 * Returns null when neither is available; file logging is then disabled.
 */
function resolveLogDir(): string | null {
  if (!IS_NODE) return null;
  const env = process.env["SHIELD_LOG_DIR"];
  if (env) return env;
  const os = builtin<typeof import("os")>("os");
  let home: string | undefined;
  try { home = os?.homedir(); } catch { /* fall through */ }
  home = home || process.env["HOME"] || process.env["USERPROFILE"];
  return home ? `${home}/.shield` : null;
}

const LOG_DIR: string | null = resolveLogDir();
/** Path of the shared event log, or "" when file logging is unavailable. */
const LOG_FILE: string = LOG_DIR ? `${LOG_DIR}/events.jsonl` : "";

let fsModule: FsModule | null = builtin<FsModule>("fs");
let fsPromise: Promise<FsModule | null> | null = null;

function getFs(): Promise<FsModule | null> {
  if (fsModule) return Promise.resolve(fsModule);
  if (!IS_NODE) return Promise.resolve(null);
  if (!fsPromise) {
    fsPromise = import("fs").then((m) => (fsModule = m)).catch(() => null);
  }
  return fsPromise;
}

function ensureLogDir(fs: FsModule): boolean {
  if (!LOG_DIR) return false;
  try {
    // The log stores snippets of user messages and transcripts — owner-only.
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true, mode: 0o700 });
    return true;
  } catch {
    return false;
  }
}

/** Best-effort tighten of perms on a log dir/file created by older versions. */
function tightenPermissions(fs: FsModule): void {
  try {
    if (LOG_DIR && fs.existsSync(LOG_DIR)) fs.chmodSync(LOG_DIR, 0o700);
    if (LOG_FILE && fs.existsSync(LOG_FILE)) fs.chmodSync(LOG_FILE, 0o600);
  } catch {
    // Never throw from a logging side-effect
  }
}

function writeEvent(fs: FsModule, event: ShieldEvent): void {
  try {
    if (!ensureLogDir(fs)) return;
    fs.appendFileSync(LOG_FILE, JSON.stringify(event) + "\n", { encoding: "utf8", mode: 0o600 });
  } catch {
    // Never throw from a logging side-effect
  }
}

let initialized = false;
let ready: Promise<void> = Promise.resolve();
// Events that arrived before fs resolved (only on runtimes without
// getBuiltinModule). Flushed in order once it does.
const pending: ShieldEvent[] = [];

/**
 * Wire shield events → the JSONL log. Safe to call multiple times (no-ops
 * after the first). Events emitted before this call are replayed from the
 * bus's recent-event buffer, so calling it after constructing a client
 * wrapper no longer loses the `shield_started` heartbeat.
 *
 * Returns a promise that resolves once the file sink is fully operational;
 * short-lived scripts should `await` it before `process.exit()`. On Node ≥
 * 20.16 the sink is synchronous from the first call and the promise is
 * already resolved.
 */
export function initFileLogger(): Promise<void> {
  if (initialized) return ready;
  initialized = true;
  if (!IS_NODE || !LOG_FILE) return ready;

  const sink = (ev: ShieldEvent) => {
    if (fsModule) writeEvent(fsModule, ev);
    else pending.push(ev);
  };

  if (fsModule) {
    tightenPermissions(fsModule); // fix up dirs/files created before v1.3.0
    onShieldEvent(sink, { replay: true });
    return ready;
  }

  onShieldEvent(sink, { replay: true });
  ready = getFs().then((fs) => {
    if (!fs) { pending.length = 0; return; }
    tightenPermissions(fs);
    for (const ev of pending.splice(0)) writeEvent(fs, ev);
  });
  return ready;
}

/**
 * Strip terminal control characters from attacker-controlled text before
 * printing it. Event `detail` holds raw snippets of flagged content (and
 * process command lines) — without this, a malicious page/transcript could
 * embed ANSI/OSC escape sequences that rewrite or hide what `shield logs`
 * shows on screen. Newlines/tabs become spaces so one event stays one line.
 * Bidi overrides go too: U+202E can visually reverse the rest of a log line.
 */
export function sanitizeForTerminal(text: string): string {
  return text
    .replace(/[\n\t]/g, " ")
    // C0 controls (incl. ESC and \r), DEL, and C1 controls (incl. CSI/OSC 0x9B/0x9D)
    .replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g, "")
    // Bidi embedding/override/isolate controls
    .replace(/[\u202A-\u202E\u2066-\u2069]/g, "");
}

export interface ReadEventsOptions {
  limit?: number;
  type?: ShieldEvent["type"];
  since?: Date;
  source?: string;
}

/** Read events from the log file, newest-last. Malformed lines are skipped. */
export async function readEvents(opts: ReadEventsOptions = {}): Promise<ShieldEvent[]> {
  const fs = await getFs();
  if (!fs || !LOG_FILE) return [];
  try {
    if (!fs.existsSync(LOG_FILE)) return [];
    const lines = fs.readFileSync(LOG_FILE, "utf8").split("\n");
    let events: ShieldEvent[] = [];
    for (const line of lines) {
      if (!line.trim()) continue;
      // One truncated line (crash mid-write, concurrent appenders) used to make
      // the whole log unreadable — `shield status` then said "no events".
      try {
        const ev = JSON.parse(line) as ShieldEvent;
        if (ev && typeof ev === "object" && typeof ev.type === "string") events.push(ev);
      } catch {
        // skip
      }
    }

    if (opts.type) events = events.filter((e) => e.type === opts.type);
    if (opts.source) events = events.filter((e) => String(e.source ?? "").includes(opts.source!));
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

function epoch(ts: string | null | undefined): number {
  const t = ts ? Date.parse(ts) : NaN;
  return Number.isNaN(t) ? -Infinity : t;
}

/**
 * Aggregate the shared event log into a per-app health view for `shield status`.
 * Pure — pass `now` for deterministic tests. Timestamps are compared as
 * instants, not strings: Python writes `+00:00` with microseconds and TS
 * writes `Z` with milliseconds, and those don't sort lexically.
 */
export function summarizeStatus(events: ShieldEvent[], now: Date = new Date()): AppStatus[] {
  const weekAgo = now.getTime() - 7 * 24 * 60 * 60 * 1000;
  const byApp = new Map<string, AppStatus>();

  for (const ev of events) {
    const source = String(ev.source ?? "");
    const app = source.split(":")[0] || source;
    let s = byApp.get(app);
    if (!s) {
      s = { app, version: null, lastStarted: null, lastEventAt: null, injections7d: 0, leaks7d: 0, stripped7d: 0, headless7d: 0 };
      byApp.set(app, s);
    }

    if (epoch(ev.timestamp) > epoch(s.lastEventAt)) s.lastEventAt = ev.timestamp;

    if (ev.type === "shield_started") {
      if (epoch(ev.timestamp) > epoch(s.lastStarted)) {
        s.lastStarted = ev.timestamp;
        s.version = String(ev.detail ?? "").match(/^v(.+)$/)?.[1] ?? null;
      }
      continue;
    }

    if (epoch(ev.timestamp) >= weekAgo) {
      if (ev.type === "injection_detected") s.injections7d++;
      else if (ev.type === "canary_leaked") s.leaks7d++;
      else if (ev.type === "trigger_stripped") s.stripped7d++;
      else if (ev.type === "headless_detected") s.headless7d++;
    }
  }

  return [...byApp.values()].sort((a, b) => a.app.localeCompare(b.app));
}

export { LOG_FILE };
