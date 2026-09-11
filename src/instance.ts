/**
 * createShield(config) — an instance with its own configuration, sinks and
 * event buffer.
 *
 * Everything in shield.ts is module-level: one bus, one salt, one announced
 * set. That is fine for a single app on a laptop and wrong for a library:
 * two tenants in one process, a test that needs a clean slate, an app that
 * ships events to a webhook instead of a home-directory file. A Shield
 * instance owns:
 *
 *   - its app label, thresholds, canary, output/tool policy, registered secrets
 *   - its own subscribers and recent-event buffer
 *   - the decision whether to forward events to the global bus (default yes,
 *     so `shield logs` / `shield status` keep working) and whether to attach
 *     the JSONL file sink under Node (default yes)
 *
 * The module-level functions keep working unchanged; `getDefaultShield()`
 * is the instance they are equivalent to.
 */

import {
  SHIELD_VERSION,
  announceShield,
  detectInjection,
  emitShieldEvent,
  hardenSystemPrompt,
  outputLeakedCanary,
  scanDetail,
  wrapUntrusted,
  type HardenResult,
  type InjectionScan,
  type ShieldEvent,
  type SubscribeOptions,
} from "./shield.js";
import {
  evaluateToolCall,
  outputDetail,
  scanOutput,
  type OutputCategory,
  type OutputScan,
  type OutputScanContext,
  type ToolCall,
  type ToolCallContext,
  type ToolDecision,
  type ToolPolicy,
} from "./output.js";
import { initFileLogger } from "./logger.js";

export type Sink = (event: ShieldEvent) => void;

export interface OutputConfig {
  /** Hosts the model may legitimately reference in URLs. */
  allowedHosts?: string[];
  /** Per-category on/off (all on by default). */
  detectors?: Partial<Record<OutputCategory, boolean>>;
  /** Flag threshold for output scans (default 0.5). */
  threshold?: number;
}

export interface ShieldConfig {
  /** App label used as the event source. */
  app?: string;
  /** Input-scan flag threshold (default 0.5). */
  threshold?: number;
  /** Pin the canary token (see README: prompt caching across workers). */
  canary?: string;
  /** What to keep in `detail`: the triage excerpt (default), a 32-bit hash of
   *  it, or nothing. Excerpts contain snippets of user content. */
  redact?: "excerpt" | "hash" | "none";
  /** Values the model must never emit. Never logged. */
  secrets?: string[];
  output?: OutputConfig;
  toolPolicy?: ToolPolicy;
  /** Extra event sinks (console, webhook, OpenTelemetry…). */
  sinks?: Sink[];
  /** Also emit on the module-level bus (default true) so `shield logs` and
   *  existing onShieldEvent subscribers see this instance's events. */
  forwardToGlobal?: boolean;
  /** Attach the JSONL file sink under Node (default true). */
  fileLogger?: boolean;
  /** Print the startup banner (default true; SHIELD_QUIET=1 also silences). */
  banner?: boolean;
}

export interface ScanInputOptions {
  /** Channel qualifier appended to the source: "tool_result", "document"… */
  channel?: string;
  /** Override the instance threshold for this call. */
  threshold?: number;
}

function hash32hex(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
  return h.toString(16).padStart(8, "0");
}

export class Shield {
  readonly config: Readonly<ShieldConfig>;
  readonly app: string;
  private readonly handlers: Sink[] = [];
  private readonly recent: ShieldEvent[] = [];
  private static readonly RECENT_MAX = 256;

  constructor(config: ShieldConfig = {}) {
    this.config = Object.freeze({ ...config });
    this.app = config.app ?? "shield";
    for (const s of config.sinks ?? []) this.handlers.push(s);
    if (config.fileLogger !== false) void initFileLogger();
    announceShield({ appLabel: this.app, banner: config.banner });
  }

  get version(): string {
    return SHIELD_VERSION;
  }

  // ── events ────────────────────────────────────────────────────────────────

  /** Subscribe to this instance's events. Returns an unsubscribe function. */
  on(handler: Sink, opts: SubscribeOptions = {}): () => void {
    if (opts.replay) for (const ev of [...this.recent]) { try { handler(ev); } catch (err) { console.error("[shield] sink threw during replay; continuing:", err); } }
    this.handlers.push(handler);
    return () => { const i = this.handlers.indexOf(handler); if (i >= 0) this.handlers.splice(i, 1); };
  }

  /** Events this instance has emitted (most recent 256). */
  get events(): readonly ShieldEvent[] {
    return this.recent;
  }

  emit(event: Omit<ShieldEvent, "timestamp">): ShieldEvent {
    const full: ShieldEvent = { ...event, detail: this.redact(event.detail), timestamp: new Date().toISOString() };
    this.recent.push(full);
    if (this.recent.length > Shield.RECENT_MAX) this.recent.splice(0, this.recent.length - Shield.RECENT_MAX);
    for (const h of [...this.handlers]) {
      try { h(full); } catch (err) { console.error("[shield] sink threw; continuing:", err); }
    }
    if (this.config.forwardToGlobal !== false) {
      const { timestamp: _t, ...rest } = full;
      void _t;
      emitShieldEvent(rest);
    }
    return full;
  }

  private redact(detail: string): string {
    switch (this.config.redact) {
      case "hash": return detail ? `sha:${hash32hex(detail)}` : "";
      case "none": return "";
      default: return detail;
    }
  }

  private source(channel?: string): string {
    return channel ? `${this.app}:${channel}` : this.app;
  }

  // ── input side ────────────────────────────────────────────────────────────

  /** Scan untrusted text; emits `injection_detected` when flagged. */
  scanInput(text: string, opts: ScanInputOptions = {}): InjectionScan {
    const scan = detectInjection(text, opts.threshold ?? this.config.threshold ?? 0.5);
    if (scan.flagged) {
      this.emit({
        type: "injection_detected",
        source: this.source(opts.channel),
        detail: scanDetail(text, scan),
        score: scan.score,
        patterns: scan.matches,
        direction: "input",
      });
    }
    return scan;
  }

  wrap(content: string, label: string): string {
    return wrapUntrusted(content, label);
  }

  harden(base: string): HardenResult {
    return hardenSystemPrompt(base, this.config.canary);
  }

  // ── output side ───────────────────────────────────────────────────────────

  /**
   * Scan model output for leaked secrets, PII, exfiltration channels, echoed
   * injections and the canary. Emits `canary_leaked` for a canary hit (kept
   * separate so `shield status` counts it as before) and `output_flagged`
   * for everything else.
   */
  scanOutput(text: string, ctx: OutputScanContext = {}): OutputScan {
    const merged: OutputScanContext = {
      allowedHosts: this.config.output?.allowedHosts,
      detectors: this.config.output?.detectors,
      threshold: this.config.output?.threshold,
      secrets: this.config.secrets,
      ...ctx,
    };
    const scan = scanOutput(text, merged);
    if (merged.canary && outputLeakedCanary(text, merged.canary)) {
      this.emit({ type: "canary_leaked", source: this.app, detail: text.slice(0, 200), direction: "output" });
      console.warn(`[shield] Canary leak detected in response from ${this.app}`);
    }
    const rest = scan.findings.filter((f) => f.category !== "canary");
    if (rest.length > 0 && scan.flagged) {
      this.emit({
        type: "output_flagged",
        source: this.app,
        detail: outputDetail({ ...scan, findings: rest }),
        score: scan.score,
        patterns: rest.map((f) => f.label),
        direction: "output",
      });
    }
    return scan;
  }

  /** Evaluate a requested tool call against the policy; emits `tool_call_gated` unless allowed. */
  checkToolCall(call: ToolCall, ctx: ToolCallContext = {}): ToolDecision {
    const d = evaluateToolCall(call, this.config.toolPolicy ?? {}, ctx);
    if (d.decision !== "allow") {
      this.emit({
        type: "tool_call_gated",
        source: this.app,
        detail: `${d.decision}: ${call.name} — ${d.reasons.join("; ")}`.slice(0, 300),
        score: d.decision === "block" ? 1 : 0.6,
        patterns: [`tool:${call.name}`, `decision:${d.decision}`],
        direction: "tool",
      });
    }
    return d;
  }
}

export function createShield(config: ShieldConfig = {}): Shield {
  return new Shield(config);
}

let defaultInstance: Shield | null = null;

/** The instance the module-level API is equivalent to (app "shield", defaults). */
export function getDefaultShield(): Shield {
  if (!defaultInstance) defaultInstance = new Shield({ banner: false });
  return defaultInstance;
}
