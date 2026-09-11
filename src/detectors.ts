/**
 * Pluggable detectors — the slot for anything the regex layer can't do.
 *
 * The pattern layer is a tripwire: it catches known phrasings and misses
 * paraphrase, translation and novel framings. This is where an app adds a
 * local classifier, an embedding-similarity check, a blocklist of its own
 * terms, or an LLM-judge call.
 *
 * Sync vs async, and why the distinction is load-bearing:
 *
 *   - **Sync detectors run everywhere**, including inside the SDK wrappers,
 *     and their findings are merged into the returned scan. A local
 *     classifier or a term list belongs here.
 *   - **Async detectors** (an LLM-judge round trip) run when you call
 *     `scanInputAsync` / `scanOutputAsync`, and — on the OUTPUT side only —
 *     are fired off by the wrappers, arriving later as their own event.
 *     Output scanning never gates anything, so a late answer is still
 *     useful. INPUT scanning feeds the tool-call decision, so a late answer
 *     there would be unsound: the sync path skips async input detectors and
 *     says so, rather than quietly deciding without them.
 *
 * A detector that throws or hangs must never take the scan with it: every
 * call is isolated, and a rejected promise is reported, not propagated.
 */

import type { InjectionScan } from "./shield.js";
import type { OutputScan } from "./output.js";

export type DetectorSide = "input" | "output";

export interface DetectorFinding {
  /** Short label, namespaced by the runner as `detector:<name>:<label>`. */
  label: string;
  /** 0–1 severity, combined with the pattern layer the same way weights are. */
  weight: number;
  /** Optional context for triage. Mask anything sensitive yourself. */
  excerpt?: string;
  /** Optional 0-based offset into the scanned text. */
  index?: number;
}

export interface DetectorContext {
  side: DetectorSide;
  /** App label of the Shield instance that invoked the detector. */
  app: string;
  /** Channel qualifier for input scans ("tool_result", "document", …). */
  channel?: string;
  /** What the pattern layer already found, so a detector can skip work or
   *  corroborate rather than duplicate. */
  baseline?: InjectionScan | OutputScan;
}

export interface Detector {
  /** Stable identifier; appears in every finding label and error message. */
  name: string;
  /** Sides this detector runs on. Defaults to both. */
  sides?: readonly DetectorSide[];
  scan(text: string, ctx: DetectorContext): DetectorFinding[] | Promise<DetectorFinding[]>;
}

export interface DetectorRun {
  /** Findings from detectors that answered synchronously. */
  findings: DetectorFinding[];
  /** Names of async detectors the sync path did not wait for. */
  deferred: string[];
  /** Resolves to the deferred detectors' findings; null when there are none. */
  pending: Promise<DetectorFinding[]> | null;
}

function appliesTo(d: Detector, side: DetectorSide): boolean {
  return !d.sides || d.sides.includes(side);
}

/** `detector:<name>:<label>`, so a finding's origin survives into the log. */
export function qualify(detector: Detector, finding: DetectorFinding): DetectorFinding {
  return { ...finding, label: `detector:${detector.name}:${finding.label}` };
}

function normalize(detector: Detector, raw: unknown): DetectorFinding[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((f): f is DetectorFinding => !!f && typeof f.label === "string")
    .map((f) => qualify(detector, { ...f, weight: Math.max(0, Math.min(1, Number(f.weight) || 0)) }));
}

function report(detector: Detector, err: unknown): void {
  // Deliberately console, not the event bus: a detector failing while the bus
  // is mid-dispatch would re-enter it.
  console.error(`[shield] detector "${detector.name}" threw; continuing without it:`, err);
}

/**
 * Run detectors without awaiting. Sync results come back immediately; async
 * ones are named in `deferred` and collected in `pending` for callers that
 * can use a late answer.
 */
export function runDetectors(
  detectors: readonly Detector[],
  text: string,
  ctx: DetectorContext,
): DetectorRun {
  const findings: DetectorFinding[] = [];
  const deferred: string[] = [];
  const promises: Array<Promise<DetectorFinding[]>> = [];

  for (const d of detectors) {
    if (!appliesTo(d, ctx.side)) continue;
    try {
      const out = d.scan(text, ctx);
      if (out && typeof (out as Promise<DetectorFinding[]>).then === "function") {
        deferred.push(d.name);
        promises.push(
          (out as Promise<DetectorFinding[]>).then(
            (r) => normalize(d, r),
            (err) => { report(d, err); return []; },
          ),
        );
      } else {
        findings.push(...normalize(d, out));
      }
    } catch (err) {
      report(d, err);
    }
  }

  return {
    findings,
    deferred,
    pending: promises.length === 0 ? null : Promise.all(promises).then((r) => r.flat()),
  };
}

/** Run every applicable detector to completion. */
export async function runDetectorsAsync(
  detectors: readonly Detector[],
  text: string,
  ctx: DetectorContext,
): Promise<DetectorFinding[]> {
  const run = runDetectors(detectors, text, ctx);
  const late = run.pending ? await run.pending : [];
  return [...run.findings, ...late];
}

/**
 * Combine a pattern-layer score with detector findings the same way
 * detectInjection combines its own patterns: highest weight wins, each
 * additional signal adds a little.
 */
export function combineScore(baseScore: number, baseCount: number, findings: readonly DetectorFinding[]): number {
  if (findings.length === 0) return baseScore;
  const max = findings.reduce((a, f) => Math.max(a, f.weight), 0);
  const total = baseCount + findings.length;
  return Math.min(1, Math.max(baseScore, max) + Math.max(0, total - 1) * 0.05);
}
