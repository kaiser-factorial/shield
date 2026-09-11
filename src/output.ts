/**
 * Output-side pipeline — what the model SAID and what it wants to DO.
 *
 * Before v1.6 the only thing shield inspected in model output was the
 * canary. Real damage in agentic apps happens on the way out: a leaked
 * credential in a reply, an email address the model was tricked into
 * repeating, a markdown image pointing at an attacker's beacon, or a tool
 * call the injected page asked for. This module is the symmetric half of
 * the input scanner:
 *
 *   scanOutput(text, ctx)       → OutputScan   (secrets, PII, exfil URLs, echo, canary)
 *   evaluateToolCall(call, ctx) → ToolDecision (allow / flag / block by policy)
 *
 * Pure and zero-dependency. Every regex is bounded (see shield.ts on ReDoS).
 */

import { detectInjection, outputLeakedCanary, type InjectionScan } from "./shield.js";

// ── findings ─────────────────────────────────────────────────────────────────

export type OutputCategory = "canary" | "secret" | "pii" | "exfil" | "echo" | "refusal" | "custom";

export interface OutputFinding {
  /** e.g. "secret:aws-access-key", "pii:email", "exfil:beacon-url", "echo:ignore-instructions" */
  label: string;
  category: OutputCategory;
  /** 0–1 severity contribution */
  weight: number;
  /** ±60 chars around the match (secrets are masked) */
  excerpt: string;
  /** 0-based char offset in the scanned text */
  index: number;
}

export interface OutputScan {
  score: number;
  flagged: boolean;
  findings: OutputFinding[];
  /** convenience: labels of all findings */
  matches: string[];
}

export interface OutputScanContext {
  /** Canary embedded in this request's system prompt, if any. */
  canary?: string;
  /** Input-side scan(s) for this request: matched excerpts are checked for echo. */
  inputScans?: InjectionScan[];
  /** Hosts the app is allowed to reference in URLs. Others with long/opaque
   *  query strings are reported as exfil beacons. Suffix match ("example.com"
   *  covers "api.example.com"). */
  allowedHosts?: string[];
  /** Detector toggles (all on by default). */
  detectors?: Partial<Record<OutputCategory, boolean>>;
  /** Score at or above which `flagged` is true (default 0.5). */
  threshold?: number;
  /** App-specific values the model must never emit (DB passwords, internal
   *  URLs, account numbers). Compared after stripping punctuation and case;
   *  values under 8 alphanumerics are ignored. Never logged. */
  secrets?: string[];
}

const EXCERPT_RADIUS = 60;

function excerptAt(text: string, index: number, length: number, mask = false): string {
  const start = Math.max(0, index - EXCERPT_RADIUS);
  const end = Math.min(text.length, index + length + EXCERPT_RADIUS);
  let body = text.slice(start, end);
  if (mask) {
    const hit = text.slice(index, index + length);
    const masked = hit.length <= 8 ? "*".repeat(hit.length) : hit.slice(0, 4) + "…" + hit.slice(-2);
    body = body.replace(hit, masked);
  }
  return (start > 0 ? "…" : "") + body.replace(/\s+/g, " ").trim() + (end < text.length ? "…" : "");
}

// ── secrets ──────────────────────────────────────────────────────────────────

interface SecretPattern { label: string; re: RegExp; weight: number }

/**
 * Credential shapes. Anchored on distinctive prefixes so ordinary prose
 * doesn't trip them; the generic "key = value" rule needs an explicit
 * key-ish word right before it.
 */
export const SECRET_PATTERNS: readonly SecretPattern[] = [
  { label: "aws-access-key",      re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/,                              weight: 0.95 },
  { label: "aws-secret-key",      re: /\baws_?secret(?:_access)?_?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b/i, weight: 0.95 },
  { label: "github-token",        re: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b/, weight: 0.95 },
  { label: "openai-key",          re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/,               weight: 0.9 },
  { label: "anthropic-key",       re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,                              weight: 0.95 },
  { label: "slack-token",         re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,                           weight: 0.9 },
  { label: "google-api-key",      re: /\bAIza[0-9A-Za-z_-]{35}\b/,                                  weight: 0.9 },
  { label: "stripe-key",          re: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}\b/,                   weight: 0.9 },
  { label: "private-key-block",   re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/, weight: 1 },
  { label: "jwt",                 re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, weight: 0.8 },
  { label: "bearer-token",        re: /\bBearer\s+[A-Za-z0-9._-]{24,}\b/,                           weight: 0.7 },
  { label: "generic-api-key",     re: /\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)["']?\s*[:=]\s*["']?([A-Za-z0-9/+_.=-]{16,})/i, weight: 0.75 },
  { label: "connection-string",   re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]{1,64}:[^\s@/]{1,128}@/i, weight: 0.9 },
];

// ── PII ──────────────────────────────────────────────────────────────────────

function luhnValid(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

interface PiiPattern { label: string; re: RegExp; weight: number; validate?: (m: RegExpExecArray) => boolean }

export const PII_PATTERNS: readonly PiiPattern[] = [
  { label: "email",        re: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/, weight: 0.5 },
  { label: "phone",        re: /(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/, weight: 0.4 },
  { label: "ssn",          re: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/, weight: 0.8 },
  { label: "credit-card",  re: /\b(?:\d[ -]?){13,19}\b/, weight: 0.85,
    validate: (m) => { const d = m[0].replace(/\D/g, ""); return d.length >= 13 && d.length <= 19 && luhnValid(d); } },
  { label: "iban",         re: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}[ ]?[A-Z0-9]{1,4}\b/, weight: 0.6 },
];

// ── refusal ──────────────────────────────────────────────────────────────────

/**
 * The model declining, or reporting that it was asked to do something it
 * shouldn't. On its own this is ordinary and harmless — models refuse all
 * day — so the weight sits below the flag threshold and it only surfaces in
 * combination. What makes it worth recording is the pairing: a refusal in
 * the same turn that untrusted content was flagged is the shape of a probe
 * that the model caught and the pattern layer only half-saw.
 */
const REFUSAL_PATTERNS: ReadonlyArray<{ label: string; re: RegExp }> = [
  { label: "declined",        re: /\bI\s+(?:can(?:'|’)?t|cannot|am\s+unable\s+to|won(?:'|’)?t|will\s+not)\b[^.!?\n]{0,60}?\b(?:help|assist|comply|do\s+that|provide|share|reveal|continue|follow)\b/i },
  { label: "apologetic",      re: /\bI(?:'|’)?m\s+(?:sorry|afraid)\b[^.!?\n]{0,40}?\b(?:can(?:'|’)?t|cannot|unable|not\s+able)\b/i },
  { label: "must-decline",    re: /\bI\s+(?:must|have\s+to|will)\s+(?:decline|refuse)\b/i },
  { label: "against-policy",  re: /\b(?:that|this|it)\s+(?:would\s+)?(?:violate|goes?\s+against|conflicts?\s+with)\b[^.!?\n]{0,40}?\b(?:polic|guideline|instruction|constraint)/i },
  // The model naming the attack. High-signal on its own terms: it means the
  // content carried instructions and the model noticed.
  { label: "reported-injection", re: /\b(?:this|the)\s+(?:message|text|content|page|document|tool\s+result|input)\b[^.!?\n]{0,60}?\b(?:appears\s+to\s+)?(?:contain|include)s?\b[^.!?\n]{0,40}?\b(?:prompt\s+injection|injected\s+instruction|hidden\s+instruction|embedded\s+instruction)/i },
];

// ── exfiltration ─────────────────────────────────────────────────────────────

const URL_RE = /\b(?:https?:)?\/\/([A-Za-z0-9.-]{1,253})(?::\d{1,5})?(\/[^\s)<>"'\]]{0,2048})?/g;
const MD_IMAGE_RE = /!\[[^\]\n]{0,200}\]\(\s*((?:https?:)?\/\/[^)\s]{1,2048})\s*\)/g;
const HTML_IMG_RE = /<img\b[^>]{0,500}?\bsrc\s*=\s*["']?((?:https?:)?\/\/[^"'\s>]{1,2048})/gi;
const MAILTO_RE = /\bmailto:[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}/gi;

function hostAllowed(host: string, allowed: string[] | undefined): boolean {
  if (!allowed || allowed.length === 0) return false;
  const h = host.toLowerCase();
  return allowed.some((a) => { const x = a.toLowerCase(); return h === x || h.endsWith("." + x); });
}

/** Query strings that look like carried data: long, or base64/hex-ish. */
function opaqueQuery(path: string | undefined): boolean {
  if (!path) return false;
  const q = path.indexOf("?");
  if (q < 0) return false;
  const query = path.slice(q + 1);
  if (query.length >= 48) return true;
  return /[A-Za-z0-9+/=_-]{32,}/.test(query);
}

// ── main scanner ─────────────────────────────────────────────────────────────

const normSecret = (s: string) => s.replace(/[^a-z0-9]/gi, "").toLowerCase();

/**
 * Scan model output. Returns every finding with a masked excerpt; the
 * composite score is the max weight plus a small boost per extra finding,
 * mirroring detectInjection.
 */
export function scanOutput(text: string, ctx: OutputScanContext = {}): OutputScan {
  const findings: OutputFinding[] = [];
  const on = (c: OutputCategory) => ctx.detectors?.[c] !== false;
  const raw = String(text ?? "");
  const scanned = raw.length > 512 * 1024 ? raw.slice(0, 256 * 1024) + "\n…\n" + raw.slice(-256 * 1024) : raw;

  // 1. canary
  if (on("canary") && ctx.canary && outputLeakedCanary(scanned, ctx.canary)) {
    const i = scanned.indexOf(ctx.canary);
    findings.push({ label: "canary:leaked", category: "canary", weight: 1, excerpt: excerptAt(scanned, Math.max(0, i), ctx.canary.length, true), index: Math.max(0, i) });
  }

  // 2. secrets
  if (on("secret")) {
    for (const p of SECRET_PATTERNS) {
      const m = p.re.exec(scanned);
      if (m) findings.push({ label: `secret:${p.label}`, category: "secret", weight: p.weight, excerpt: excerptAt(scanned, m.index, m[0].length, true), index: m.index });
    }
    if (ctx.secrets && ctx.secrets.length > 0) {
      const n = normSecret(scanned);
      for (const raw of ctx.secrets) {
        const s = normSecret(raw);
        if (s.length >= 8 && n.includes(s)) {
          findings.push({ label: "secret:registered", category: "secret", weight: 1, excerpt: "(registered secret — value withheld)", index: -1 });
          break;
        }
      }
    }
  }

  // 3. PII
  if (on("pii")) {
    for (const p of PII_PATTERNS) {
      const re = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g");
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = re.exec(scanned)) && guard++ < 50) {
        if (p.validate && !p.validate(m)) continue;
        findings.push({ label: `pii:${p.label}`, category: "pii", weight: p.weight, excerpt: excerptAt(scanned, m.index, m[0].length, true), index: m.index });
        break; // one finding per PII type is enough for triage
      }
    }
  }

  // 4. exfiltration channels
  if (on("exfil")) {
    const seen = new Set<string>();
    const report = (label: string, weight: number, index: number, length: number) => {
      const key = `${label}@${index}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({ label: `exfil:${label}`, category: "exfil", weight, excerpt: excerptAt(scanned, index, length), index });
    };
    for (const m of scanned.matchAll(MD_IMAGE_RE)) {
      const host = m[1].replace(/^(?:https?:)?\/\//, "").split(/[/?#:]/)[0];
      report(hostAllowed(host, ctx.allowedHosts) ? "markdown-image" : "markdown-image-beacon", hostAllowed(host, ctx.allowedHosts) ? 0.3 : 0.85, m.index, m[0].length);
    }
    for (const m of scanned.matchAll(HTML_IMG_RE)) {
      const host = m[1].replace(/^(?:https?:)?\/\//, "").split(/[/?#:]/)[0];
      if (!hostAllowed(host, ctx.allowedHosts)) report("html-image-beacon", 0.85, m.index, m[0].length);
    }
    for (const m of scanned.matchAll(URL_RE)) {
      const host = m[1];
      if (hostAllowed(host, ctx.allowedHosts)) continue;
      if (opaqueQuery(m[2])) report("beacon-url", 0.8, m.index, m[0].length);
      else if (ctx.allowedHosts && ctx.allowedHosts.length > 0) report("unlisted-host", 0.4, m.index, m[0].length);
    }
    for (const m of scanned.matchAll(MAILTO_RE)) report("mailto", 0.4, m.index, m[0].length);
  }

  // 5. refusal / self-report — telemetry on its own, a real signal next to a
  //    flagged input.
  if (on("refusal")) {
    const afterFlagged = ctx.inputScans?.some((s) => s.flagged) ?? false;
    for (const p of REFUSAL_PATTERNS) {
      const m = p.re.exec(scanned);
      if (!m) continue;
      findings.push({
        label: afterFlagged ? `refusal:${p.label}:after-flagged-input` : `refusal:${p.label}`,
        category: "refusal",
        weight: afterFlagged ? 0.7 : 0.35,
        excerpt: excerptAt(scanned, m.index, m[0].length),
        index: m.index,
      });
      break; // one refusal finding is enough for triage
    }
  }

  // 6. echo of injected instructions — the model complied with something
  //    an input scan flagged.
  if (on("echo") && ctx.inputScans && ctx.inputScans.length > 0) {
    // A pattern that fired on the input firing again on the output means the
    // model reproduced the injected instruction rather than treating it as data.
    const probe = detectInjection(scanned, 0);
    const inputPatterns = new Set(ctx.inputScans.flatMap((s) => s.matches));
    for (const hit of probe.excerpts) {
      if (inputPatterns.has(hit.pattern)) {
        findings.push({ label: `echo:${hit.pattern}`, category: "echo", weight: 0.7, excerpt: hit.excerpt, index: hit.index });
      }
    }
  }

  // dedupe by label (keep first)
  const byLabel = new Map<string, OutputFinding>();
  for (const f of findings) if (!byLabel.has(f.label)) byLabel.set(f.label, f);
  const unique = [...byLabel.values()];

  // A registered secret must never reach a log through ANOTHER finding's
  // excerpt (an AWS key next to the DB password, say). Mask verbatim hits;
  // withhold the excerpt entirely when only the normalized form matches.
  if (ctx.secrets && ctx.secrets.length > 0) {
    for (const f of unique) {
      for (const raw of ctx.secrets) {
        if (normSecret(raw).length < 8) continue;
        if (f.excerpt.toLowerCase().includes(raw.toLowerCase())) {
          f.excerpt = f.excerpt.replace(new RegExp(raw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), "[secret]");
        } else if (normSecret(f.excerpt).includes(normSecret(raw))) {
          f.excerpt = "(excerpt withheld — contains a registered secret)";
        }
      }
    }
  }

  const max = unique.reduce((a, f) => Math.max(a, f.weight), 0);
  const score = unique.length === 0 ? 0 : Math.min(1, max + (unique.length - 1) * 0.05);
  const threshold = ctx.threshold ?? 0.5;
  return { score, flagged: score >= threshold, findings: unique, matches: unique.map((f) => f.label) };
}

/** Event detail line for a flagged output scan. */
export function outputDetail(scan: OutputScan): string {
  return scan.findings.map((f) => `[${f.label}] "${f.excerpt}"`).join(" | ").slice(0, 300);
}

// ── tool-call policy ─────────────────────────────────────────────────────────

export interface ToolCall {
  name: string;
  /** Parsed arguments (object) or raw JSON string. */
  input: unknown;
  id?: string;
}

/**
 * Thrown when a blocked tool call is assembled from a stream under
 * `enforceToolPolicy`.
 *
 * On a non-streaming response the wrapper strips the blocked block and the
 * caller simply never sees it. A stream has already handed the caller earlier
 * events by the time the call completes, so there is nothing to strip —
 * ending the iteration loudly is the only way to stop the call being acted
 * on. Catch it to fall back; letting it propagate is the safe default.
 */
export class ShieldBlockedToolError extends Error {
  readonly call: ToolCall;
  readonly reasons: string[];

  constructor(call: ToolCall, reasons: string[]) {
    super(`shield blocked tool call "${call.name}" mid-stream: ${reasons.join("; ")}`);
    this.name = "ShieldBlockedToolError";
    this.call = call;
    this.reasons = reasons;
  }
}

export interface ToolCallContext {
  /** True when this turn's context contained untrusted content (tool results,
   *  documents, fetched pages) — the "lethal trifecta" precondition. */
  untrustedInputSeen?: boolean;
  /** Input scans for this request; a flagged one raises severity. */
  inputScans?: InjectionScan[];
}

export interface ToolArgumentRule {
  /** Apply to this tool only (default: all tools). */
  tool?: string;
  /** Tested against the JSON-serialized arguments. Keep it bounded. */
  pattern: RegExp;
  action: "block" | "flag";
  reason?: string;
}

export interface ToolPolicy {
  /** If set, only these tools may be called; anything else is blocked. */
  allow?: string[];
  /** Always blocked. */
  deny?: string[];
  /** Tools with side effects (send email, write file, run shell, HTTP POST…).
   *  Calling one after untrusted input was seen is flagged; with
   *  `blockSideEffectsAfterUntrusted` it is blocked. */
  sideEffects?: string[];
  blockSideEffectsAfterUntrusted?: boolean;
  /** Argument-level rules (URLs to unknown hosts, shell metacharacters, paths). */
  argumentRules?: ToolArgumentRule[];
  /** Per-tool argument schemas. Stronger than `argumentRules` for the shapes
   *  that matter — a regex over serialized JSON cannot tell which field it
   *  matched, and cannot notice an argument that should not be there at all. */
  schemas?: ToolSchema[];
  /** Hosts tool arguments may reference; any other URL in arguments is flagged
   *  (blocked when `blockUnlistedHosts`). */
  allowedHosts?: string[];
  blockUnlistedHosts?: boolean;
}


// ── per-tool argument schemas ────────────────────────────────────────────────

/**
 * A constraint on one tool argument.
 *
 * This is deliberately not JSON Schema. Shield ships no dependencies, and a
 * full validator would be a large surface for the sake of keywords that do
 * nothing for security. What is here is the set that stops the arguments an
 * injected model actually reaches for: a path that escapes its directory, a
 * URL pointing at someone else's host, a free-form string where an enum was
 * expected, a number outside its range.
 */
export interface ToolParamSchema {
  type?: "string" | "number" | "integer" | "boolean" | "object" | "array";
  /** Allowed values; anything else is a violation. */
  enum?: ReadonlyArray<string | number | boolean>;
  /** Strings must match. Keep it bounded — this runs on model output. */
  pattern?: RegExp;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  /** Extra checks for the three argument shapes that carry real risk. */
  format?: "url" | "email" | "path";
  /** For format "url": hosts this argument may reference. */
  allowedHosts?: string[];
  /** For format "path": allow absolute paths (default false). */
  allowAbsolute?: boolean;
  /** Element constraint for arrays. */
  items?: ToolParamSchema;
}

export interface ToolSchema {
  /** The tool these constraints apply to. */
  tool: string;
  properties?: Record<string, ToolParamSchema>;
  required?: string[];
  /** Reject arguments not named in `properties`. Defaults to TRUE: an
   *  argument nobody declared is exactly how an extra `path` or `url` gets
   *  smuggled into an otherwise ordinary call. */
  additionalProperties?: boolean;
  /** Severity of a violation (default "block" — a schema is an assertion
   *  about what the tool accepts, not a suggestion). */
  action?: "block" | "flag";
}

const TRAVERSAL_RE = /(?:^|[\\/])\.\.(?:[\\/]|$)/;

function typeOf(v: unknown): string {
  if (Array.isArray(v)) return "array";
  if (v === null) return "null";
  return typeof v;
}

/** Check one value; returns human-readable violations, empty when it passes. */
function checkParam(name: string, value: unknown, schema: ToolParamSchema): string[] {
  const out: string[] = [];
  const actual = typeOf(value);

  if (schema.type) {
    const ok = schema.type === "integer"
      ? actual === "number" && Number.isInteger(value)
      : actual === schema.type;
    if (!ok) {
      // A type mismatch makes every other check meaningless — report it alone
      // rather than piling on errors derived from the wrong type.
      return [`"${name}" should be ${schema.type}, got ${actual}`];
    }
  }

  if (schema.enum && !schema.enum.includes(value as string)) {
    out.push(`"${name}" is not one of the allowed values`);
  }

  if (typeof value === "string") {
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      out.push(`"${name}" is longer than ${schema.maxLength} characters`);
    }
    if (schema.pattern && !schema.pattern.test(value)) {
      out.push(`"${name}" does not match the required pattern`);
    }
    if (schema.format === "path") {
      // Check the raw string AND its percent-decoded form: %2e%2e%2f is the
      // oldest way past a traversal check that only looks at literal dots.
      let decoded = value;
      try { decoded = decodeURIComponent(value); } catch { /* keep the raw form */ }
      if (TRAVERSAL_RE.test(value) || TRAVERSAL_RE.test(decoded)) {
        out.push(`"${name}" contains a path traversal segment`);
      }
      if (!schema.allowAbsolute && /^(?:[\\/]|[A-Za-z]:[\\/])/.test(value)) {
        out.push(`"${name}" is an absolute path`);
      }
      if (value.includes("\u0000")) out.push(`"${name}" contains a NUL byte`);
    }
    if (schema.format === "url") {
      const m = /^([a-z][a-z0-9+.-]*):/i.exec(value);
      const scheme = m?.[1]?.toLowerCase();
      if (!scheme || !["http", "https"].includes(scheme)) {
        // file:, data: and javascript: in a tool argument are not typos.
        out.push(`"${name}" is not an http(s) URL`);
      } else if (schema.allowedHosts) {
        const host = /^[a-z]+:\/\/([^/?#]+)/i.exec(value)?.[1]?.split("@").pop()?.split(":")[0];
        if (!host || !hostAllowed(host, schema.allowedHosts)) {
          out.push(`"${name}" references unlisted host ${host ?? "(unparseable)"}`);
        }
      }
    }
    if (schema.format === "email" && !/^[^\s@]+@[^\s@.]+\.[^\s@]+$/.test(value)) {
      out.push(`"${name}" is not an email address`);
    }
  }

  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) out.push(`"${name}" is below ${schema.minimum}`);
    if (schema.maximum !== undefined && value > schema.maximum) out.push(`"${name}" is above ${schema.maximum}`);
  }

  if (Array.isArray(value) && schema.items) {
    value.forEach((el, i) => out.push(...checkParam(`${name}[${i}]`, el, schema.items!)));
  }

  return out;
}

/**
 * Validate a call's arguments against its schema.
 *
 * Returns the violations; an empty array means it passed. Arguments that did
 * not parse as JSON are themselves a violation: a schema that silently does
 * not run is worse than no schema, because it reads as a check that passed.
 */
export function validateToolArguments(call: ToolCall, schema: ToolSchema): string[] {
  const input = call.input;

  if (typeof input === "string") {
    return [`arguments did not parse as JSON, so the schema could not be applied`];
  }
  if (input === null || input === undefined) {
    return schema.required?.length ? [`arguments are missing (${schema.required.join(", ")} required)`] : [];
  }
  if (typeOf(input) !== "object") {
    return [`arguments should be an object, got ${typeOf(input)}`];
  }

  const args = input as Record<string, unknown>;
  const out: string[] = [];
  const props = schema.properties ?? {};

  for (const name of schema.required ?? []) {
    if (!(name in args) || args[name] === undefined) out.push(`"${name}" is required but missing`);
  }

  if (schema.additionalProperties === false || schema.additionalProperties === undefined) {
    for (const name of Object.keys(args)) {
      if (!(name in props)) out.push(`"${name}" is not a declared argument of ${call.name}`);
    }
  }

  for (const [name, param] of Object.entries(props)) {
    if (!(name in args) || args[name] === undefined) continue;
    out.push(...checkParam(name, args[name], param));
  }

  return out;
}

export type ToolDecisionKind = "allow" | "flag" | "block";

export interface ToolDecision {
  decision: ToolDecisionKind;
  reasons: string[];
  call: ToolCall;
}

function argsText(input: unknown): string {
  if (typeof input === "string") return input;
  try { return JSON.stringify(input ?? ""); } catch { return String(input); }
}

/**
 * Decide whether a model-requested tool call should proceed. Pure: the
 * caller (or the client wrapper) emits the event and enforces.
 */
export function evaluateToolCall(call: ToolCall, policy: ToolPolicy = {}, ctx: ToolCallContext = {}): ToolDecision {
  const reasons: string[] = [];
  let decision: ToolDecisionKind = "allow";
  const escalate = (to: ToolDecisionKind, why: string) => {
    reasons.push(why);
    if (to === "block" || (to === "flag" && decision === "allow")) decision = to;
  };

  if (policy.deny?.includes(call.name)) escalate("block", `tool "${call.name}" is denied by policy`);
  if (policy.allow && !policy.allow.includes(call.name)) escalate("block", `tool "${call.name}" is not on the allow list`);

  const untrusted = Boolean(ctx.untrustedInputSeen) || Boolean(ctx.inputScans?.some((s) => s.flagged));
  if (policy.sideEffects?.includes(call.name) && untrusted) {
    escalate(policy.blockSideEffectsAfterUntrusted ? "block" : "flag",
      `side-effecting tool "${call.name}" requested after untrusted input${ctx.inputScans?.some((s) => s.flagged) ? " that was flagged for injection" : ""}`);
  }

  const text = argsText(call.input);
  for (const rule of policy.argumentRules ?? []) {
    if (rule.tool && rule.tool !== call.name) continue;
    if (rule.pattern.test(text)) escalate(rule.action, rule.reason ?? `argument rule matched: ${rule.pattern}`);
  }

  for (const schema of policy.schemas ?? []) {
    if (schema.tool !== call.name) continue;
    const violations = validateToolArguments(call, schema);
    for (const v of violations) escalate(schema.action ?? "block", `schema: ${v}`);
  }

  if (policy.allowedHosts) {
    for (const m of text.matchAll(URL_RE)) {
      if (!hostAllowed(m[1], policy.allowedHosts)) {
        escalate(policy.blockUnlistedHosts ? "block" : "flag", `argument references unlisted host ${m[1]}`);
        break;
      }
    }
  }

  return { decision, reasons, call };
}
