/**
 * Headless-browser / automation watch — detect browser automation running on
 * this machine (Playwright, Puppeteer, Selenium, bare headless Chromium…).
 *
 * Why: agents and test runners drive browsers invisibly, and so does malware
 * or a hijacked automation. A headless browser you didn't start is exactly
 * the kind of "mysterious activity" worth an event in the shared log.
 * This is a tripwire, not a blocker — detections are logged, you decide.
 *
 * Node-only (shells out to `ps`); exposed via `shield headless [--watch]`.
 */

import { emitShieldEvent } from "./shield.js";

export interface HeadlessSignature {
  label: string;
  re: RegExp;
}

/**
 * Command-line signatures of browser automation. Matching is on the full
 * process command line, so install paths count (Playwright/Puppeteer keep
 * their browsers under distinctive cache directories).
 */
export const HEADLESS_SIGNATURES: HeadlessSignature[] = [
  // The flag itself — any browser (or Electron app) running headless.
  { label: "headless-flag",  re: /--headless(=\S+)?\b/i },
  // CDP remote debugging — how Puppeteer/CDP clients attach, even to a
  // VISIBLE browser. A headful browser with this flag is still automation.
  { label: "remote-debug",   re: /--remote-debugging-(port|pipe)/i },
  // Frameworks, matched via their driver processes and browser cache paths.
  { label: "playwright",     re: /playwright/i },
  { label: "puppeteer",      re: /puppeteer/i },
  { label: "webdriver",      re: /(chromedriver|geckodriver|msedgedriver|operadriver|safaridriver)/i },
  { label: "selenium",       re: /selenium/i },
  { label: "cypress",        re: /cypress/i },
  { label: "phantomjs",      re: /phantomjs/i },
];

/** Labels of every signature the command line matches (empty = clean). */
export function matchHeadless(command: string): string[] {
  return HEADLESS_SIGNATURES.filter((s) => s.re.test(command)).map((s) => s.label);
}

export interface HeadlessProcess {
  pid: number;
  ppid: number;
  command: string;
  labels: string[];
}

/**
 * Scan currently running processes for automation signatures.
 * Excludes this process itself. macOS/Linux (`ps -axo`).
 */
export async function scanHeadlessProcesses(): Promise<HeadlessProcess[]> {
  const { execFile } = await import("child_process");
  const stdout = await new Promise<string>((resolve, reject) => {
    execFile("ps", ["-axo", "pid=,ppid=,command="], { maxBuffer: 16 * 1024 * 1024 }, (err, out) => {
      // Normalized rather than passed through: execFile's callback types the
      // error as nullable, and a rejection reason that isn't an Error loses
      // its stack at the catch site.
      if (err) reject(err instanceof Error ? err : new Error("ps failed"));
      else resolve(out);
    });
  });

  const found: HeadlessProcess[] = [];
  for (const line of stdout.split("\n")) {
    const m = line.match(/^\s*(\d+)\s+(\d+)\s+(.*)$/);
    if (!m) continue;
    const pid = Number(m[1]);
    const ppid = Number(m[2]);
    const command = m[3] ?? "";
    if (pid === process.pid) continue;
    const labels = matchHeadless(command);
    if (labels.length > 0) found.push({ pid, ppid, command, labels });
  }
  return found;
}

/**
 * Emit a `headless_detected` event for a process. Wire initFileLogger()
 * first if you want it persisted (the CLI does).
 */
export function reportHeadless(proc: HeadlessProcess): void {
  emitShieldEvent({
    type: "headless_detected",
    source: "headless-watch",
    detail: `pid=${proc.pid} ppid=${proc.ppid} [${proc.labels.join(",")}] ${proc.command}`.slice(0, 200),
    patterns: proc.labels,
  });
}
