/**
 * Tests for the file logger's security posture: terminal-output sanitization
 * and owner-only permissions on ~/.shield.
 *
 * HOME is redirected to a temp dir BEFORE the logger module is imported
 * (LOG_DIR is computed at module load), so this file never touches the real
 * ~/.shield. Each node:test file runs in its own process, so the redirect
 * can't leak into other suites.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, statSync, existsSync, mkdirSync, writeFileSync, chmodSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

process.env["SHIELD_QUIET"] = "1";
const fakeHome = mkdtempSync(join(tmpdir(), "shield-logger-test-"));
process.env["HOME"] = fakeHome;

const { initFileLogger, sanitizeForTerminal, LOG_FILE } = await import("../src/logger.js");
const { emitShieldEvent } = await import("../src/shield.js");

const LOG_DIR = join(fakeHome, ".shield");
assert.ok(LOG_FILE.startsWith(fakeHome), "logger must have picked up the redirected HOME");

// The file write behind emitShieldEvent is async (fire-and-forget) — poll.
async function waitFor(cond: () => boolean, ms = 2000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > ms) throw new Error("timed out waiting for logger");
    await new Promise((r) => setTimeout(r, 20));
  }
}

const mode = (path: string) => statSync(path).mode & 0o777;

// ── sanitizeForTerminal ──────────────────────────────────────────────────────

test("sanitizeForTerminal strips ANSI escape sequences (ESC byte)", () => {
  const esc = String.fromCharCode(0x1b);
  assert.equal(sanitizeForTerminal(`a${esc}[31mred${esc}[0mb`), "a[31mred[0mb");
});

test("sanitizeForTerminal strips C1 controls (raw CSI/OSC bytes) and BEL", () => {
  const csi = String.fromCharCode(0x9b);
  const osc = String.fromCharCode(0x9d);
  const bel = String.fromCharCode(0x07);
  assert.equal(sanitizeForTerminal(`x${csi}2Jy${osc}0;evil${bel}z`), "x2Jy0;evilz");
});

test("sanitizeForTerminal flattens newlines and tabs to spaces", () => {
  assert.equal(sanitizeForTerminal("line1\nline2\tend"), "line1 line2 end");
});

test("sanitizeForTerminal strips NUL, BEL, backspace, and carriage return", () => {
  const cc = (n: number) => String.fromCharCode(n);
  assert.equal(sanitizeForTerminal(`a${cc(0)}b${cc(7)}c${cc(8)}d${cc(13)}e`), "abcde");
});

test("sanitizeForTerminal leaves normal text (incl. unicode) alone", () => {
  const s = "ignore previous instructions — 日本語 · émojis 👻";
  assert.equal(sanitizeForTerminal(s), s);
});

// ── log file permissions ─────────────────────────────────────────────────────

test("log dir is 0700 and log file is 0600 after first write", async () => {
  // Pre-create with loose permissions to prove initFileLogger tightens legacy files.
  mkdirSync(LOG_DIR, { recursive: true, mode: 0o755 });
  writeFileSync(LOG_FILE, "", { encoding: "utf8", mode: 0o644 });
  chmodSync(LOG_DIR, 0o755);
  chmodSync(LOG_FILE, 0o644);

  initFileLogger();
  emitShieldEvent({ type: "shield_started", source: "perms-test", detail: "v" });

  await waitFor(() => existsSync(LOG_FILE) && mode(LOG_FILE) === 0o600 && mode(LOG_DIR) === 0o700);
  assert.equal(mode(LOG_DIR), 0o700);
  assert.equal(mode(LOG_FILE), 0o600);
});
