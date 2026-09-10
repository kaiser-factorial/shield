/**
 * Tests for announce/heartbeat and the `shield status` aggregation.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "fs";

process.env["SHIELD_QUIET"] = "1";

import {
  announceShield,
  onShieldEvent,
  SHIELD_VERSION,
  PATTERN_COUNT,
  type ShieldEvent,
} from "../src/shield.js";
import { ShieldAnthropicClient } from "../src/client-anthropic.js";
import { summarizeStatus } from "../src/logger.js";

const events: ShieldEvent[] = [];
onShieldEvent((ev) => events.push(ev));

test("version constant matches package.json (parity is enforced, not hoped for)", () => {
  const pkg = JSON.parse(
    readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
  ) as { version: string };
  assert.equal(SHIELD_VERSION, pkg.version);
});

test("pattern count matches the documented 30", () => {
  assert.equal(PATTERN_COUNT, 30);
});

test("announce emits a shield_started heartbeat carrying the version", () => {
  const before = events.length;
  announceShield({ appLabel: "announce-test-1" });
  const emitted = events.slice(before);
  assert.equal(emitted.length, 1);
  assert.equal(emitted[0]!.type, "shield_started");
  assert.equal(emitted[0]!.source, "announce-test-1");
  assert.equal(emitted[0]!.detail, `v${SHIELD_VERSION}`);
});

test("announce is once-per-process per label", () => {
  announceShield({ appLabel: "announce-test-2" });
  const before = events.length;
  announceShield({ appLabel: "announce-test-2" });
  assert.equal(events.length, before);
});

test("client wrapper construction announces automatically", () => {
  const before = events.length;
  const inner = { messages: { create: async () => ({}) } };
  new ShieldAnthropicClient(inner, { appLabel: "auto-announce-test" });
  const started = events.slice(before).filter((e) => e.type === "shield_started");
  assert.equal(started.length, 1);
  assert.equal(started[0]!.source, "auto-announce-test");
});

test("summarizeStatus aggregates per app, parses versions, windows counts to 7 days", () => {
  const now = new Date("2026-07-02T12:00:00Z");
  const t = (daysAgo: number) =>
    new Date(now.getTime() - daysAgo * 24 * 60 * 60 * 1000).toISOString();

  const synthetic: ShieldEvent[] = [
    { type: "shield_started", source: "bulwork", detail: "v1.0.0", timestamp: t(10) },
    { type: "shield_started", source: "bulwork", detail: "v1.1.0", timestamp: t(1) },
    // source qualifiers after ":" group under the app name
    { type: "injection_detected", source: "bulwork:page_title", detail: "x", score: 0.9, patterns: ["ignore-instructions"], timestamp: t(2) },
    { type: "injection_detected", source: "bulwork", detail: "y", score: 0.9, patterns: ["jailbreak-dan"], timestamp: t(9) }, // outside window
    { type: "canary_leaked", source: "voicelogger", detail: "z", timestamp: t(3) },
    { type: "trigger_stripped", source: "wrap:untrusted_page_title", detail: "w", timestamp: t(1) },
  ];

  const apps = summarizeStatus(synthetic, now);
  assert.deepEqual(apps.map((a) => a.app), ["bulwork", "voicelogger", "wrap"]);

  const bulwork = apps[0]!;
  assert.equal(bulwork.version, "1.1.0", "latest heartbeat wins");
  assert.equal(bulwork.lastStarted, t(1));
  assert.equal(bulwork.injections7d, 1, "9-day-old injection falls outside the window");

  const voicelogger = apps[1]!;
  assert.equal(voicelogger.version, null, "no heartbeat → unknown version");
  assert.equal(voicelogger.lastStarted, null);
  assert.equal(voicelogger.leaks7d, 1);
});
