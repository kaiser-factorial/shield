/**
 * Tests for the headless-browser / automation watch.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "child_process";

import { matchHeadless, scanHeadlessProcesses, reportHeadless } from "../src/headless.js";
import { onShieldEvent, type ShieldEvent } from "../src/shield.js";
import { summarizeStatus } from "../src/logger.js";

const AUTOMATION_COMMANDS: Array<{ cmd: string; expect: string }> = [
  { cmd: "/Applications/Chromium.app/Contents/MacOS/Chromium --headless --disable-gpu https://x.test", expect: "headless-flag" },
  { cmd: "/opt/chrome/chrome --headless=new --remote-debugging-port=9222", expect: "remote-debug" },
  { cmd: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --remote-debugging-port=9222", expect: "remote-debug" },
  { cmd: "node /Users/x/Library/Caches/ms-playwright/chromium-1105/chrome-mac/Chromium.app/x", expect: "playwright" },
  { cmd: "node node_modules/.bin/playwright test --project=chromium", expect: "playwright" },
  { cmd: "node /Users/x/.cache/puppeteer/chrome/mac-121/chrome", expect: "puppeteer" },
  { cmd: "/usr/local/bin/chromedriver --port=51222", expect: "webdriver" },
  { cmd: "java -jar selenium-server-4.1.0.jar standalone", expect: "selenium" },
  { cmd: "/Users/x/Library/Caches/Cypress/13.0.0/Cypress.app/Contents/MacOS/Cypress", expect: "cypress" },
  { cmd: "phantomjs render.js", expect: "phantomjs" },
];

const BENIGN_COMMANDS: string[] = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --type=renderer --lang=en-US",
  "node dist/bin/shield-cli.js headless --watch",
  "npm run build",
  "python3 bridge.py",
  "/Applications/Slack.app/Contents/MacOS/Slack",
  "vim notes/headless-testing-ideas.md", // word "headless" without the flag is fine
];

test("matcher: automation command lines are detected with the expected label", () => {
  for (const { cmd, expect } of AUTOMATION_COMMANDS) {
    const labels = matchHeadless(cmd);
    assert.ok(labels.includes(expect), `expected ${expect} for: ${cmd} (got ${labels})`);
  }
});

test("matcher: ordinary processes are not flagged", () => {
  for (const cmd of BENIGN_COMMANDS) {
    assert.deepEqual(matchHeadless(cmd), [], `false positive on: ${cmd}`);
  }
});

test("scan: finds a live decoy process carrying --headless", async () => {
  // A harmless sleeping process whose argv contains the flag. The compound
  // command stops bash exec-replacing itself with `sleep` (which would drop
  // the decoy argv from ps).
  const decoy = spawn("bash", ["-c", "sleep 8; true", "shield-decoy", "--headless"], {
    stdio: "ignore",
  });
  try {
    await new Promise((r) => setTimeout(r, 300)); // let ps see it
    const procs = await scanHeadlessProcesses();
    const hit = procs.find((p) => p.pid === decoy.pid);
    assert.ok(hit, "decoy process not found in scan");
    assert.ok(hit.labels.includes("headless-flag"));
  } finally {
    decoy.kill();
  }
});

test("report: emits a headless_detected event with pid and labels", () => {
  const events: ShieldEvent[] = [];
  onShieldEvent((ev) => events.push(ev));
  reportHeadless({ pid: 4242, ppid: 1, command: "chromium --headless x", labels: ["headless-flag"] });
  const ev = events.find((e) => e.type === "headless_detected");
  assert.ok(ev);
  assert.equal(ev.source, "headless-watch");
  assert.ok(ev.detail.includes("pid=4242"));
  assert.deepEqual(ev.patterns, ["headless-flag"]);
});

test("status: headless events are counted in the 7-day window", () => {
  const now = new Date("2026-07-02T12:00:00Z");
  const t = (daysAgo: number) => new Date(now.getTime() - daysAgo * 86400e3).toISOString();
  const apps = summarizeStatus(
    [
      { type: "headless_detected", source: "headless-watch", detail: "pid=1", timestamp: t(1) },
      { type: "headless_detected", source: "headless-watch", detail: "pid=2", timestamp: t(9) }, // outside window
    ],
    now,
  );
  assert.equal(apps.length, 1);
  assert.equal(apps[0]!.headless7d, 1);
});
