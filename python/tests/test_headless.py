"""
Tests for the headless-browser / automation watch (mirrors test/headless.test.ts).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("SHIELD_QUIET", "1")

import shield.logger as shield_logger
from shield import match_headless, scan_headless_processes
from shield.headless import HeadlessProcess, report_headless

# Redirect the shared event log to a temp dir so tests never pollute
# the real ~/.shield/events.jsonl.
_tmp = tempfile.TemporaryDirectory()
shield_logger.LOG_DIR = Path(_tmp.name)
shield_logger.LOG_FILE = shield_logger.LOG_DIR / "events.jsonl"


AUTOMATION_COMMANDS = [
    ("/Applications/Chromium.app/Contents/MacOS/Chromium --headless --disable-gpu https://x.test", "headless-flag"),
    ("/opt/chrome/chrome --headless=new --remote-debugging-port=9222", "remote-debug"),
    ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --remote-debugging-port=9222", "remote-debug"),
    ("node /Users/x/Library/Caches/ms-playwright/chromium-1105/chrome-mac/Chromium.app/x", "playwright"),
    ("node node_modules/.bin/playwright test --project=chromium", "playwright"),
    ("node /Users/x/.cache/puppeteer/chrome/mac-121/chrome", "puppeteer"),
    ("/usr/local/bin/chromedriver --port=51222", "webdriver"),
    ("java -jar selenium-server-4.1.0.jar standalone", "selenium"),
    ("/Users/x/Library/Caches/Cypress/13.0.0/Cypress.app/Contents/MacOS/Cypress", "cypress"),
    ("phantomjs render.js", "phantomjs"),
]

BENIGN_COMMANDS = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --type=renderer --lang=en-US",
    "node dist/bin/shield-cli.js headless --watch",
    "npm run build",
    "python3 bridge.py",
    "/Applications/Slack.app/Contents/MacOS/Slack",
    "vim notes/headless-testing-ideas.md",
]


class TestMatcher(unittest.TestCase):
    def test_automation_commands_detected(self):
        for cmd, expected in AUTOMATION_COMMANDS:
            labels = match_headless(cmd)
            self.assertIn(expected, labels, f"expected {expected} for: {cmd} (got {labels})")

    def test_benign_commands_not_flagged(self):
        for cmd in BENIGN_COMMANDS:
            self.assertEqual(match_headless(cmd), [], f"false positive on: {cmd}")


class TestScan(unittest.TestCase):
    def test_finds_live_decoy_process(self):
        # A harmless python process whose argv contains the flag.
        decoy = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(8)", "--headless"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(0.3)  # let ps see it
            procs = scan_headless_processes()
            hit = next((p for p in procs if p.pid == decoy.pid), None)
            self.assertIsNotNone(hit, "decoy process not found in scan")
            self.assertIn("headless-flag", hit.labels)
        finally:
            decoy.kill()

    def test_report_writes_event(self):
        report_headless(HeadlessProcess(pid=4242, ppid=1, command="chromium --headless x", labels=["headless-flag"]))
        lines = shield_logger.LOG_FILE.read_text(encoding="utf-8").strip().splitlines()
        events = [json.loads(line) for line in lines if line]
        ev = next(e for e in events if e["type"] == "headless_detected")
        self.assertEqual(ev["source"], "headless-watch")
        self.assertIn("pid=4242", ev["detail"])
        self.assertEqual(ev["patterns"], ["headless-flag"])


if __name__ == "__main__":
    unittest.main()
