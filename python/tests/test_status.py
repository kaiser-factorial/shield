"""
Tests for announce/heartbeat behavior and version parity with pyproject.toml.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("SHIELD_QUIET", "1")  # suppress banners in test output

import shield.logger as shield_logger
from shield import SHIELD_VERSION, ShieldAnthropicClient, announce_shield, __version__

# Redirect the shared event log to a temp dir so tests never pollute
# the real ~/.shield/events.jsonl.
_tmp = tempfile.TemporaryDirectory()
shield_logger.LOG_DIR = Path(_tmp.name)
shield_logger.LOG_FILE = shield_logger.LOG_DIR / "events.jsonl"


def _events() -> list[dict]:
    if not shield_logger.LOG_FILE.exists():
        return []
    return [
        json.loads(line)
        for line in shield_logger.LOG_FILE.read_text(encoding="utf-8").strip().splitlines()
        if line
    ]


class TestAnnounce(unittest.TestCase):
    def test_version_matches_pyproject(self):
        pyproject = (Path(__file__).parent.parent / "pyproject.toml").read_text()
        declared = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M).group(1)
        self.assertEqual(SHIELD_VERSION, declared)
        self.assertEqual(__version__, declared)

    def test_announce_emits_heartbeat_with_version(self):
        before = len(_events())
        announce_shield("announce-test-1")
        events = _events()
        self.assertEqual(len(events), before + 1)
        self.assertEqual(events[-1]["type"], "shield_started")
        self.assertEqual(events[-1]["source"], "announce-test-1")
        self.assertEqual(events[-1]["detail"], f"v{SHIELD_VERSION}")

    def test_announce_once_per_process_per_label(self):
        announce_shield("announce-test-2")
        before = len(_events())
        announce_shield("announce-test-2")
        self.assertEqual(len(_events()), before)

    def test_wrapper_construction_announces_automatically(self):
        before = len(_events())
        inner = SimpleNamespace(messages=SimpleNamespace(create=lambda **kw: None))
        ShieldAnthropicClient(inner, app_label="auto-announce-test")
        started = [e for e in _events()[before:] if e["type"] == "shield_started"]
        self.assertEqual(len(started), 1)
        self.assertEqual(started[0]["source"], "auto-announce-test")


if __name__ == "__main__":
    unittest.main()
