"""
Tests for the event log's security posture: the log holds snippets of user
messages and transcripts, so the directory must be 0700 and the file 0600 —
including tightening files created by pre-1.3 versions with looser modes.
"""
from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("SHIELD_QUIET", "1")

import shield.logger as shield_logger


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


class TestLogPermissions(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = (shield_logger.LOG_DIR, shield_logger.LOG_FILE)
        shield_logger.LOG_DIR = Path(self._tmp.name) / "shield-home"
        shield_logger.LOG_FILE = shield_logger.LOG_DIR / "events.jsonl"

    def tearDown(self):
        shield_logger.LOG_DIR, shield_logger.LOG_FILE = self._orig
        self._tmp.cleanup()

    def test_fresh_log_dir_and_file_are_owner_only(self):
        shield_logger.emit_event("shield_started", source="perm-test", detail="v")
        self.assertEqual(_mode(shield_logger.LOG_DIR), 0o700)
        self.assertEqual(_mode(shield_logger.LOG_FILE), 0o600)

    def test_existing_loose_permissions_are_tightened(self):
        shield_logger.LOG_DIR.mkdir(parents=True)
        shield_logger.LOG_FILE.write_text("")
        os.chmod(shield_logger.LOG_DIR, 0o755)
        os.chmod(shield_logger.LOG_FILE, 0o644)

        shield_logger.emit_event("shield_started", source="perm-test", detail="v")
        self.assertEqual(_mode(shield_logger.LOG_DIR), 0o700)
        self.assertEqual(_mode(shield_logger.LOG_FILE), 0o600)

    def test_events_still_append(self):
        shield_logger.emit_event("shield_started", source="perm-test", detail="v1")
        shield_logger.emit_event("shield_started", source="perm-test", detail="v2")
        lines = shield_logger.LOG_FILE.read_text().strip().splitlines()
        self.assertEqual(len(lines), 2)


if __name__ == "__main__":
    unittest.main()
