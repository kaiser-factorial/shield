"""
Append-only JSONL event log — writes to ~/.shield/events.jsonl.
Compatible with the TypeScript shield log format so `shield logs` shows Python events too.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

EventType = Literal["injection_detected", "canary_leaked", "trigger_stripped", "shield_started", "headless_detected"]

LOG_DIR = Path.home() / ".shield"
LOG_FILE = LOG_DIR / "events.jsonl"


def _ensure_log_dir() -> bool:
    try:
        # The log stores snippets of user messages and transcripts — owner-only.
        # chmod (not just mkdir mode) so dirs created by older versions or with
        # a permissive umask get tightened too.
        LOG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(LOG_DIR, 0o700)
        return True
    except OSError:
        return False


def emit_event(
    type: EventType,
    source: str,
    detail: str = "",
    score: Optional[float] = None,
    patterns: Optional[list[str]] = None,
) -> None:
    if not _ensure_log_dir():
        return
    event: dict = {
        "type": type,
        "source": source,
        "detail": detail[:200],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if score is not None:
        event["score"] = round(score, 4)
    if patterns is not None:
        event["patterns"] = patterns
    try:
        # os.open (not Path.open) so a newly created file gets 0600 regardless
        # of umask; chmod tightens files created by older versions.
        fd = os.open(LOG_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
        os.chmod(LOG_FILE, 0o600)
    except OSError:
        pass
