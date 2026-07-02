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

EventType = Literal["injection_detected", "canary_leaked", "trigger_stripped"]

LOG_DIR = Path.home() / ".shield"
LOG_FILE = LOG_DIR / "events.jsonl"


def _ensure_log_dir() -> bool:
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
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
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except OSError:
        pass
