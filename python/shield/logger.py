"""
Event bus + append-only JSONL file sink.

`emit_event` dispatches to in-process subscribers (`on_event`) and, by
default, appends to the shared log (`~/.shield/events.jsonl`, or
`$SHIELD_LOG_DIR/events.jsonl`) in the same format the TypeScript side
writes, so `shield logs` shows Python events too.

Before v1.5 there was no bus at all — every event went straight to disk and
apps had no way to route events to their own logging, a webhook, or tests.
"""
from __future__ import annotations

import json
import os
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal, Optional

EventType = Literal["injection_detected", "canary_leaked", "trigger_stripped", "shield_started", "headless_detected"]

_env_dir = os.environ.get("SHIELD_LOG_DIR")
LOG_DIR = Path(_env_dir) if _env_dir else Path.home() / ".shield"
LOG_FILE = LOG_DIR / "events.jsonl"

# Set to False to keep events in-process only (route them with on_event).
FILE_SINK_ENABLED = True

Handler = Callable[[dict], None]
_handlers: list[Handler] = []
_recent: deque = deque(maxlen=256)


def on_event(handler: Handler, *, replay: bool = False) -> Callable[[], None]:
    """
    Subscribe to shield events. Returns an unsubscribe function. With
    `replay=True`, events emitted before subscribing (most recent 256) are
    delivered first — so wiring a sink after constructing a client wrapper
    doesn't lose the `shield_started` heartbeat.
    """
    if replay:
        for ev in list(_recent):
            try:
                handler(ev)
            except Exception as err:  # noqa: BLE001
                print(f"[shield] event handler threw during replay; continuing: {err!r}")
    _handlers.append(handler)

    def off() -> None:
        off_event(handler)

    return off


def off_event(handler: Handler) -> None:
    """Remove a previously registered handler (no-op if it isn't registered)."""
    try:
        _handlers.remove(handler)
    except ValueError:
        pass


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


def _write_file(event: dict) -> None:
    if not _ensure_log_dir():
        return
    try:
        # os.open (not Path.open) so a newly created file gets 0600 regardless
        # of umask; chmod tightens files created by older versions.
        fd = os.open(LOG_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
        os.chmod(LOG_FILE, 0o600)
    except OSError:
        pass


def emit_event(
    type: EventType,
    source: str,
    detail: str = "",
    score: Optional[float] = None,
    patterns: Optional[list[str]] = None,
) -> None:
    event: dict = {
        "type": type,
        "source": source,
        "detail": detail[:300],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if score is not None:
        event["score"] = round(score, 4)
    if patterns is not None:
        event["patterns"] = patterns

    _recent.append(event)
    # Iterate a copy and isolate each handler: a subscriber bug must never
    # break sanitization (emit_event is called from wrap_untrusted).
    for h in list(_handlers):
        try:
            h(event)
        except Exception as err:  # noqa: BLE001
            print(f"[shield] event handler threw; continuing: {err!r}")
    if FILE_SINK_ENABLED:
        _write_file(event)


def read_events(limit: Optional[int] = None) -> list[dict]:
    """Read events from the log file, newest-last. Malformed lines are skipped."""
    try:
        text = LOG_FILE.read_text(encoding="utf-8")
    except OSError:
        return []
    out: list[dict] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if isinstance(ev, dict) and isinstance(ev.get("type"), str):
            out.append(ev)
    return out[-limit:] if limit else out
