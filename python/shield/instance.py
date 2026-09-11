"""
create_shield(...) — an instance with its own configuration, sinks and event
buffer. Mirrors src/instance.ts.

The module-level functions keep working unchanged; `get_default_shield()` is
the instance they are equivalent to. Events are forwarded to the module bus
(and therefore the shared JSONL log) unless `forward_to_global=False`.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Sequence

from .core import SHIELD_VERSION, announce_shield, harden_system_prompt, output_leaked_canary, wrap_untrusted
from .detect import InjectionScan, detect_injection, scan_detail
from .logger import emit_event
from .output import (
    OutputScan,
    ToolCall,
    ToolDecision,
    ToolPolicy,
    evaluate_tool_call,
    output_detail,
    scan_output,
)

Sink = Callable[[dict], None]


def _hash32hex(s: str) -> str:
    h = 0x811C9DC5
    b = s.encode("utf-16-le")
    for i in range(0, len(b), 2):
        h ^= b[i] | (b[i + 1] << 8)
        h = (h * 16777619) & 0xFFFFFFFF
    return f"{h:08x}"


class Shield:
    """See create_shield()."""

    RECENT_MAX = 256

    def __init__(
        self,
        *,
        app: str = "shield",
        threshold: float = 0.5,
        canary: Optional[str] = None,
        redact: str = "excerpt",               # "excerpt" | "hash" | "none"
        secrets: Optional[Sequence[str]] = None,
        allowed_hosts: Optional[Sequence[str]] = None,
        output_detectors: Optional[dict[str, bool]] = None,
        output_threshold: float = 0.5,
        tool_policy: Optional[ToolPolicy] = None,
        sinks: Optional[Sequence[Sink]] = None,
        forward_to_global: bool = True,
        banner: bool = True,
    ):
        self.app = app
        self.threshold = threshold
        self.canary = canary
        self.redact = redact
        self.secrets = list(secrets or [])
        self.allowed_hosts = list(allowed_hosts) if allowed_hosts is not None else None
        self.output_detectors = dict(output_detectors or {})
        self.output_threshold = output_threshold
        self.tool_policy = tool_policy or ToolPolicy()
        self.forward_to_global = forward_to_global
        self._handlers: list[Sink] = list(sinks or [])
        self._recent: deque = deque(maxlen=self.RECENT_MAX)
        announce_shield(app, banner=banner)

    @property
    def version(self) -> str:
        return SHIELD_VERSION

    # ── events ────────────────────────────────────────────────────────────────

    def on(self, handler: Sink, *, replay: bool = False) -> Callable[[], None]:
        if replay:
            for ev in list(self._recent):
                try:
                    handler(ev)
                except Exception as err:  # noqa: BLE001
                    print(f"[shield] sink threw during replay; continuing: {err!r}")
        self._handlers.append(handler)

        def off() -> None:
            try:
                self._handlers.remove(handler)
            except ValueError:
                pass

        return off

    @property
    def events(self) -> list[dict]:
        return list(self._recent)

    def _redact(self, detail: str) -> str:
        if self.redact == "hash":
            return f"sha:{_hash32hex(detail)}" if detail else ""
        if self.redact == "none":
            return ""
        return detail

    def emit(
        self,
        type: str,
        *,
        source: Optional[str] = None,
        detail: str = "",
        score: Optional[float] = None,
        patterns: Optional[list[str]] = None,
        direction: Optional[str] = None,
    ) -> dict:
        detail = self._redact(detail)
        event: dict = {
            "type": type,
            "source": source or self.app,
            "detail": detail[:300],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if score is not None:
            event["score"] = round(score, 4)
        if patterns is not None:
            event["patterns"] = patterns
        if direction:
            event["direction"] = direction
        self._recent.append(event)
        for h in list(self._handlers):
            try:
                h(event)
            except Exception as err:  # noqa: BLE001
                print(f"[shield] sink threw; continuing: {err!r}")
        if self.forward_to_global:
            emit_event(type, source=event["source"], detail=detail, score=score,  # type: ignore[arg-type]
                       patterns=patterns, direction=direction)
        return event

    def _source(self, channel: Optional[str]) -> str:
        return f"{self.app}:{channel}" if channel else self.app

    # ── input side ────────────────────────────────────────────────────────────

    def scan_input(self, text: str, *, channel: Optional[str] = None, threshold: Optional[float] = None) -> InjectionScan:
        scan = detect_injection(text, threshold if threshold is not None else self.threshold)
        if scan.flagged:
            self.emit("injection_detected", source=self._source(channel), detail=scan_detail(text, scan),
                      score=scan.score, patterns=scan.matches, direction="input")
        return scan

    def wrap(self, content: str, label: str) -> str:
        return wrap_untrusted(content, label)

    def harden(self, base: str) -> tuple[str, str]:
        return harden_system_prompt(base, self.canary)

    # ── output side ───────────────────────────────────────────────────────────

    def scan_output(
        self,
        text: str,
        *,
        canary: Optional[str] = None,
        input_scans: Optional[Sequence[InjectionScan]] = None,
        allowed_hosts: Optional[Sequence[str]] = None,
        detectors: Optional[dict[str, bool]] = None,
        threshold: Optional[float] = None,
    ) -> OutputScan:
        scan = scan_output(
            text,
            canary=canary,
            input_scans=input_scans,
            allowed_hosts=allowed_hosts if allowed_hosts is not None else self.allowed_hosts,
            detectors=detectors if detectors is not None else self.output_detectors,
            threshold=threshold if threshold is not None else self.output_threshold,
            secrets=self.secrets,
        )
        if canary and output_leaked_canary(text, canary):
            self.emit("canary_leaked", detail=text[:200], direction="output")
            print(f"[shield] WARNING: canary leaked in response from {self.app}")
        rest = [f for f in scan.findings if f.category != "canary"]
        if rest and scan.flagged:
            self.emit("output_flagged", detail=output_detail(OutputScan(scan.score, scan.flagged, rest)),
                      score=scan.score, patterns=[f.label for f in rest], direction="output")
        return scan

    def check_tool_call(
        self,
        call: ToolCall,
        *,
        untrusted_input_seen: bool = False,
        input_scans: Optional[Sequence[InjectionScan]] = None,
    ) -> ToolDecision:
        d = evaluate_tool_call(call, self.tool_policy, untrusted_input_seen=untrusted_input_seen, input_scans=input_scans)
        if d.decision != "allow":
            self.emit("tool_call_gated",
                      detail=f"{d.decision}: {call.name} — {'; '.join(d.reasons)}",
                      score=1.0 if d.decision == "block" else 0.6,
                      patterns=[f"tool:{call.name}", f"decision:{d.decision}"], direction="tool")
        return d


def create_shield(**config: Any) -> Shield:
    return Shield(**config)


_default: Optional[Shield] = None


def get_default_shield() -> Shield:
    global _default
    if _default is None:
        _default = Shield(banner=False)
    return _default
