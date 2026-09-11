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

import asyncio

from .core import SHIELD_VERSION, announce_shield, harden_system_prompt, output_leaked_canary, wrap_untrusted
from .detectors import (
    Detector,
    await_pending,
    close_pending,
    DetectorContext,
    DetectorFinding,
    combine_score,
    run_detectors,
    run_detectors_async,
)
from .detect import InjectionScan, detect_injection, scan_detail
from .logger import emit_event
from .output import (
    OutputFinding,
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
        detectors: Optional[Sequence[Detector]] = None,
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
        # Extra detectors beyond the pattern layer — a classifier, a term
        # list, an LLM judge. Sync ones run everywhere; async ones need the
        # *_async scans (see detectors.py for why input stays synchronous).
        self.detectors = list(detectors or [])
        self._warned_deferred: set[str] = set()
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

    def _detector_ctx(self, side: str, channel: Optional[str] = None, baseline: Any = None) -> DetectorContext:
        return DetectorContext(side=side, app=self.app, channel=channel, baseline=baseline)

    def _warn_deferred(self, name: str, why: str) -> None:
        if name in self._warned_deferred:
            return
        self._warned_deferred.add(name)
        print(f'[shield] detector "{name}" is async and was skipped: {why}')

    def _merge_input(self, scan: InjectionScan, findings: list[DetectorFinding], threshold: float) -> InjectionScan:
        """Fold detector findings into a pattern-layer scan, keeping the shape callers consume."""
        if not findings:
            return scan
        score = combine_score(scan.score, len(scan.matches), findings)
        return InjectionScan(
            score=score,
            matches=[*scan.matches, *(f.label for f in findings)],
            flagged=score >= threshold,
            excerpts=[*scan.excerpts,
                      *({"pattern": f.label, "excerpt": f.excerpt, "line": 1, "index": max(0, f.index)}
                        for f in findings)],
            truncated=scan.truncated,
        )

    def _emit_input(self, text: str, scan: InjectionScan, channel: Optional[str]) -> None:
        if scan.flagged:
            self.emit("injection_detected", source=self._source(channel), detail=scan_detail(text, scan),
                      score=scan.score, patterns=scan.matches, direction="input")

    def scan_input(self, text: str, *, channel: Optional[str] = None, threshold: Optional[float] = None) -> InjectionScan:
        """
        Scan untrusted text; emits `injection_detected` when flagged.

        Synchronous, because the result gates tool calls: an async detector
        registered on the input side is SKIPPED here (named once in a
        warning) rather than silently left out of a decision. Use
        `scan_input_async` when you can wait.
        """
        th = threshold if threshold is not None else self.threshold
        base = detect_injection(text, th)
        if not self.detectors:
            self._emit_input(text, base, channel)
            return base
        run = run_detectors(self.detectors, text, self._detector_ctx("input", channel, base))
        for name in run.deferred:
            self._warn_deferred(
                name,
                "the synchronous input scan gates tool calls and cannot wait for it. "
                "Use scan_input_async() to include it.")
        close_pending(run.pending)
        scan = self._merge_input(base, run.findings, th)
        self._emit_input(text, scan, channel)
        return scan

    async def scan_input_async(self, text: str, *, channel: Optional[str] = None,
                               threshold: Optional[float] = None) -> InjectionScan:
        """Like scan_input, but waits for async detectors too."""
        th = threshold if threshold is not None else self.threshold
        base = detect_injection(text, th)
        findings = (await run_detectors_async(self.detectors, text, self._detector_ctx("input", channel, base))
                    if self.detectors else [])
        scan = self._merge_input(base, findings, th)
        self._emit_input(text, scan, channel)
        return scan

    def wrap(self, content: str, label: str) -> str:
        return wrap_untrusted(content, label)

    def harden(self, base: str) -> tuple[str, str]:
        return harden_system_prompt(base, self.canary)

    # ── output side ───────────────────────────────────────────────────────────

    def _output_kwargs(self, canary, input_scans, allowed_hosts, detectors, threshold) -> dict:
        return dict(
            canary=canary,
            input_scans=input_scans,
            allowed_hosts=allowed_hosts if allowed_hosts is not None else self.allowed_hosts,
            detectors=detectors if detectors is not None else self.output_detectors,
            threshold=threshold if threshold is not None else self.output_threshold,
            secrets=self.secrets,
        )

    def _merge_output(self, scan: OutputScan, findings: list[DetectorFinding], threshold: float) -> OutputScan:
        if not findings:
            return scan
        extra = [OutputFinding(f.label, "custom", f.weight, f.excerpt, f.index) for f in findings]
        allf = [*scan.findings, *extra]
        score = combine_score(scan.score, len(scan.findings), findings)
        return OutputScan(score=score, flagged=score >= threshold, findings=allf)

    def _emit_output(self, text: str, scan: OutputScan, canary: Optional[str], *,
                     canary_already_emitted: bool = False, only_detector_findings: bool = False) -> None:
        if not canary_already_emitted and canary and output_leaked_canary(text, canary):
            self.emit("canary_leaked", detail=text[:200], direction="output")
            print(f"[shield] WARNING: canary leaked in response from {self.app}")
        rest = [f for f in scan.findings if f.category != "canary"]
        # The late-detector pass re-reports only what the first pass could not.
        if only_detector_findings:
            rest = [f for f in rest if f.label.startswith("detector:")]
        if not rest or not scan.flagged:
            return
        self.emit("output_flagged", detail=output_detail(OutputScan(scan.score, scan.flagged, rest)),
                  score=scan.score, patterns=[f.label for f in rest], direction="output")

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
        kwargs = self._output_kwargs(canary, input_scans, allowed_hosts, detectors, threshold)
        base = scan_output(text, **kwargs)
        th = kwargs["threshold"]
        scan = base

        if self.detectors:
            run = run_detectors(self.detectors, text, self._detector_ctx("output", None, base))
            scan = self._merge_output(base, run.findings, th)
            # Output scanning never gates anything, so a late verdict is
            # still worth having — schedule async detectors when a loop is
            # running, and say so plainly when there isn't one to run them on.
            if run.pending:
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None
                if loop is not None:
                    loop.create_task(self._finish_output(text, base, run.pending, th, canary))
                else:
                    for name in run.deferred:
                        self._warn_deferred(
                            name,
                            "scan_output() was called outside a running event loop, so there is "
                            "nowhere to run it. Use scan_output_async() (or call from async code).")
                    close_pending(run.pending)

        self._emit_output(text, scan, canary)
        return scan

    async def _finish_output(self, text: str, base: OutputScan, pending, threshold: float,
                             canary: Optional[str]) -> None:
        late = await await_pending(pending)
        if late:
            self._emit_output(text, self._merge_output(base, late, threshold), canary,
                              canary_already_emitted=True, only_detector_findings=True)

    async def scan_output_async(
        self,
        text: str,
        *,
        canary: Optional[str] = None,
        input_scans: Optional[Sequence[InjectionScan]] = None,
        allowed_hosts: Optional[Sequence[str]] = None,
        detectors: Optional[dict[str, bool]] = None,
        threshold: Optional[float] = None,
    ) -> OutputScan:
        """Like scan_output, but waits for async detectors and emits once."""
        kwargs = self._output_kwargs(canary, input_scans, allowed_hosts, detectors, threshold)
        base = scan_output(text, **kwargs)
        findings = (await run_detectors_async(self.detectors, text, self._detector_ctx("output", None, base))
                    if self.detectors else [])
        scan = self._merge_output(base, findings, kwargs["threshold"])
        self._emit_output(text, scan, canary)
        return scan

    def report_unscanned(self, what: str, *, channel: Optional[str] = None) -> None:
        """
        Record content that reached the model without being scanned — a base64
        PDF, an image, a remote URL the SDK fetches server-side.

        This exists because the alternative is silence, and silence reads as
        "scanned, nothing found". A log that cannot distinguish "we checked
        and it was clean" from "we never opened it" is not a security log.
        """
        self.emit(
            "content_not_scanned",
            source=self._source(channel),
            detail=f"not scanned: {what}"[:300],
            score=0,
            patterns=["coverage:not_scanned"],
            direction="input",
        )

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
