"""
Pluggable detectors — the slot for anything the regex layer can't do.
Mirrors src/detectors.ts.

The pattern layer is a tripwire: it catches known phrasings and misses
paraphrase, translation and novel framings. This is where an app adds a
local classifier, an embedding-similarity check, a blocklist of its own
terms, or an LLM-judge call.

Sync vs async, and why the distinction is load-bearing:

  - **Sync detectors run everywhere**, including inside the SDK wrappers,
    and their findings are merged into the returned scan.
  - **Async detectors** (a coroutine, e.g. an LLM-judge round trip) run when
    you call `scan_input_async` / `scan_output_async`, and — on the OUTPUT
    side only — are scheduled by `scan_output` when an event loop is
    running, arriving later as their own event. Output scanning never gates
    anything, so a late answer is still useful. INPUT scanning feeds the
    tool-call decision, so a late answer there would be unsound: the sync
    path skips async input detectors and says so, rather than quietly
    deciding without them.

A detector that raises must never take the scan with it: every call is
isolated and failures are reported, not propagated.
"""
from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, Sequence, Union

DetectorSide = str  # "input" | "output"


@dataclass
class DetectorFinding:
    label: str            # namespaced by the runner as "detector:<name>:<label>"
    weight: float         # 0-1
    excerpt: str = ""     # optional context; mask anything sensitive yourself
    index: int = -1       # optional 0-based offset into the scanned text


@dataclass
class DetectorContext:
    side: DetectorSide
    app: str
    channel: Optional[str] = None
    baseline: Any = None   # InjectionScan | OutputScan from the pattern layer


ScanFn = Callable[[str, DetectorContext], Union[Sequence[DetectorFinding], Awaitable[Sequence[DetectorFinding]]]]


@dataclass
class Detector:
    name: str
    scan: ScanFn
    #: Sides this detector runs on; empty means both.
    sides: tuple[str, ...] = ()


@dataclass
class DetectorRun:
    findings: list[DetectorFinding] = field(default_factory=list)
    #: (detector, awaitable) for async detectors the sync path did not wait
    #: for. Held raw so a caller that will not await them can close() them —
    #: wrapping first would leave the inner coroutine dangling.
    pending: list[tuple["Detector", Awaitable]] = field(default_factory=list)

    @property
    def deferred(self) -> list[str]:
        """Names of the async detectors that were not awaited."""
        return [d.name for d, _ in self.pending]


def _applies(d: Detector, side: str) -> bool:
    return not d.sides or side in d.sides


def qualify(detector: Detector, f: DetectorFinding) -> DetectorFinding:
    """`detector:<name>:<label>`, so a finding's origin survives into the log."""
    return DetectorFinding(
        label=f"detector:{detector.name}:{f.label}",
        weight=max(0.0, min(1.0, float(f.weight or 0))),
        excerpt=f.excerpt,
        index=f.index,
    )


def _normalize(detector: Detector, raw: Any) -> list[DetectorFinding]:
    if not raw:
        return []
    try:
        return [qualify(detector, f) for f in raw if isinstance(f, DetectorFinding)]
    except TypeError:
        return []


def _report(detector: Detector, err: BaseException) -> None:
    # Deliberately print, not the event bus: a detector failing while the bus
    # is mid-dispatch would re-enter it.
    print(f'[shield] detector "{detector.name}" raised; continuing without it: {err!r}')


def run_detectors(detectors: Sequence[Detector], text: str, ctx: DetectorContext) -> DetectorRun:
    """
    Run detectors without awaiting. Sync results come back immediately; async
    ones are named in `deferred` with their awaitables in `pending`.
    """
    run = DetectorRun()
    for d in detectors:
        if not _applies(d, ctx.side):
            continue
        try:
            out = d.scan(text, ctx)
        except Exception as err:  # noqa: BLE001
            _report(d, err)
            continue
        if inspect.isawaitable(out):
            run.pending.append((d, out))
        else:
            run.findings.extend(_normalize(d, out))
    return run


async def await_pending(pending: Sequence[tuple[Detector, Awaitable]]) -> list[DetectorFinding]:
    """Await deferred detectors, isolating failures the way the sync path does."""
    out: list[DetectorFinding] = []
    for detector, awaitable in pending:
        try:
            out.extend(_normalize(detector, await awaitable))
        except Exception as err:  # noqa: BLE001
            _report(detector, err)
    return out


def close_pending(pending: Sequence[tuple[Detector, Awaitable]]) -> None:
    """Discard deferred detectors nothing will await, without a dangling-coroutine warning."""
    for _, awaitable in pending:
        close = getattr(awaitable, "close", None)
        if callable(close):
            close()


async def run_detectors_async(detectors: Sequence[Detector], text: str, ctx: DetectorContext) -> list[DetectorFinding]:
    """Run every applicable detector to completion."""
    run = run_detectors(detectors, text, ctx)
    return [*run.findings, *await await_pending(run.pending)]


def combine_score(base_score: float, base_count: int, findings: Sequence[DetectorFinding]) -> float:
    """
    Combine a pattern-layer score with detector findings the same way
    detect_injection combines its own patterns: highest weight wins, each
    additional signal adds a little.
    """
    if not findings:
        return base_score
    mx = max(f.weight for f in findings)
    total = base_count + len(findings)
    return min(1.0, max(base_score, mx) + max(0, total - 1) * 0.05)
