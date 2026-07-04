"""
Prompt injection detection — same 26 patterns as the TypeScript version.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class InjectionScan:
    score: float
    matches: list[str]
    flagged: bool
    # Context around each match — what actually tripped the pattern, for
    # triage. Each entry: {"pattern": label, "excerpt": "…text around match…"}
    excerpts: list[dict] = field(default_factory=list)


_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    # Override attempts
    ("ignore-instructions",    re.compile(r"ignore\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|rules?|prompts?|directives?)", re.I), 0.90),
    ("forget-instructions",    re.compile(r"forget\s+(everything|all\s+instructions?|your\s+instructions?)", re.I), 0.90),
    ("disregard-instructions", re.compile(r"disregard\s+(all\s+)?(previous|prior|your)\s+(instructions?|rules?)", re.I), 0.85),
    ("new-instructions",       re.compile(r"new\s+(instructions?|directive|rules?|orders?)\s*:", re.I), 0.75),
    ("override-instructions",  re.compile(r"override\s+(your\s+)?(instructions?|rules?|programming)", re.I), 0.85),
    # Role hijacking
    ("you-are-now",            re.compile(r"you\s+are\s+now\s+(a|an|the)\s+\w", re.I), 0.70),
    ("act-as",                 re.compile(r"act\s+as\s+(a|an|the)\s+\w", re.I), 0.50),
    ("pretend-you-are",        re.compile(r"pretend\s+(you\s+are|to\s+be)\s+", re.I), 0.60),
    ("roleplay-as",            re.compile(r"roleplay\s+as\s+", re.I), 0.50),
    ("your-new-persona",       re.compile(r"your\s+(new\s+)?(persona|identity|role)\s+is", re.I), 0.70),
    # System prompt exposure
    ("reveal-system-prompt",   re.compile(r"reveal\s+(your\s+)?(system\s+prompt|instructions?|hidden\s+prompt)", re.I), 0.90),
    ("print-system-prompt",    re.compile(r"print\s+(your\s+)?(system\s+prompt|initial\s+prompt)", re.I), 0.85),
    ("what-is-your-system",    re.compile(r"what\s+(is|are)\s+your\s+(system\s+prompt|instructions?|rules?)", re.I), 0.60),
    ("repeat-above",           re.compile(r"repeat\s+(everything|all\s+(text|content|instructions?))\s+(above|before)", re.I), 0.75),
    # Embedded role spoofing
    ("system-tag",             re.compile(r"^\s*\[(system|admin|operator)\]", re.I | re.M), 0.80),
    ("system-colon",           re.compile(r"^\s*(system|admin|operator)\s*:\s+", re.I | re.M), 0.70),
    ("xml-system-tag",         re.compile(r"<(system|instructions?|prompt)\s*>", re.I), 0.75),
    # Jailbreak boilerplate
    # The acronym is case-SENSITIVE on purpose: jailbreak boilerplate writes
    # "DAN" in caps, while "Dan"/"dan" is overwhelmingly just someone's name.
    # A mixed-case "Dan" jailbreak has to define the acronym to work, and the
    # spelled-out phrase below stays case-insensitive to catch exactly that.
    ("jailbreak-dan",          re.compile(r"\bDAN\b"), 0.85),
    ("do-anything-now",        re.compile(r"do\s+anything\s+now", re.I), 0.85),
    ("jailbreak-dev-mode",     re.compile(r"developer\s+mode\s+(enabled|on|activated)", re.I), 0.85),
    ("jailbreak-no-filters",   re.compile(r"without\s+(any\s+)?(restrictions?|filters?|limitations?|safety\s+checks?)", re.I), 0.65),
    ("jailbreak-training",     re.compile(r"your\s+(training|programming|safety\s+constraints?)\s+(doesn'?t\s+apply|can\s+be\s+(ignored|overridden))", re.I), 0.80),
    # Indirect / second-order
    ("when-you-read-this",     re.compile(r"when\s+you\s+read\s+this", re.I), 0.60),
    ("if-you-see-this",        re.compile(r"if\s+you\s+(see|read|process)\s+this", re.I), 0.55),
    ("hidden-instruction",     re.compile(r"hidden\s+(instruction|command|directive)", re.I), 0.70),
    # Boundary breakout — content trying to open/close shield's <untrusted_*>
    # wrapper tags to escape the trust boundary. Scan raw text BEFORE wrapping;
    # wrapped output contains these tags legitimately.
    ("untrusted-tag-breakout", re.compile(r"[<＜]\s*/?\s*untrusted[\w-]*", re.I), 0.85),
]


_EXCERPT_RADIUS = 60


def _match_context(text: str, start: int, end: int) -> str:
    lo = max(0, start - _EXCERPT_RADIUS)
    hi = min(len(text), end + _EXCERPT_RADIUS)
    pre = "…" if lo > 0 else ""
    post = "…" if hi < len(text) else ""
    return pre + re.sub(r"\s+", " ", text[lo:hi]).strip() + post


def detect_injection(text: str, threshold: float = 0.5) -> InjectionScan:
    matches: list[str] = []
    excerpts: list[dict] = []
    max_weight = 0.0

    for label, pattern, weight in _PATTERNS:
        m = pattern.search(text)
        if m:
            matches.append(label)
            excerpts.append({"pattern": label, "excerpt": _match_context(text, m.start(), m.end())})
            if weight > max_weight:
                max_weight = weight

    if not matches:
        score = 0.0
    else:
        score = min(1.0, max_weight + (len(matches) - 1) * 0.05)

    return InjectionScan(score=score, matches=matches, flagged=score >= threshold, excerpts=excerpts)


def scan_detail(text: str, scan: InjectionScan) -> str:
    """
    Event detail line for a flagged scan: context around each match instead of
    the head of the message — the first 200 chars of a long fetched page often
    don't include the injection at all, which makes the log useless for triage.
    """
    if not scan.excerpts:
        return text[:200]
    return " | ".join(f"[{e['pattern']}] {e['excerpt']}" for e in scan.excerpts)[:200]
