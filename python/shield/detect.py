"""
Prompt injection detection — same 30 patterns as the TypeScript version.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field


@dataclass
class InjectionScan:
    score: float
    matches: list[str]
    flagged: bool
    # Context around each match — what actually tripped the pattern, for
    # triage. Each entry: {"pattern": label, "excerpt": "…", "line": 1-based
    # line in the normalized text, "index": 0-based char offset in it}.
    excerpts: list[dict] = field(default_factory=list)
    # True when the input exceeded MAX_SCAN_CHARS and only head+tail were scanned.
    truncated: bool = False


# Zero-width / invisible format characters. Models ignore them; regexes don't.
# Stripped before scanning, and tolerated inside the tag-breakout matcher so a
# closing tag padded with U+200B can't slip past the sanitizer.
_ZERO_WIDTH_CLASS = "\u00ad\u200b-\u200f\u2060-\u2064\ufeff"
_ZERO_WIDTH_RE = re.compile(f"[{_ZERO_WIDTH_CLASS}]")
_ZW = f"[{_ZERO_WIDTH_CLASS}]*"

# Bounded quantifiers only: `\s*` next to another `\s*` (or after a multiline
# `^`, where \s also eats newlines) was quadratic — 40k whitespace chars took
# half a minute here, on attacker-controlled input.
TAG_BREAKOUT_SRC = (
    f"[<＜][ \\t{_ZERO_WIDTH_CLASS}]{{0,16}}/?[ \\t{_ZERO_WIDTH_CLASS}]{{0,16}}"
    + _ZW.join("untrusted")
    + r"[\w-]*"
)

_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    # Override attempts
    ("ignore-instructions",    re.compile(r"ignore\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|rules?|prompts?|directives?)", re.I), 0.90),
    ("forget-instructions",    re.compile(r"forget\s+(everything|all\s+instructions?|your\s+instructions?)", re.I), 0.90),
    ("disregard-instructions", re.compile(r"disregard\s+(all\s+)?(previous|prior|your)\s+(instructions?|rules?)", re.I), 0.85),
    ("new-instructions",       re.compile(r"new\s+(instructions?|directive|rules?|orders?)\s*:", re.I), 0.75),
    ("override-instructions",  re.compile(r"override\s+(your\s+)?(instructions?|rules?|programming)", re.I), 0.85),
    # Role hijacking. "act as" / "roleplay as" / "what are your rules" are
    # everyday phrasing, so they sit below the 0.5 threshold and only flag when
    # they co-occur with something stronger.
    ("you-are-now",            re.compile(r"you\s+are\s+now\s+(a|an|the)\s+\w", re.I), 0.70),
    ("act-as",                 re.compile(r"act\s+as\s+(a|an|the)\s+\w", re.I), 0.40),
    ("pretend-you-are",        re.compile(r"pretend\s+(you\s+are|to\s+be)\s+", re.I), 0.50),
    ("roleplay-as",            re.compile(r"roleplay\s+as\s+", re.I), 0.40),
    ("your-new-persona",       re.compile(r"your\s+(new\s+)?(persona|identity|role)\s+is", re.I), 0.70),
    # System prompt exposure
    ("reveal-system-prompt",   re.compile(r"reveal\s+(your\s+)?(system\s+prompt|instructions?|hidden\s+prompt)", re.I), 0.90),
    ("print-system-prompt",    re.compile(r"print\s+(your\s+)?(system\s+prompt|initial\s+prompt)", re.I), 0.85),
    ("what-is-your-system",    re.compile(r"what\s+(is|are)\s+your\s+(system\s+prompt|instructions?|rules?)", re.I), 0.45),
    ("repeat-above",           re.compile(r"repeat\s+(everything|all\s+(text|content|instructions?))\s+(above|before)", re.I), 0.75),
    ("encode-above",           re.compile(r"(encode|base64|rot13|translate)\s+(the\s+)?(above|previous|prior|system\s+prompt|your\s+instructions?)", re.I), 0.50),
    # Embedded role spoofing. After a multiline `^`, only horizontal whitespace.
    ("system-tag",             re.compile(r"^[ \t]*\[(system|admin|operator)\]", re.I | re.M), 0.80),
    ("system-colon",           re.compile(r"^[ \t]*(system|admin|operator)[ \t]*:[ \t]+", re.I | re.M), 0.70),
    ("xml-system-tag",         re.compile(r"<(system|instructions?|prompt)[ \t]{0,8}>", re.I), 0.75),
    ("chat-delimiter-spoof",   re.compile(r"<\|(im_start|im_end|system|user|assistant|endoftext|start_header_id|eot_id)\|>|\[INST\]|<<SYS>>", re.I), 0.80),
    # Jailbreak boilerplate
    # The acronym is case-SENSITIVE on purpose: jailbreak boilerplate writes
    # "DAN" in caps, while "Dan"/"dan" is overwhelmingly just someone's name.
    ("jailbreak-dan",          re.compile(r"\bDAN\b"), 0.85),
    ("do-anything-now",        re.compile(r"do\s+anything\s+now", re.I), 0.85),
    ("jailbreak-dev-mode",     re.compile(r"developer\s+mode\s+(enabled|on|activated)", re.I), 0.85),
    ("jailbreak-no-filters",   re.compile(r"without\s+(any\s+)?(restrictions?|filters?|limitations?|safety\s+checks?)", re.I), 0.65),
    ("jailbreak-training",     re.compile(r"your\s+(training|programming|safety\s+constraints?)\s+(doesn'?t\s+apply|can\s+be\s+(ignored|overridden))", re.I), 0.80),
    # Indirect / second-order
    ("when-you-read-this",     re.compile(r"when\s+you\s+read\s+this", re.I), 0.60),
    ("if-you-see-this",        re.compile(r"if\s+you\s+(see|read|process)\s+this", re.I), 0.55),
    ("hidden-instruction",     re.compile(r"hidden\s+(instruction|command|directive)", re.I), 0.70),
    # Exfiltration setup
    ("markdown-image-exfil",   re.compile(r"!\[[^\]\n]{0,200}\]\((?:https?:)?//[^)\s]{1,300}\?[^)\s]{16,}\)", re.I), 0.80),
    ("exfil-send-to",          re.compile(r"\b(send|post|email|forward|transmit|upload)\s+(this|it|them|the\s+(above|conversation|data|contents?|response|results?|history|document))\s+to\s+", re.I), 0.60),
    # Boundary breakout — scan raw text BEFORE wrapping; wrapped output
    # contains these tags legitimately.
    ("untrusted-tag-breakout", re.compile(TAG_BREAKOUT_SRC, re.I), 0.85),
]

PATTERN_COUNT = len(_PATTERNS)

_EXCERPT_RADIUS = 60

# Longest input the patterns are run against; beyond this, head + tail.
MAX_SCAN_CHARS = 512 * 1024

_SEPARATED_LETTERS_RE = re.compile(r"\b(?:[a-z][-._*~ ]){3,}[a-z]\b", re.I)
_SEPARATOR_RE = re.compile(r"[-._*~ ]")


def normalize_for_scan(text: str) -> str:
    """
    Canonicalize text before pattern matching so cheap evasions don't work:
    NFKC folds fullwidth/compatibility forms, zero-width characters are
    dropped, and single letters separated by one punctuation/space each
    ("i-g-n-o-r-e", "i g n o r e") are rejoined. Excerpt line/index values
    refer to this normalized text.
    """
    t = _ZERO_WIDTH_RE.sub("", unicodedata.normalize("NFKC", text))
    return _SEPARATED_LETTERS_RE.sub(lambda m: _SEPARATOR_RE.sub("", m.group(0)), t)


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

    scanned = normalize_for_scan(text if isinstance(text, str) else str(text or ""))
    truncated = False
    if len(scanned) > MAX_SCAN_CHARS:
        half = MAX_SCAN_CHARS // 2
        scanned = scanned[:half] + "\n…\n" + scanned[-half:]
        truncated = True

    for label, pattern, weight in _PATTERNS:
        m = pattern.search(scanned)
        if m:
            matches.append(label)
            excerpts.append({
                "pattern": label,
                "excerpt": _match_context(scanned, m.start(), m.end()),
                "line": scanned.count("\n", 0, m.start()) + 1,
                "index": m.start(),
            })
            if weight > max_weight:
                max_weight = weight

    if not matches:
        score = 0.0
    else:
        score = min(1.0, max_weight + (len(matches) - 1) * 0.05)

    return InjectionScan(score=score, matches=matches, flagged=score >= threshold,
                         excerpts=excerpts, truncated=truncated)


def scan_detail(text: str, scan: InjectionScan) -> str:
    """
    Event detail line for a flagged scan: context around each match instead of
    the head of the message — the first 200 chars of a long fetched page often
    don't include the injection at all, which makes the log useless for triage.
    """
    if not scan.excerpts:
        return text[:200]
    return " | ".join(f"[{e['pattern']} @L{e.get('line', '?')}] \"{e['excerpt']}\"" for e in scan.excerpts)[:300]
