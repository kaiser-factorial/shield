"""
Output-side pipeline — what the model SAID and what it wants to DO.
Mirrors src/output.ts.

    scan_output(text, ...)        -> OutputScan   (secrets, PII, exfil URLs, echo, canary)
    evaluate_tool_call(call, ...) -> ToolDecision (allow / flag / block by policy)

Pure and zero-dependency. Every regex is bounded.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import unquote
from typing import Any, Callable, Optional, Sequence

from .detect import InjectionScan, detect_injection
from .core import output_leaked_canary

# ── findings ─────────────────────────────────────────────────────────────────


@dataclass
class OutputFinding:
    label: str          # "secret:aws-access-key", "pii:email", "exfil:beacon-url", "echo:<pattern>"
    category: str       # canary | secret | pii | exfil | echo
    weight: float
    excerpt: str        # ±60 chars around the match (secrets masked)
    index: int          # 0-based char offset, -1 when withheld


@dataclass
class OutputScan:
    score: float
    flagged: bool
    findings: list[OutputFinding] = field(default_factory=list)

    @property
    def matches(self) -> list[str]:
        return [f.label for f in self.findings]


_EXCERPT_RADIUS = 60


def _excerpt_at(text: str, index: int, length: int, mask: bool = False) -> str:
    lo = max(0, index - _EXCERPT_RADIUS)
    hi = min(len(text), index + length + _EXCERPT_RADIUS)
    body = text[lo:hi]
    if mask:
        hit = text[index:index + length]
        masked = "*" * len(hit) if len(hit) <= 8 else hit[:4] + "…" + hit[-2:]
        body = body.replace(hit, masked, 1)
    body = re.sub(r"\s+", " ", body).strip()
    return ("…" if lo > 0 else "") + body + ("…" if hi < len(text) else "")


# ── secrets ──────────────────────────────────────────────────────────────────

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    ("aws-access-key",    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), 0.95),
    ("aws-secret-key",    re.compile(r"\baws_?secret(?:_access)?_?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b", re.I), 0.95),
    ("github-token",      re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"), 0.95),
    ("openai-key",        re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"), 0.90),
    ("anthropic-key",     re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), 0.95),
    ("slack-token",       re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), 0.90),
    ("google-api-key",    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0.90),
    ("stripe-key",        re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}\b"), 0.90),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"), 1.0),
    ("jwt",               re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), 0.80),
    ("bearer-token",      re.compile(r"\bBearer\s+[A-Za-z0-9._-]{24,}\b"), 0.70),
    ("generic-api-key",   re.compile(r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+_.=-]{16,})", re.I), 0.75),
    ("connection-string", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]{1,64}:[^\s@/]{1,128}@", re.I), 0.90),
]

# ── PII ──────────────────────────────────────────────────────────────────────


def _luhn_valid(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _card_ok(m: re.Match[str]) -> bool:
    d = re.sub(r"\D", "", m.group(0))
    return 13 <= len(d) <= 19 and _luhn_valid(d)


PII_PATTERNS: list[tuple[str, re.Pattern[str], float, Optional[Callable[[re.Match[str]], bool]]]] = [
    ("email",       re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b"), 0.50, None),
    ("phone",       re.compile(r"(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"), 0.40, None),
    ("ssn",         re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), 0.80, None),
    ("credit-card", re.compile(r"\b(?:\d[ -]?){13,19}\b"), 0.85, _card_ok),
    ("iban",        re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}[ ]?[A-Z0-9]{1,4}\b"), 0.60, None),
]

# ── refusal ──────────────────────────────────────────────────────────────────

# The model declining, or reporting that it was asked to do something it
# shouldn't. On its own this is ordinary — models refuse all day — so the
# weight sits below the flag threshold and it only surfaces in combination.
# The pairing is what matters: a refusal in the same turn that untrusted
# content was flagged is the shape of a probe the model caught.
REFUSAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("declined",        re.compile(r"\bI\s+(?:can(?:'|\u2019)?t|cannot|am\s+unable\s+to|won(?:'|\u2019)?t|will\s+not)\b[^.!?\n]{0,60}?\b(?:help|assist|comply|do\s+that|provide|share|reveal|continue|follow)\b", re.I)),
    ("apologetic",      re.compile(r"\bI(?:'|\u2019)?m\s+(?:sorry|afraid)\b[^.!?\n]{0,40}?\b(?:can(?:'|\u2019)?t|cannot|unable|not\s+able)\b", re.I)),
    ("must-decline",    re.compile(r"\bI\s+(?:must|have\s+to|will)\s+(?:decline|refuse)\b", re.I)),
    ("against-policy",  re.compile(r"\b(?:that|this|it)\s+(?:would\s+)?(?:violate|goes?\s+against|conflicts?\s+with)\b[^.!?\n]{0,40}?\b(?:polic|guideline|instruction|constraint)", re.I)),
    # The model naming the attack: the content carried instructions and it noticed.
    ("reported-injection", re.compile(r"\b(?:this|the)\s+(?:message|text|content|page|document|tool\s+result|input)\b[^.!?\n]{0,60}?\b(?:appears\s+to\s+)?(?:contain|include)s?\b[^.!?\n]{0,40}?\b(?:prompt\s+injection|injected\s+instruction|hidden\s+instruction|embedded\s+instruction)", re.I)),
]

# ── exfiltration ─────────────────────────────────────────────────────────────

_URL_RE = re.compile(r"\b(?:https?:)?//([A-Za-z0-9.-]{1,253})(?::\d{1,5})?(/[^\s)<>\"'\]]{0,2048})?")
_MD_IMAGE_RE = re.compile(r"!\[[^\]\n]{0,200}\]\(\s*((?:https?:)?//[^)\s]{1,2048})\s*\)")
_HTML_IMG_RE = re.compile(r"<img\b[^>]{0,500}?\bsrc\s*=\s*[\"']?((?:https?:)?//[^\"'\s>]{1,2048})", re.I)
_MAILTO_RE = re.compile(r"\bmailto:[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}", re.I)
_OPAQUE_RE = re.compile(r"[A-Za-z0-9+/=_-]{32,}")


def _host_allowed(host: str, allowed: Optional[Sequence[str]]) -> bool:
    if not allowed:
        return False
    h = host.lower()
    return any(h == a.lower() or h.endswith("." + a.lower()) for a in allowed)


def _host_of(url: str) -> str:
    return re.sub(r"^(?:https?:)?//", "", url).split("/")[0].split("?")[0].split("#")[0].split(":")[0]


def _opaque_query(path: Optional[str]) -> bool:
    if not path or "?" not in path:
        return False
    q = path.split("?", 1)[1]
    return len(q) >= 48 or bool(_OPAQUE_RE.search(q))


_NORM_RE = re.compile(r"[^a-z0-9]", re.I)


def _norm(s: str) -> str:
    return _NORM_RE.sub("", s).lower()


# ── main scanner ─────────────────────────────────────────────────────────────


def scan_output(
    text: str,
    *,
    canary: Optional[str] = None,
    input_scans: Optional[Sequence[InjectionScan]] = None,
    allowed_hosts: Optional[Sequence[str]] = None,
    detectors: Optional[dict[str, bool]] = None,
    threshold: float = 0.5,
    secrets: Optional[Sequence[str]] = None,
) -> OutputScan:
    """
    Scan model output for leaked secrets, PII, exfiltration channels, echoed
    injections and the canary. Excerpts of secrets are masked; registered
    `secrets` are never echoed into findings at all.
    """
    findings: list[OutputFinding] = []
    detectors = detectors or {}

    def on(cat: str) -> bool:
        return detectors.get(cat, True)

    raw = text if isinstance(text, str) else str(text or "")
    limit = 512 * 1024
    scanned = raw if len(raw) <= limit else raw[: limit // 2] + "\n…\n" + raw[-(limit // 2):]

    if on("canary") and canary and output_leaked_canary(scanned, canary):
        i = max(0, scanned.find(canary))
        findings.append(OutputFinding("canary:leaked", "canary", 1.0, _excerpt_at(scanned, i, len(canary), True), i))

    if on("secret"):
        for label, pat, weight in SECRET_PATTERNS:
            m = pat.search(scanned)
            if m:
                findings.append(OutputFinding(f"secret:{label}", "secret", weight,
                                              _excerpt_at(scanned, m.start(), m.end() - m.start(), True), m.start()))
        if secrets:
            n = _norm(scanned)
            for raw_secret in secrets:
                s = _norm(raw_secret)
                if len(s) >= 8 and s in n:
                    findings.append(OutputFinding("secret:registered", "secret", 1.0,
                                                  "(registered secret — value withheld)", -1))
                    break

    if on("pii"):
        for label, pat, weight, validate in PII_PATTERNS:
            for m in pat.finditer(scanned):
                if validate and not validate(m):
                    continue
                findings.append(OutputFinding(f"pii:{label}", "pii", weight,
                                              _excerpt_at(scanned, m.start(), m.end() - m.start(), True), m.start()))
                break

    if on("exfil"):
        seen: set[str] = set()

        def report(label: str, weight: float, index: int, length: int) -> None:
            key = f"{label}@{index}"
            if key in seen:
                return
            seen.add(key)
            findings.append(OutputFinding(f"exfil:{label}", "exfil", weight, _excerpt_at(scanned, index, length), index))

        for m in _MD_IMAGE_RE.finditer(scanned):
            ok = _host_allowed(_host_of(m.group(1)), allowed_hosts)
            report("markdown-image" if ok else "markdown-image-beacon", 0.3 if ok else 0.85, m.start(), m.end() - m.start())
        for m in _HTML_IMG_RE.finditer(scanned):
            if not _host_allowed(_host_of(m.group(1)), allowed_hosts):
                report("html-image-beacon", 0.85, m.start(), m.end() - m.start())
        for m in _URL_RE.finditer(scanned):
            if _host_allowed(m.group(1), allowed_hosts):
                continue
            if _opaque_query(m.group(2)):
                report("beacon-url", 0.8, m.start(), m.end() - m.start())
            elif allowed_hosts:
                report("unlisted-host", 0.4, m.start(), m.end() - m.start())
        for m in _MAILTO_RE.finditer(scanned):
            report("mailto", 0.4, m.start(), m.end() - m.start())

    if on("refusal"):
        after_flagged = any(s.flagged for s in (input_scans or []))
        for label, pat in REFUSAL_PATTERNS:
            m = pat.search(scanned)
            if not m:
                continue
            findings.append(OutputFinding(
                f"refusal:{label}:after-flagged-input" if after_flagged else f"refusal:{label}",
                "refusal", 0.7 if after_flagged else 0.35,
                _excerpt_at(scanned, m.start(), m.end() - m.start()), m.start()))
            break  # one refusal finding is enough for triage

    if on("echo") and input_scans:
        probe = detect_injection(scanned, 0)
        input_patterns = {p for s in input_scans for p in s.matches}
        for e in probe.excerpts:
            if e["pattern"] in input_patterns:
                findings.append(OutputFinding(f"echo:{e['pattern']}", "echo", 0.7, e["excerpt"], e["index"]))

    unique: dict[str, OutputFinding] = {}
    for f in findings:
        unique.setdefault(f.label, f)
    fl = list(unique.values())

    # A registered secret must never reach a log through ANOTHER finding's
    # excerpt. Mask verbatim hits; withhold the excerpt entirely when only
    # the normalized form matches.
    if secrets:
        for f in fl:
            for raw_secret in secrets:
                if len(_norm(raw_secret)) < 8:
                    continue
                if raw_secret.lower() in f.excerpt.lower():
                    f.excerpt = re.sub(re.escape(raw_secret), "[secret]", f.excerpt, flags=re.I)
                elif _norm(raw_secret) in _norm(f.excerpt):
                    f.excerpt = "(excerpt withheld — contains a registered secret)"
    mx = max((f.weight for f in fl), default=0.0)
    score = 0.0 if not fl else min(1.0, mx + (len(fl) - 1) * 0.05)
    return OutputScan(score=score, flagged=score >= threshold, findings=fl)


def output_detail(scan: OutputScan) -> str:
    return " | ".join(f'[{f.label}] "{f.excerpt}"' for f in scan.findings)[:300]


# ── tool-call policy ─────────────────────────────────────────────────────────


@dataclass
class ToolCall:
    name: str
    input: Any = None
    id: Optional[str] = None


@dataclass
class ToolArgumentRule:
    pattern: re.Pattern[str]
    action: str                     # "block" | "flag"
    tool: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class ToolPolicy:
    allow: Optional[list[str]] = None
    deny: Optional[list[str]] = None
    side_effects: Optional[list[str]] = None
    block_side_effects_after_untrusted: bool = False
    argument_rules: list[ToolArgumentRule] = field(default_factory=list)
    #: Per-tool argument schemas. Stronger than `argument_rules` for the
    #: shapes that matter — a regex over serialized JSON cannot tell which
    #: field it matched, nor notice an argument that should not be there.
    schemas: list["ToolSchema"] = field(default_factory=list)
    allowed_hosts: Optional[list[str]] = None
    block_unlisted_hosts: bool = False



# ── per-tool argument schemas ────────────────────────────────────────────────


@dataclass
class ToolParamSchema:
    """
    A constraint on one tool argument. Mirrors src/output.ts.

    Deliberately not JSON Schema: shield ships no dependencies, and a full
    validator would be a large surface for the sake of keywords that do
    nothing for security. What is here is the set that stops the arguments an
    injected model actually reaches for — a path that escapes its directory, a
    URL pointing at someone else's host, a free-form string where an enum was
    expected, a number outside its range.
    """
    type: Optional[str] = None          # string|number|integer|boolean|object|array
    enum: Optional[list] = None
    pattern: Optional[re.Pattern] = None
    max_length: Optional[int] = None
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    format: Optional[str] = None        # "url" | "email" | "path"
    allowed_hosts: Optional[list[str]] = None
    allow_absolute: bool = False
    items: Optional["ToolParamSchema"] = None


@dataclass
class ToolSchema:
    tool: str
    properties: dict[str, ToolParamSchema] = field(default_factory=dict)
    required: list[str] = field(default_factory=list)
    #: Reject arguments not named in `properties`. Defaults to True: an
    #: argument nobody declared is exactly how an extra `path` or `url` gets
    #: smuggled into an otherwise ordinary call.
    additional_properties: bool = False
    #: Severity of a violation — a schema is an assertion about what the tool
    #: accepts, not a suggestion.
    action: str = "block"


_TRAVERSAL_RE = re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)")
_ABSOLUTE_RE = re.compile(r"^(?:[\\/]|[A-Za-z]:[\\/])")
_URL_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.-]*):", re.I)
_URL_HOST_RE = re.compile(r"^[a-z]+://([^/?#]+)", re.I)
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@.]+\.[^\s@]+$")


def _type_of(v: Any) -> str:
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    if isinstance(v, int) or isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if v is None:
        return "null"
    return type(v).__name__


def _check_param(name: str, value: Any, schema: ToolParamSchema) -> list[str]:
    out: list[str] = []
    actual = _type_of(value)

    if schema.type:
        if schema.type == "integer":
            ok = isinstance(value, int) and not isinstance(value, bool)
        else:
            ok = actual == schema.type
        if not ok:
            # A type mismatch makes every other check meaningless — report it
            # alone rather than piling on errors derived from the wrong type.
            return [f'"{name}" should be {schema.type}, got {actual}']

    if schema.enum is not None and value not in schema.enum:
        out.append(f'"{name}" is not one of the allowed values')

    if isinstance(value, str):
        if schema.max_length is not None and len(value) > schema.max_length:
            out.append(f'"{name}" is longer than {schema.max_length} characters')
        if schema.pattern is not None and not schema.pattern.search(value):
            out.append(f'"{name}" does not match the required pattern')
        if schema.format == "path":
            # Check the raw string AND its percent-decoded form: %2e%2e%2f is
            # the oldest way past a check that only looks at literal dots.
            try:
                decoded = unquote(value)
            except Exception:  # noqa: BLE001
                decoded = value
            if _TRAVERSAL_RE.search(value) or _TRAVERSAL_RE.search(decoded):
                out.append(f'"{name}" contains a path traversal segment')
            if not schema.allow_absolute and _ABSOLUTE_RE.search(value):
                out.append(f'"{name}" is an absolute path')
            if "\x00" in value:
                out.append(f'"{name}" contains a NUL byte')
        if schema.format == "url":
            m = _URL_SCHEME_RE.match(value)
            scheme = m.group(1).lower() if m else None
            if scheme not in ("http", "https"):
                # file:, data: and javascript: in a tool argument are not typos.
                out.append(f'"{name}" is not an http(s) URL')
            elif schema.allowed_hosts is not None:
                hm = _URL_HOST_RE.match(value)
                host = hm.group(1).split("@")[-1].split(":")[0] if hm else None
                if not host or not _host_allowed(host, schema.allowed_hosts):
                    out.append(f'"{name}" references unlisted host {host or "(unparseable)"}')
        if schema.format == "email" and not _EMAIL_RE.match(value):
            out.append(f'"{name}" is not an email address')

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if schema.minimum is not None and value < schema.minimum:
            out.append(f'"{name}" is below {schema.minimum}')
        if schema.maximum is not None and value > schema.maximum:
            out.append(f'"{name}" is above {schema.maximum}')

    if isinstance(value, list) and schema.items is not None:
        for i, el in enumerate(value):
            out.extend(_check_param(f"{name}[{i}]", el, schema.items))

    return out


def validate_tool_arguments(call: ToolCall, schema: ToolSchema) -> list[str]:
    """
    Validate a call's arguments against its schema; empty means it passed.

    Arguments that did not parse as JSON are themselves a violation: a schema
    that silently does not run is worse than no schema, because it reads as a
    check that passed.
    """
    inp = call.input

    if isinstance(inp, str):
        return ["arguments did not parse as JSON, so the schema could not be applied"]
    if inp is None:
        return ([f'arguments are missing ({", ".join(schema.required)} required)']
                if schema.required else [])
    if not isinstance(inp, dict):
        return [f"arguments should be an object, got {_type_of(inp)}"]

    out: list[str] = []
    props = schema.properties or {}

    for name in schema.required:
        if name not in inp or inp[name] is None:
            out.append(f'"{name}" is required but missing')

    if not schema.additional_properties:
        for name in inp:
            if name not in props:
                out.append(f'"{name}" is not a declared argument of {call.name}')

    for name, param in props.items():
        if name not in inp or inp[name] is None:
            continue
        out.extend(_check_param(name, inp[name], param))

    return out


@dataclass
class ToolDecision:
    decision: str                   # "allow" | "flag" | "block"
    reasons: list[str]
    call: ToolCall


def _args_text(inp: Any) -> str:
    if isinstance(inp, str):
        return inp
    try:
        return json.dumps(inp if inp is not None else "")
    except (TypeError, ValueError):
        return str(inp)


def evaluate_tool_call(
    call: ToolCall,
    policy: Optional[ToolPolicy] = None,
    *,
    untrusted_input_seen: bool = False,
    input_scans: Optional[Sequence[InjectionScan]] = None,
) -> ToolDecision:
    """Decide whether a model-requested tool call should proceed. Pure."""
    policy = policy or ToolPolicy()
    reasons: list[str] = []
    decision = "allow"

    def escalate(to: str, why: str) -> None:
        nonlocal decision
        reasons.append(why)
        if to == "block" or (to == "flag" and decision == "allow"):
            decision = to

    if policy.deny and call.name in policy.deny:
        escalate("block", f'tool "{call.name}" is denied by policy')
    if policy.allow is not None and call.name not in policy.allow:
        escalate("block", f'tool "{call.name}" is not on the allow list')

    flagged_input = any(s.flagged for s in (input_scans or []))
    untrusted = untrusted_input_seen or flagged_input
    if policy.side_effects and call.name in policy.side_effects and untrusted:
        escalate("block" if policy.block_side_effects_after_untrusted else "flag",
                 f'side-effecting tool "{call.name}" requested after untrusted input'
                 + (" that was flagged for injection" if flagged_input else ""))

    text = _args_text(call.input)
    for rule in policy.argument_rules:
        if rule.tool and rule.tool != call.name:
            continue
        if rule.pattern.search(text):
            escalate(rule.action, rule.reason or f"argument rule matched: {rule.pattern.pattern}")

    for schema in policy.schemas:
        if schema.tool != call.name:
            continue
        for v in validate_tool_arguments(call, schema):
            escalate(schema.action, f"schema: {v}")

    if policy.allowed_hosts is not None:
        for m in _URL_RE.finditer(text):
            if not _host_allowed(m.group(1), policy.allowed_hosts):
                escalate("block" if policy.block_unlisted_hosts else "flag",
                         f"argument references unlisted host {m.group(1)}")
                break

    return ToolDecision(decision=decision, reasons=reasons, call=call)
