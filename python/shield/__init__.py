"""
shield — prompt injection defense for Python LLM apps.

Quick start:
    from shield import ShieldAnthropicClient, detect_injection, wrap_untrusted
    import anthropic

    client = ShieldAnthropicClient(anthropic.Anthropic(), app_label="my-app")
    # Use client.messages.create() / .stream() exactly as before.
"""

from .detect import detect_injection, scan_detail, normalize_for_scan, InjectionScan, PATTERN_COUNT, MAX_SCAN_CHARS
from .core import (
    SHIELD_VERSION,
    announce_shield,
    sanitize_untrusted,
    normalize_label,
    wrap_untrusted,
    harden_system_prompt,
    output_leaked_canary,
    generate_canary,
)
from .headless import (
    HeadlessProcess,
    match_headless,
    scan_headless_processes,
    scan_and_report,
)
from .logger import emit_event, on_event, off_event, read_events
from .wrappers import ShieldAnthropicClient, ShieldOpenAIClient, ShieldCoverageError, shield_anthropic, shield_openai
from .stream_tools import ShieldBlockedToolError
from .output import (
    ToolSchema,
    ToolParamSchema,
    validate_tool_arguments,
    OutputScan,
    OutputFinding,
    ToolCall,
    ToolPolicy,
    ToolArgumentRule,
    ToolDecision,
    scan_output,
    output_detail,
    evaluate_tool_call,
    SECRET_PATTERNS,
    PII_PATTERNS,
)
from .instance import Shield, create_shield, get_default_shield
from .detectors import (
    Detector,
    DetectorContext,
    DetectorFinding,
    run_detectors,
    run_detectors_async,
)

__version__ = SHIELD_VERSION

__all__ = [
    "SHIELD_VERSION",
    "__version__",
    "announce_shield",
    "detect_injection",
    "scan_detail",
    "normalize_for_scan",
    "InjectionScan",
    "PATTERN_COUNT",
    "MAX_SCAN_CHARS",
    "sanitize_untrusted",
    "normalize_label",
    "wrap_untrusted",
    "harden_system_prompt",
    "output_leaked_canary",
    "generate_canary",
    "emit_event",
    "on_event",
    "off_event",
    "read_events",
    "HeadlessProcess",
    "match_headless",
    "scan_headless_processes",
    "scan_and_report",
    "ShieldAnthropicClient",
    "ShieldOpenAIClient",
    "ShieldCoverageError",
    "shield_anthropic",
    "shield_openai",
    "OutputScan",
    "OutputFinding",
    "ToolCall",
    "ToolPolicy",
    "ToolArgumentRule",
    "ToolDecision",
    "scan_output",
    "output_detail",
    "evaluate_tool_call",
    "SECRET_PATTERNS",
    "PII_PATTERNS",
    "Shield",
    "create_shield",
    "get_default_shield",
    "ShieldBlockedToolError",
    "ToolSchema",
    "ToolParamSchema",
    "validate_tool_arguments",
    "Detector",
    "DetectorContext",
    "DetectorFinding",
    "run_detectors",
    "run_detectors_async",
]
