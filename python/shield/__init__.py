"""
shield — prompt injection defense for Python LLM apps.

Quick start:
    from shield import ShieldAnthropicClient, detect_injection, wrap_untrusted
    import anthropic

    client = ShieldAnthropicClient(anthropic.Anthropic(), app_label="my-app")
    # Use client.messages.create() / .stream() exactly as before.
"""

from .detect import detect_injection, InjectionScan
from .core import (
    sanitize_untrusted,
    wrap_untrusted,
    harden_system_prompt,
    output_leaked_canary,
    generate_canary,
)
from .logger import emit_event
from .wrappers import ShieldAnthropicClient, ShieldOpenAIClient

__all__ = [
    "detect_injection",
    "InjectionScan",
    "sanitize_untrusted",
    "wrap_untrusted",
    "harden_system_prompt",
    "output_leaked_canary",
    "generate_canary",
    "emit_event",
    "ShieldAnthropicClient",
    "ShieldOpenAIClient",
]
