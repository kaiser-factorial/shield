"""
SDK wrappers — drop-in replacements for anthropic.Anthropic and openai.OpenAI
that auto-harden, auto-detect, and log injection events.
"""
from __future__ import annotations

from typing import Any, Iterator, Optional

from .core import (
    announce_shield,
    generate_canary,
    harden_system_prompt,
    output_leaked_canary,
    security_boilerplate,
    wrap_untrusted,
)
from .detect import detect_injection, scan_detail
from .logger import emit_event


def _extract_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(
            part.get("text", "") if isinstance(part, dict) else str(part)
            for part in content
            if isinstance(part, dict) and part.get("type") == "text"
        )
    return str(content or "")


def _harden_system(system: Any) -> tuple[Any, str]:
    """
    Harden a system prompt of any legal shape.
    - str (or None): append boilerplate as before.
    - list of blocks: append the boilerplate as a NEW text block so existing
      blocks (incl. cache_control markers) are preserved. (Previously a
      list-form system prompt was silently replaced with just the boilerplate.)
    - anything else: pass through untouched rather than destroy it.
    """
    if system is None or isinstance(system, str):
        return harden_system_prompt(system or "")
    if isinstance(system, list):
        seed = "\n".join(
            b["text"]
            for b in system
            if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)
        )
        canary = generate_canary(seed)
        return [*system, {"type": "text", "text": security_boilerplate(canary)}], canary
    return system, generate_canary(str(system))


def _wrap_content_text(content: Any, label: str) -> Any:
    """
    Wrap the text of a message while PRESERVING non-text blocks
    (images, audio, …). Previously the whole content list was
    flattened to a single wrapped string.
    """
    if isinstance(content, str):
        return wrap_untrusted(content, label)
    if isinstance(content, list):
        return [
            {**b, "text": wrap_untrusted(b["text"], label)}
            if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)
            else b
            for b in content
        ]
    return content


def _wrap_user_content(content: Any) -> Any:
    return _wrap_content_text(content, "user_message")


def _extract_tool_result_text(content: Any) -> str:
    """
    Text carried inside tool_result blocks of a user message. Tool results are
    where fetched pages, file contents, and search output enter the context —
    the primary indirect-injection channel — so they get their own extraction
    (and their own event source qualifier) instead of riding along with typed
    user text.
    """
    if not isinstance(content, list):
        return ""
    parts = []
    for b in content:
        if isinstance(b, dict) and b.get("type") == "tool_result":
            inner = b.get("content")
            text = inner if isinstance(inner, str) else _extract_text(inner)
            if text:
                parts.append(text)
    return " ".join(parts)


def _wrap_tool_result_blocks(content: Any) -> Any:
    """
    Wrap the text inside tool_result blocks as <untrusted_tool_result> while
    preserving block structure (string content stays a string, image blocks
    inside list-form content are untouched).
    """
    if not isinstance(content, list):
        return content
    wrapped = []
    for b in content:
        if isinstance(b, dict) and b.get("type") == "tool_result":
            inner = b.get("content")
            if isinstance(inner, str):
                b = {**b, "content": wrap_untrusted(inner, "tool_result")}
            elif isinstance(inner, list):
                b = {**b, "content": _wrap_content_text(inner, "tool_result")}
        wrapped.append(b)
    return wrapped


class ShieldAnthropicClient:
    """
    Drop-in wrapper around anthropic.Anthropic.

    Usage:
        import anthropic
        from shield import ShieldAnthropicClient

        client = ShieldAnthropicClient(anthropic.Anthropic(), app_label="wearabLLM")
        # Use client.messages.create / client.messages.stream exactly as before
    """

    def __init__(
        self,
        inner: Any,
        *,
        app_label: str = "shield",
        wrap_user_messages: bool = False,
        wrap_tool_results: bool = True,
        announce: bool = True,
    ):
        self._inner = inner
        self._app_label = app_label
        self._wrap = wrap_user_messages
        # Tool results are machine-fetched external content — the main indirect
        # injection vector in agentic apps — so unlike user messages, wrapping
        # them defaults to ON. Detection scanning of tool results is always on.
        self._wrap_tools = wrap_tool_results
        announce_shield(app_label, wrap_user_messages=wrap_user_messages, banner=announce)

    # ── messages proxy ────────────────────────────────────────────────────────

    @property
    def messages(self) -> "_MessagesProxy":
        return _MessagesProxy(self._inner.messages, self._app_label, self._wrap, self._wrap_tools)

    # Passthrough for everything else on the inner client
    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _MessagesProxy:
    def __init__(self, inner_messages: Any, app_label: str, wrap: bool, wrap_tools: bool = True):
        self._m = inner_messages
        self._label = app_label
        self._wrap = wrap
        self._wrap_tools = wrap_tools

    def _prepare(self, kwargs: dict) -> tuple[dict, str]:
        hardened, canary = _harden_system(kwargs.get("system"))
        kwargs = {**kwargs, "system": hardened}

        messages = kwargs.get("messages", [])
        new_messages = []
        for m in messages:
            if m.get("role") == "user":
                text = _extract_text(m.get("content", ""))
                scan = detect_injection(text)
                if scan.flagged:
                    emit_event(
                        "injection_detected",
                        source=self._label,
                        detail=scan_detail(text, scan),
                        score=scan.score,
                        patterns=scan.matches,
                    )

                # Tool results carry external content (fetched pages, files,
                # search output) — scan them always, with a source qualifier
                # so `shield logs` shows where the injection came in.
                tool_text = _extract_tool_result_text(m.get("content"))
                if tool_text:
                    tool_scan = detect_injection(tool_text)
                    if tool_scan.flagged:
                        emit_event(
                            "injection_detected",
                            source=f"{self._label}:tool_result",
                            detail=scan_detail(tool_text, tool_scan),
                            score=tool_scan.score,
                            patterns=tool_scan.matches,
                        )

                content = m.get("content", "")
                if self._wrap_tools:
                    content = _wrap_tool_result_blocks(content)
                if self._wrap:
                    content = _wrap_user_content(content)
                if content is not m.get("content", ""):
                    m = {**m, "content": content}
            new_messages.append(m)
        kwargs["messages"] = new_messages
        return kwargs, canary

    def _check_canary(self, response: Any, canary: str) -> None:
        content = getattr(response, "content", None)
        if not content:
            return
        text = "".join(
            getattr(b, "text", "") for b in content if getattr(b, "type", None) == "text"
        )
        if output_leaked_canary(text, canary):
            emit_event("canary_leaked", source=self._label, detail=text[:200])
            print(f"[shield] WARNING: canary leaked in response from {self._label}")

    def create(self, **kwargs: Any) -> Any:
        prepared, canary = self._prepare(kwargs)
        response = self._m.create(**prepared)
        self._check_canary(response, canary)
        return response

    def stream(self, **kwargs: Any) -> Any:
        """Returns a context manager identical to anthropic's messages.stream."""
        prepared, _canary = self._prepare(kwargs)
        # We don't check the canary on streaming responses (would need to buffer
        # the whole stream — too expensive). Detection on input is the main guard.
        return self._m.stream(**prepared)

    def parse(self, **kwargs: Any) -> Any:
        """Pass-through for SDK helpers like messages.parse with zodOutputFormat."""
        prepared, canary = self._prepare(kwargs)
        response = self._m.parse(**prepared)
        self._check_canary(response, canary)
        return response

    # Passthrough for anything else
    def __getattr__(self, name: str) -> Any:
        return getattr(self._m, name)


class ShieldOpenAIClient:
    """
    Drop-in wrapper around openai.OpenAI (or any OpenAI-compatible client).

    Usage:
        import openai
        from shield import ShieldOpenAIClient

        client = ShieldOpenAIClient(openai.OpenAI(api_key=key), app_label="wearabLLM")
        resp = client.chat.completions.create(model=..., messages=...)
    """

    def __init__(
        self,
        inner: Any,
        *,
        app_label: str = "shield",
        wrap_user_messages: bool = False,
        wrap_tool_results: bool = True,
        announce: bool = True,
    ):
        self._inner = inner
        self._app_label = app_label
        self._wrap = wrap_user_messages
        # Tool results are machine-fetched external content — the main indirect
        # injection vector in agentic apps — so unlike user messages, wrapping
        # them defaults to ON. Detection scanning of tool messages is always on.
        self._wrap_tools = wrap_tool_results
        announce_shield(app_label, wrap_user_messages=wrap_user_messages, banner=announce)

    @property
    def chat(self) -> "_ChatProxy":
        return _ChatProxy(self._inner.chat, self._app_label, self._wrap, self._wrap_tools)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _ChatProxy:
    def __init__(self, inner_chat: Any, app_label: str, wrap: bool, wrap_tools: bool = True):
        self._c = inner_chat
        self._label = app_label
        self._wrap = wrap
        self._wrap_tools = wrap_tools

    @property
    def completions(self) -> "_CompletionsProxy":
        return _CompletionsProxy(self._c.completions, self._label, self._wrap, self._wrap_tools)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._c, name)


class _CompletionsProxy:
    def __init__(self, inner: Any, app_label: str, wrap: bool, wrap_tools: bool = True):
        self._c = inner
        self._label = app_label
        self._wrap = wrap
        self._wrap_tools = wrap_tools

    def _prepare(self, kwargs: dict) -> tuple[dict, str]:
        messages = list(kwargs.get("messages", []))
        # Harden the FIRST system (or developer — the newer OpenAI equivalent)
        # message in place; any later system messages pass through untouched.
        # Multiple system messages are legal, and replacing them all with the
        # hardened first one (the old behavior) silently destroyed their content.
        sys_idx = next(
            (i for i, m in enumerate(messages) if m.get("role") in ("system", "developer")),
            None,
        )
        sys_msg = messages[sys_idx] if sys_idx is not None else None
        hardened, canary = _harden_system(sys_msg.get("content") if sys_msg else None)

        new_messages = []
        for i, m in enumerate(messages):
            if i == sys_idx:
                m = {**m, "content": hardened}
            elif m.get("role") == "user":
                text = _extract_text(m.get("content", ""))
                scan = detect_injection(text)
                if scan.flagged:
                    emit_event("injection_detected", source=self._label,
                               detail=scan_detail(text, scan), score=scan.score, patterns=scan.matches)
                if self._wrap:
                    m = {**m, "content": _wrap_user_content(m.get("content", ""))}
            elif m.get("role") == "tool":
                # Tool results carry external content (fetched pages, files,
                # search output) — the primary indirect-injection channel.
                # Always scan; wrap unless explicitly disabled.
                content = m.get("content", "")
                text = content if isinstance(content, str) else _extract_text(content)
                scan = detect_injection(text)
                if scan.flagged:
                    emit_event("injection_detected", source=f"{self._label}:tool_result",
                               detail=scan_detail(text, scan), score=scan.score, patterns=scan.matches)
                if self._wrap_tools:
                    m = {**m, "content": _wrap_content_text(content, "tool_result")}
            new_messages.append(m)

        # No system/developer message in the request: the hardened prompt
        # would otherwise never reach the model (and the canary would be an
        # orphan) — prepend it.
        if sys_idx is None:
            new_messages.insert(0, {"role": "system", "content": hardened})

        return {**kwargs, "messages": new_messages}, canary

    def create(self, **kwargs: Any) -> Any:
        prepared, canary = self._prepare(kwargs)
        response = self._c.create(**prepared)
        if hasattr(response, "choices"):
            text = "".join(
                c.message.content or "" for c in response.choices
                if hasattr(c, "message") and c.message
            )
            if output_leaked_canary(text, canary):
                emit_event("canary_leaked", source=self._label, detail=text[:200])
                print(f"[shield] WARNING: canary leaked in response from {self._label}")
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._c, name)
