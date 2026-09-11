"""
SDK wrappers — drop-in replacements for anthropic.Anthropic and openai.OpenAI
that auto-harden, auto-detect, and log injection events.

Coverage is deny-by-default. Before v1.5 every attribute the proxies didn't
know about was forwarded straight to the inner SDK, so
`client.chat.completions.parse(...)`, `client.responses.create(...)` and
`client.beta.messages.create(...)` reached the model with no hardening while
the startup banner said "shield active". Now each attribute reached through a
shielded client is one of:
  - intercepted  → shielded implementation,
  - allowed      → known not to send prompts to a model, forwarded as-is,
  - passthrough  → the consumer opted a surface out by name, forwarded as-is,
  - anything else → ShieldCoverageError naming the path.
"""
from __future__ import annotations

import inspect
from typing import Any, AsyncIterator, Callable, Iterator, Optional, Sequence

from .core import (
    generate_canary,
    harden_system_prompt,
    security_boilerplate,
    wrap_untrusted,
)
from .detect import InjectionScan
from .instance import Shield, create_shield
from .output import ToolCall
from .stream_tools import ShieldBlockedToolError, assembler_for


class ShieldCoverageError(AttributeError):
    """Raised when a shielded client is asked for a surface shield doesn't cover.

    Subclasses AttributeError so `hasattr(client, "beta")` is False rather than
    an exception — but a direct access still fails loudly.
    """

    def __init__(self, path: str):
        rel = path.split(".", 1)[1] if "." in path else path
        super().__init__(
            f'[shield] "{path}" is not covered by the shield wrapper. It may send prompts to the '
            f"model without hardening or scanning. Either use a covered surface, or opt out "
            f'explicitly with passthrough=["{rel}"] in the wrapper options.'
        )
        self.path = path


def _nested_passthrough(passthrough: Sequence[str], segment: str) -> list[str]:
    prefix = segment + "."
    return [p[len(prefix):] for p in passthrough if p.startswith(prefix)]


class _Guard:
    """Deny-by-default attribute proxy (see module docstring)."""

    def __init__(
        self,
        inner: Any,
        path: str,
        intercept: dict[str, Callable[[Any], Any]],
        allow: Sequence[str],
        passthrough: Sequence[str] = (),
    ):
        object.__setattr__(self, "_g_inner", inner)
        object.__setattr__(self, "_g_path", path)
        object.__setattr__(self, "_g_intercept", intercept)
        object.__setattr__(self, "_g_allow", set(allow))
        object.__setattr__(self, "_g_pass", {p.split(".", 1)[0] for p in passthrough})
        object.__setattr__(self, "_g_cache", {})

    def __getattr__(self, name: str) -> Any:
        inner = object.__getattribute__(self, "_g_inner")
        intercept = object.__getattribute__(self, "_g_intercept")
        cache = object.__getattribute__(self, "_g_cache")
        if name in intercept:
            if name not in cache:
                cache[name] = intercept[name](inner)
            return cache[name]
        if (
            name.startswith("_")
            or name in object.__getattribute__(self, "_g_allow")
            or name in object.__getattribute__(self, "_g_pass")
        ):
            return getattr(inner, name)
        raise ShieldCoverageError(f"{object.__getattribute__(self, '_g_path')}.{name}")

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_g_inner"), name, value)

    def __dir__(self):  # pragma: no cover - introspection nicety
        return sorted(set(dir(object.__getattribute__(self, "_g_inner")))
                      | set(object.__getattribute__(self, "_g_intercept")))

    def __repr__(self) -> str:
        return f"<shielded {object.__getattribute__(self, '_g_path')} of {object.__getattribute__(self, '_g_inner')!r}>"

    # Clients are context managers; dunders bypass __getattr__, so forward them.
    def __enter__(self) -> Any:
        object.__getattribute__(self, "_g_inner").__enter__()
        return self

    def __exit__(self, *exc: Any) -> Any:
        return object.__getattribute__(self, "_g_inner").__exit__(*exc)

    async def __aenter__(self) -> Any:
        await object.__getattribute__(self, "_g_inner").__aenter__()
        return self

    async def __aexit__(self, *exc: Any) -> Any:
        return await object.__getattribute__(self, "_g_inner").__aexit__(*exc)


# ── content helpers ──────────────────────────────────────────────────────────

def _parts_text(content: Any, text_types: Sequence[str] = ("text",)) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(
            part["text"]
            for part in content
            if isinstance(part, dict) and part.get("type") in text_types and isinstance(part.get("text"), str)
        )
    return "" if content is None else ""


def _extract_text(content: Any) -> str:
    return _parts_text(content, ("text",))


def _harden_system(system: Any, fixed_canary: Optional[str] = None) -> tuple[Any, str]:
    """
    Harden a system prompt of any legal shape.
    - str (or None): append boilerplate.
    - list of blocks: append the boilerplate as a NEW text block so existing
      blocks (incl. cache_control markers) are preserved.
    - anything else: pass through untouched rather than destroy it.
    """
    if system is None or isinstance(system, str):
        return harden_system_prompt(system or "", fixed_canary)
    if isinstance(system, list):
        seed = "\n".join(
            b["text"]
            for b in system
            if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)
        )
        canary = fixed_canary or generate_canary(seed)
        return [*system, {"type": "text", "text": security_boilerplate(canary)}], canary
    return system, fixed_canary or generate_canary(str(system))


def _wrap_content_text(content: Any, label: str, text_types: Sequence[str] = ("text",)) -> Any:
    """Wrap the text of a message while PRESERVING non-text blocks."""
    if isinstance(content, str):
        return wrap_untrusted(content, label)
    if isinstance(content, list):
        return [
            {**b, "text": wrap_untrusted(b["text"], label)}
            if isinstance(b, dict) and b.get("type") in text_types and isinstance(b.get("text"), str)
            else b
            for b in content
        ]
    return content


def _wrap_user_content(content: Any) -> Any:
    return _wrap_content_text(content, "user_message")


def _extract_tool_result_text(content: Any) -> str:
    """Text inside tool_result blocks — the primary indirect-injection channel."""
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


def _extract_document_text(content: Any) -> str:
    """Text of `document` blocks with an inline text source (never scanned before v1.5)."""
    if not isinstance(content, list):
        return ""
    out = []
    for b in content:
        if isinstance(b, dict) and b.get("type") == "document":
            src = b.get("source")
            if isinstance(src, dict) and src.get("type") == "text" and isinstance(src.get("data"), str):
                out.append(src["data"])
    return " ".join(out)


def _unscannable_documents(content: Any) -> list[str]:
    """
    Document sources shield cannot read: a PDF or image as base64, a remote
    URL, an uploaded file id. The bytes never reach the pattern layer, so a
    document block is NOT evidence that the document was checked.

    Returns a short description per unreadable source, for the
    `content_not_scanned` event. Silence here would be the worst outcome: an
    operator reading a clean log would reasonably conclude the PDF was scanned
    and found harmless, when in fact it was never opened.
    """
    if not isinstance(content, list):
        return []
    out: list[str] = []
    for b in content:
        if not isinstance(b, dict) or b.get("type") != "document":
            continue
        src = b.get("source")
        if not isinstance(src, dict):
            continue
        kind = src.get("type")
        if kind == "text":
            continue
        if kind == "base64":
            out.append(f'base64 {src.get("media_type") or "document"}')
        elif kind == "url":
            out.append(f'remote url {str(src.get("url") or "")[:120]}')
        elif kind == "file":
            out.append(f'uploaded file {src.get("file_id") or ""}')
        else:
            out.append(f'document source "{kind}"')
    return out


def _wrap_document_blocks(content: Any) -> Any:
    """
    Wrap the text inside document blocks as <untrusted_document>. A document
    is external content in exactly the way a tool result is; it was being
    scanned but not fenced, so an instruction inside it still read to the
    model as part of the user's own message.
    """
    if not isinstance(content, list):
        return content
    wrapped = []
    for b in content:
        if isinstance(b, dict) and b.get("type") == "document":
            src = b.get("source")
            if isinstance(src, dict) and src.get("type") == "text" and isinstance(src.get("data"), str):
                b = {**b, "source": {**src, "data": wrap_untrusted(src["data"], "document")}}
        wrapped.append(b)
    return wrapped


def _wrap_tool_result_blocks(content: Any) -> Any:
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


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _anthropic_delta_text(ev: Any) -> str:
    if _get(ev, "type") == "content_block_delta":
        delta = _get(ev, "delta")
        if _get(delta, "type") == "text_delta":
            return _get(delta, "text", "") or ""
    return ""


def _anthropic_response_text(response: Any) -> str:
    content = _get(response, "content") or []
    if not isinstance(content, list):
        return ""
    return "".join(_get(b, "text", "") or "" for b in content if _get(b, "type") == "text")


def _openai_chunk_text(ev: Any) -> str:
    choices = _get(ev, "choices")
    if not choices:
        return ""
    delta = _get(choices[0], "delta")
    return _get(delta, "content", "") or ""


def _openai_chat_helper_text(ev: Any) -> str:
    """ChatCompletionStream events: `content.delta` carries the text."""
    if _get(ev, "type") == "content.delta":
        return _get(ev, "delta", "") or ""
    return _openai_chunk_text(ev)


def _openai_completion_text(response: Any) -> str:
    choices = _get(response, "choices")
    if not choices:
        return ""
    out = []
    for c in choices:
        msg = _get(c, "message")
        if msg:
            out.append(_get(msg, "content", "") or "")
    return "".join(out)


def _responses_delta_text(ev: Any) -> str:
    if _get(ev, "type") == "response.output_text.delta":
        return _get(ev, "delta", "") or ""
    return ""


def _responses_output_text(response: Any) -> str:
    text = _get(response, "output_text")
    if isinstance(text, str) and text:
        return text
    items = _get(response, "output") or []
    out = []
    for item in items:
        if _get(item, "type") == "message":
            for part in _get(item, "content") or []:
                if _get(part, "type") == "output_text" and isinstance(_get(part, "text"), str):
                    out.append(_get(part, "text"))
    return "".join(out)


# ── streaming ────────────────────────────────────────────────────────────────

class _StreamTap:
    """
    Accumulates text deltas as the CALLER iterates; runs `on_done` when the
    stream ends (or is abandoned early, on whatever accumulated by then).
    Everything else on the inner stream object passes through. Supports sync
    and async iteration.
    """

    def __init__(self, inner: Any, extract: Any, on_done: Optional[Callable[[str], None]],
                 assembler: Any = None, on_tool_call: Optional[Callable[[Any], None]] = None):
        self._inner = inner
        self._extract = extract
        self._on_done = on_done
        # Tool calls arrive in fragments; the assembler rebuilds them so the
        # policy can run on a streamed call the way it does on a returned one.
        self._assembler = assembler
        self._on_tool_call = on_tool_call
        self.collected: list[str] = []

    def _finish(self) -> None:
        if self._on_done is not None:
            try:
                self._on_done("".join(self.collected))
            except Exception:
                pass  # canary observation must never break streaming
        # A stream cut off mid-call still shows what the model was reaching
        # for. This runs after the text check so a truncated response is
        # never left unscanned.
        if self._assembler is not None and self._on_tool_call is not None:
            try:
                open_calls = self._assembler.flush()
            except Exception:
                open_calls = []
            for call in open_calls:
                try:
                    self._on_tool_call(call)
                except Exception:
                    pass  # the stream is already over; nothing left to stop

    def _tools(self, ev: Any) -> None:
        if self._assembler is None or self._on_tool_call is None:
            return
        try:
            completed = self._assembler.push(ev)
        except Exception:
            return  # a malformed chunk must not break the caller's loop
        # Deliberately NOT guarded: on_tool_call raises to block, and that has
        # to reach the caller. A policy decision is not an error to hide.
        for call in completed:
            self._on_tool_call(call)

    def _take(self, ev: Any) -> None:
        try:
            text = self._extract(ev)
        except Exception:
            text = ""
        if text:
            self.collected.append(text)

    def __iter__(self) -> Iterator[Any]:
        try:
            for ev in self._inner:
                self._take(ev)
                # Before the yield, not after: a blocked call must stop the
                # iteration without the completing event reaching the caller.
                self._tools(ev)
                yield ev
        finally:
            self._finish()

    async def __aiter__(self) -> AsyncIterator[Any]:
        try:
            async for ev in self._inner:
                self._take(ev)
                self._tools(ev)  # before the yield, as above
                yield ev
        finally:
            self._finish()

    def __enter__(self) -> "_StreamTap":
        enter = getattr(self._inner, "__enter__", None)
        if enter:
            enter()
        return self

    def __exit__(self, *exc: Any) -> Any:
        exit_fn = getattr(self._inner, "__exit__", None)
        return exit_fn(*exc) if exit_fn else None

    async def __aenter__(self) -> "_StreamTap":
        enter = getattr(self._inner, "__aenter__", None)
        if enter:
            await enter()
        return self

    async def __aexit__(self, *exc: Any) -> Any:
        exit_fn = getattr(self._inner, "__aexit__", None)
        return await exit_fn(*exc) if exit_fn else None

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _snapshot_text(stream: Any) -> str:
    """Best-effort accumulated text from an SDK helper stream's own snapshot."""
    try:
        snap = getattr(stream, "current_message_snapshot", None)
        if snap is not None:
            return _anthropic_response_text(snap)
        snap = getattr(stream, "current_completion_snapshot", None)
        if snap is not None:
            return _openai_completion_text(snap)
    except Exception:
        pass
    return ""


class _CanaryCheckedStreamManager:
    """
    Wraps an SDK stream context manager (anthropic `messages.stream`, openai
    `chat.completions.stream` / `responses.stream`). The yielded stream is
    tapped so iteration accumulates text; on exit the fuller of {tapped text,
    the SDK's own snapshot} is canary-checked. Never forces consumption of an
    abandoned stream. Sync and async.
    """

    def __init__(self, inner_mgr: Any, on_text: Callable[[str], None], extract: Any):
        self._mgr = inner_mgr
        self._on_text = on_text
        self._extract = extract
        self._tap: Optional[_StreamTap] = None
        self._raw: Any = None
        self._on_final: Optional[Callable[[Any], Any]] = None

    def _wrap(self, stream: Any) -> Any:
        self._raw = stream
        self._tap = _StreamTap(stream, self._extract, None)
        return self._tap

    def _check(self) -> None:
        try:
            tapped = "".join(self._tap.collected) if self._tap else ""
            snap = _snapshot_text(self._raw)
            text = snap if len(snap) > len(tapped) else tapped
            if text:
                self._on_text(text)
            if self._on_final is not None:
                # A distinct name: `snap` above is the accumulated TEXT, this
                # is the response object. Reusing one name for both was what
                # made the type checker complain, and it was confusing anyway.
                final = (getattr(self._raw, "current_message_snapshot", None)
                         or getattr(self._raw, "current_completion_snapshot", None))
                if final is not None:
                    self._on_final(final)
        except Exception:
            pass  # observation must never break streaming

    def __enter__(self) -> Any:
        return self._wrap(self._mgr.__enter__())

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        self._check()
        return self._mgr.__exit__(exc_type, exc, tb)

    async def __aenter__(self) -> Any:
        return self._wrap(await self._mgr.__aenter__())

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        self._check()
        return await self._mgr.__aexit__(exc_type, exc, tb)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._mgr, name)


def _maybe_await(response: Any, then: Callable[[Any], Any]) -> Any:
    """Apply `then` to a response, awaiting first if the SDK is async."""
    if inspect.isawaitable(response):
        async def _run() -> Any:
            return then(await response)
        return _run()
    return then(response)


# ── shared shield core ───────────────────────────────────────────────────────

class _Prepared:
    __slots__ = ("kwargs", "canary", "input_scans", "untrusted_input_seen")

    def __init__(self, kwargs: dict, canary: str, input_scans: list, untrusted: bool):
        self.kwargs = kwargs
        self.canary = canary
        self.input_scans = input_scans
        self.untrusted_input_seen = untrusted


class _ShieldCore:
    def __init__(self, shield: Shield, wrap: bool, wrap_tools: bool, canary: Optional[str], enforce: bool,
                 wrap_documents: bool = True):
        self._shield = shield
        self._label = shield.app
        self._wrap = wrap
        self._wrap_tools = wrap_tools
        # A document is external content in the same way a tool result is, so
        # like tool results this is on by default.
        self._wrap_documents = wrap_documents
        self._fixed_canary = canary if canary is not None else shield.canary
        self._enforce = enforce

    def _observe_output(self, text: str, p: _Prepared) -> None:
        if text:
            self._shield.scan_output(text, canary=p.canary, input_scans=p.input_scans)

    def _observe_tool_calls(self, response: Any, calls: list[ToolCall], p: _Prepared, strip: Any = None) -> Any:
        if not calls:
            return response
        blocked: set = set()
        for call in calls:
            d = self._shield.check_tool_call(call, untrusted_input_seen=p.untrusted_input_seen, input_scans=p.input_scans)
            if d.decision == "block":
                blocked.add(call.id)
        if not strip or not self._enforce or not blocked:
            return response
        return strip(response, blocked)

    def _observe_stream_tool_call(self, call: ToolCall, p: _Prepared) -> None:
        """
        Evaluate a tool call assembled from a stream. Blocking a streamed call
        cannot mean stripping it — earlier events are already with the caller —
        so under enforcement it raises, ending the iteration before the call
        can be acted on. Without enforcement it is logged like any gated call.
        """
        d = self._shield.check_tool_call(
            call, untrusted_input_seen=p.untrusted_input_seen, input_scans=p.input_scans)
        if d.decision == "block" and self._enforce:
            raise ShieldBlockedToolError(call, list(d.reasons))

    def _tap_raw_stream(self, r: Any, p: _Prepared, extract: Any, assembler_kind: str) -> Any:
        """Tap a raw create(stream=True) stream for both output text and tool calls."""
        return _StreamTap(
            r, extract, lambda t: self._observe_output(t, p),
            assembler=assembler_for(assembler_kind),
            on_tool_call=lambda call: self._observe_stream_tool_call(call, p),
        )


def _parse_args(raw: Any) -> Any:
    if not isinstance(raw, str):
        return raw
    try:
        import json
        return json.loads(raw)
    except ValueError:
        return raw


def _anthropic_tool_calls(response: Any) -> list[ToolCall]:
    content = _get(response, "content") or []
    if not isinstance(content, list):
        return []
    return [ToolCall(name=_get(b, "name"), input=_get(b, "input"), id=_get(b, "id"))
            for b in content if _get(b, "type") == "tool_use"]


def _strip_anthropic_tool_calls(response: Any, blocked: set) -> Any:
    content = [b for b in (_get(response, "content") or [])
               if not (_get(b, "type") == "tool_use" and _get(b, "id") in blocked)]
    if isinstance(response, dict):
        return {**response, "content": content}
    try:
        return response.model_copy(update={"content": content})  # pydantic models (SDK responses)
    except Exception:  # noqa: BLE001
        try:
            response.content = content
        except Exception:  # noqa: BLE001
            pass
        return response


def _openai_chat_tool_calls(response: Any) -> list[ToolCall]:
    out: list[ToolCall] = []
    for c in _get(response, "choices") or []:
        msg = _get(c, "message")
        for tc in (_get(msg, "tool_calls") or []) if msg else []:
            fn = _get(tc, "function")
            if fn:
                out.append(ToolCall(name=_get(fn, "name"), input=_parse_args(_get(fn, "arguments")), id=_get(tc, "id")))
    return out


def _strip_openai_chat_tool_calls(response: Any, blocked: set) -> Any:
    for c in _get(response, "choices") or []:
        msg = _get(c, "message")
        tcs = _get(msg, "tool_calls") if msg else None
        if tcs:
            kept = [tc for tc in tcs if _get(tc, "id") not in blocked]
            if isinstance(msg, dict):
                msg["tool_calls"] = kept
            else:
                try:
                    msg.tool_calls = kept
                except Exception:  # noqa: BLE001
                    pass
    return response


def _responses_tool_calls(response: Any) -> list[ToolCall]:
    return [ToolCall(name=_get(it, "name"),
                     input=_parse_args(_get(it, "arguments") if _get(it, "arguments") is not None else _get(it, "input")),
                     id=_get(it, "call_id") or _get(it, "id"))
            for it in (_get(response, "output") or [])
            if _get(it, "type") in ("function_call", "custom_tool_call")]


def _strip_responses_tool_calls(response: Any, blocked: set) -> Any:
    kept = [it for it in (_get(response, "output") or [])
            if not (_get(it, "type") in ("function_call", "custom_tool_call") and (_get(it, "call_id") or _get(it, "id")) in blocked)]
    if isinstance(response, dict):
        return {**response, "output": kept}
    try:
        return response.model_copy(update={"output": kept})
    except Exception:  # noqa: BLE001
        try:
            response.output = kept
        except Exception:  # noqa: BLE001
            pass
        return response


# ── Anthropic ────────────────────────────────────────────────────────────────

_ANTHROPIC_CLIENT_ALLOW = ("models", "api_key", "auth_token", "base_url", "timeout", "max_retries",
                           "default_headers", "close")
_ANTHROPIC_MESSAGES_ALLOW = ("count_tokens",)


class _AnthropicMessages(_ShieldCore):
    def __init__(self, inner_messages: Any, shield: Shield, wrap: bool, wrap_tools: bool, canary: Optional[str],
                 enforce: bool, wrap_documents: bool = True):
        super().__init__(shield, wrap, wrap_tools, canary, enforce, wrap_documents)
        self._m = inner_messages

    def _prepare(self, kwargs: dict) -> _Prepared:
        hardened, canary = _harden_system(kwargs.get("system"), self._fixed_canary)
        kwargs = {**kwargs, "system": hardened}
        input_scans: list[InjectionScan] = []
        untrusted = False

        def scan(text: str, channel: Optional[str] = None) -> None:
            if text:
                input_scans.append(self._shield.scan_input(text, channel=channel))

        new_messages = []
        for m in kwargs.get("messages", []) or []:
            if isinstance(m, dict) and m.get("role") == "user":
                content = m.get("content", "")
                scan(_extract_text(content))
                tool_text = _extract_tool_result_text(content)
                doc_text = _extract_document_text(content)
                unreadable = _unscannable_documents(content)
                # An unreadable document is still untrusted input — arguably
                # more so, since nothing here can vouch for it.
                if tool_text or doc_text or unreadable:
                    untrusted = True
                scan(tool_text, "tool_result")
                scan(doc_text, "document")
                for what in unreadable:
                    self._shield.report_unscanned(what, channel="document")

                new_content = content
                if self._wrap_documents:
                    new_content = _wrap_document_blocks(new_content)
                if self._wrap_tools:
                    new_content = _wrap_tool_result_blocks(new_content)
                if self._wrap:
                    new_content = _wrap_user_content(new_content)
                if new_content is not content:
                    m = {**m, "content": new_content}
            new_messages.append(m)
        kwargs["messages"] = new_messages
        return _Prepared(kwargs, canary, input_scans, untrusted)

    def create(self, **kwargs: Any) -> Any:
        p = self._prepare(kwargs)
        response = self._m.create(**p.kwargs)

        def finish(r: Any) -> Any:
            if kwargs.get("stream"):
                return self._tap_raw_stream(r, p, _anthropic_delta_text, "anthropic")
            self._observe_output(_anthropic_response_text(r), p)
            return self._observe_tool_calls(r, _anthropic_tool_calls(r), p, _strip_anthropic_tool_calls)

        return _maybe_await(response, finish)

    def parse(self, **kwargs: Any) -> Any:
        p = self._prepare(kwargs)
        response = self._m.parse(**p.kwargs)

        def finish(r: Any) -> Any:
            self._observe_output(_anthropic_response_text(r), p)
            return self._observe_tool_calls(r, _anthropic_tool_calls(r), p, _strip_anthropic_tool_calls)

        return _maybe_await(response, finish)

    def stream(self, **kwargs: Any) -> Any:
        """Context manager like anthropic's messages.stream, output-checked on close."""
        p = self._prepare(kwargs)

        def on_text(t: str) -> None:
            self._observe_output(t, p)

        mgr = _CanaryCheckedStreamManager(self._m.stream(**p.kwargs), on_text, _anthropic_delta_text)
        mgr._on_final = lambda msg: self._observe_tool_calls(msg, _anthropic_tool_calls(msg), p, None)
        return mgr


def shield_anthropic(
    inner: Any,
    *,
    app_label: str = "shield",
    wrap_user_messages: bool = False,
    wrap_tool_results: bool = True,
    wrap_documents: bool = True,
    announce: bool = True,
    canary: Optional[str] = None,
    passthrough: Sequence[str] = (),
    shield: Optional[Shield] = None,
    enforce_tool_policy: bool = False,
) -> Any:
    """
    Wrap an anthropic.Anthropic / AsyncAnthropic client.

    Covered: messages.create / parse / stream. `messages.count_tokens` and
    `models` pass through. Anything else that could carry a prompt to the
    model (`beta`, `completions`, `messages.batches`, `with_options`) raises
    ShieldCoverageError unless listed in `passthrough`.

    `shield` supplies a create_shield() instance (sinks, output policy, tool
    policy); otherwise one is created from `app_label` / `canary`.
    `enforce_tool_policy=True` strips tool calls the policy BLOCKS from
    non-streaming responses instead of only logging them.
    """
    sh = shield or create_shield(app=app_label, canary=canary, banner=announce)
    passthrough = list(passthrough)

    def messages(client: Any) -> Any:
        impl = _AnthropicMessages(client.messages, sh, wrap_user_messages, wrap_tool_results, canary, enforce_tool_policy, wrap_documents)
        return _Guard(
            client.messages,
            "client.messages",
            {"create": lambda _m: impl.create, "parse": lambda _m: impl.parse, "stream": lambda _m: impl.stream},
            _ANTHROPIC_MESSAGES_ALLOW,
            _nested_passthrough(passthrough, "messages"),
        )

    return _Guard(inner, "client", {"messages": messages}, _ANTHROPIC_CLIENT_ALLOW, passthrough)


class ShieldAnthropicClient(_Guard):
    """
    Drop-in wrapper around anthropic.Anthropic (class form of shield_anthropic).

        client = ShieldAnthropicClient(anthropic.Anthropic(), app_label="my-app")
        # Use client.messages.create / .parse / .stream exactly as before.
    """

    def __init__(
        self,
        inner: Any,
        *,
        app_label: str = "shield",
        wrap_user_messages: bool = False,
        wrap_tool_results: bool = True,
        announce: bool = True,
        canary: Optional[str] = None,
        passthrough: Sequence[str] = (),
        shield: Optional[Shield] = None,
        enforce_tool_policy: bool = False,
    ):
        g = shield_anthropic(
            inner, app_label=app_label, wrap_user_messages=wrap_user_messages,
            wrap_tool_results=wrap_tool_results, announce=announce, canary=canary, passthrough=passthrough,
            shield=shield, enforce_tool_policy=enforce_tool_policy,
        )
        for k in ("_g_inner", "_g_path", "_g_intercept", "_g_allow", "_g_pass", "_g_cache"):
            object.__setattr__(self, k, object.__getattribute__(g, k))


# ── OpenAI ───────────────────────────────────────────────────────────────────

_OPENAI_CLIENT_ALLOW = (
    "embeddings", "models", "files", "images", "audio", "moderations", "fine_tuning",
    "vector_stores", "uploads", "conversations", "containers",
    "api_key", "base_url", "organization", "project", "webhook_secret", "timeout", "max_retries",
    "default_headers", "close",
)
_OPENAI_COMPLETIONS_ALLOW = ("messages",)
_OPENAI_RESPONSES_ALLOW = ("input_items", "retrieve", "delete", "cancel")


class _OpenAICompletions(_ShieldCore):
    def __init__(self, inner: Any, shield: Shield, wrap: bool, wrap_tools: bool, canary: Optional[str], enforce: bool):
        super().__init__(shield, wrap, wrap_tools, canary, enforce)
        self._c = inner

    def _prepare(self, kwargs: dict) -> _Prepared:
        messages = list(kwargs.get("messages", []) or [])
        sys_idx = next(
            (i for i, m in enumerate(messages) if isinstance(m, dict) and m.get("role") in ("system", "developer")),
            None,
        )
        sys_msg = messages[sys_idx] if sys_idx is not None else None
        hardened, canary = _harden_system(sys_msg.get("content") if sys_msg else None, self._fixed_canary)
        input_scans: list[InjectionScan] = []
        untrusted = False

        new_messages = []
        for i, m in enumerate(messages):
            if i == sys_idx:
                m = {**m, "content": hardened}
            elif isinstance(m, dict) and m.get("role") == "user":
                text = _extract_text(m.get("content", ""))
                if text:
                    input_scans.append(self._shield.scan_input(text))
                if self._wrap:
                    m = {**m, "content": _wrap_user_content(m.get("content", ""))}
            elif isinstance(m, dict) and m.get("role") == "tool":
                content = m.get("content", "")
                text = _parts_text(content)
                if text:
                    untrusted = True
                    input_scans.append(self._shield.scan_input(text, channel="tool_result"))
                if self._wrap_tools:
                    m = {**m, "content": _wrap_content_text(content, "tool_result")}
            new_messages.append(m)

        if sys_idx is None:
            new_messages.insert(0, {"role": "system", "content": hardened})

        return _Prepared({**kwargs, "messages": new_messages}, canary, input_scans, untrusted)

    def create(self, **kwargs: Any) -> Any:
        p = self._prepare(kwargs)
        response = self._c.create(**p.kwargs)

        def finish(r: Any) -> Any:
            if kwargs.get("stream"):
                return self._tap_raw_stream(r, p, _openai_chunk_text, "openai_chat")
            self._observe_output(_openai_completion_text(r), p)
            return self._observe_tool_calls(r, _openai_chat_tool_calls(r), p, _strip_openai_chat_tool_calls)

        return _maybe_await(response, finish)

    def parse(self, **kwargs: Any) -> Any:
        p = self._prepare(kwargs)
        response = self._c.parse(**p.kwargs)

        def finish(r: Any) -> Any:
            self._observe_output(_openai_completion_text(r), p)
            return self._observe_tool_calls(r, _openai_chat_tool_calls(r), p, _strip_openai_chat_tool_calls)

        return _maybe_await(response, finish)

    def stream(self, **kwargs: Any) -> Any:
        p = self._prepare(kwargs)
        mgr = _CanaryCheckedStreamManager(self._c.stream(**p.kwargs), lambda t: self._observe_output(t, p), _openai_chat_helper_text)
        mgr._on_final = lambda c: self._observe_tool_calls(c, _openai_chat_tool_calls(c), p, None)
        return mgr


class _OpenAIResponses(_ShieldCore):
    """
    Responses API: `instructions` is the system prompt; `input` is a string
    (user text) or a list of items — role messages, or `function_call_output`
    items carrying tool results.
    """

    _TEXT_TYPES = ("input_text", "text")

    def __init__(self, inner: Any, shield: Shield, wrap: bool, wrap_tools: bool, canary: Optional[str], enforce: bool):
        super().__init__(shield, wrap, wrap_tools, canary, enforce)
        self._r = inner

    def _prepare(self, kwargs: dict) -> _Prepared:
        instr = kwargs.get("instructions")
        instructions, canary = harden_system_prompt(instr if isinstance(instr, str) else "", self._fixed_canary)
        input_scans: list[InjectionScan] = []
        untrusted = False

        inp = kwargs.get("input")
        if isinstance(inp, str):
            input_scans.append(self._shield.scan_input(inp))
            if self._wrap:
                inp = wrap_untrusted(inp, "user_message")
        elif isinstance(inp, list):
            items = []
            for item in inp:
                if isinstance(item, dict):
                    t = item.get("type")
                    if t in ("function_call_output", "custom_tool_call_output"):
                        out = item.get("output")
                        text = _parts_text(out, self._TEXT_TYPES)
                        if text:
                            untrusted = True
                            input_scans.append(self._shield.scan_input(text, channel="tool_result"))
                        if self._wrap_tools:
                            item = {**item, "output": _wrap_content_text(out, "tool_result", self._TEXT_TYPES)}
                    elif t in (None, "message") and item.get("role") == "user":
                        text = _parts_text(item.get("content"), self._TEXT_TYPES)
                        if text:
                            input_scans.append(self._shield.scan_input(text))
                        if self._wrap:
                            item = {**item, "content": _wrap_content_text(item.get("content"), "user_message", self._TEXT_TYPES)}
                items.append(item)
            inp = items

        return _Prepared({**kwargs, "instructions": instructions, "input": inp}, canary, input_scans, untrusted)

    def create(self, **kwargs: Any) -> Any:
        p = self._prepare(kwargs)
        response = self._r.create(**p.kwargs)

        def finish(r: Any) -> Any:
            if kwargs.get("stream"):
                return self._tap_raw_stream(r, p, _responses_delta_text, "openai_responses")
            self._observe_output(_responses_output_text(r), p)
            return self._observe_tool_calls(r, _responses_tool_calls(r), p, _strip_responses_tool_calls)

        return _maybe_await(response, finish)

    def parse(self, **kwargs: Any) -> Any:
        p = self._prepare(kwargs)
        response = self._r.parse(**p.kwargs)

        def finish(r: Any) -> Any:
            self._observe_output(_responses_output_text(r), p)
            return self._observe_tool_calls(r, _responses_tool_calls(r), p, _strip_responses_tool_calls)

        return _maybe_await(response, finish)

    def stream(self, **kwargs: Any) -> Any:
        p = self._prepare(kwargs)
        return _CanaryCheckedStreamManager(self._r.stream(**p.kwargs), lambda t: self._observe_output(t, p), _responses_delta_text)


def shield_openai(
    inner: Any,
    *,
    app_label: str = "shield",
    wrap_user_messages: bool = False,
    wrap_tool_results: bool = True,
    announce: bool = True,
    canary: Optional[str] = None,
    passthrough: Sequence[str] = (),
    shield: Optional[Shield] = None,
    enforce_tool_policy: bool = False,
) -> Any:
    """
    Wrap an openai.OpenAI / AsyncOpenAI (or OpenAI-compatible) client.

    Covered: chat.completions.create / parse / stream and responses.create /
    parse / stream. Data-only surfaces (`embeddings`, `models`, `files`, …)
    pass through. Anything else that could carry a prompt to the model
    (`beta`, legacy `completions`, `batches`, `with_options`) raises
    ShieldCoverageError unless listed in `passthrough`.

    `shield` supplies a create_shield() instance; `enforce_tool_policy=True`
    strips BLOCKED tool calls from non-streaming responses.
    """
    sh = shield or create_shield(app=app_label, canary=canary, banner=announce)
    passthrough = list(passthrough)
    args = (sh, wrap_user_messages, wrap_tool_results, canary, enforce_tool_policy)

    def completions(chat: Any) -> Any:
        impl = _OpenAICompletions(chat.completions, *args)
        return _Guard(
            chat.completions,
            "client.chat.completions",
            {"create": lambda _c: impl.create, "parse": lambda _c: impl.parse, "stream": lambda _c: impl.stream},
            _OPENAI_COMPLETIONS_ALLOW,
            _nested_passthrough(_nested_passthrough(passthrough, "chat"), "completions"),
        )

    def chat(client: Any) -> Any:
        return _Guard(client.chat, "client.chat", {"completions": completions}, (),
                      _nested_passthrough(passthrough, "chat"))

    def responses(client: Any) -> Any:
        impl = _OpenAIResponses(client.responses, *args)
        return _Guard(
            client.responses,
            "client.responses",
            {"create": lambda _r: impl.create, "parse": lambda _r: impl.parse, "stream": lambda _r: impl.stream},
            _OPENAI_RESPONSES_ALLOW,
            _nested_passthrough(passthrough, "responses"),
        )

    return _Guard(inner, "client", {"chat": chat, "responses": responses}, _OPENAI_CLIENT_ALLOW, passthrough)


class ShieldOpenAIClient(_Guard):
    """
    Drop-in wrapper around openai.OpenAI (class form of shield_openai).

        client = ShieldOpenAIClient(openai.OpenAI(api_key=key), app_label="my-app")
        resp = client.chat.completions.create(model=..., messages=...)
        resp = client.responses.create(model=..., instructions=..., input=...)
    """

    def __init__(
        self,
        inner: Any,
        *,
        app_label: str = "shield",
        wrap_user_messages: bool = False,
        wrap_tool_results: bool = True,
        announce: bool = True,
        canary: Optional[str] = None,
        passthrough: Sequence[str] = (),
        shield: Optional[Shield] = None,
        enforce_tool_policy: bool = False,
    ):
        g = shield_openai(
            inner, app_label=app_label, wrap_user_messages=wrap_user_messages,
            wrap_tool_results=wrap_tool_results, announce=announce, canary=canary, passthrough=passthrough,
            shield=shield, enforce_tool_policy=enforce_tool_policy,
        )
        for k in ("_g_inner", "_g_path", "_g_intercept", "_g_allow", "_g_pass", "_g_cache"):
            object.__setattr__(self, k, object.__getattribute__(g, k))
