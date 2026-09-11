"""
Rebuilding tool calls from raw SDK streams. Mirrors src/stream.ts.

A non-streaming response is a finished object: the wrapper reads its tool
calls, evaluates them, and strips the blocked ones before the caller sees
them. A raw ``create(stream=True)`` stream has no such object — a tool call
arrives in fragments (a start event, a run of partial-JSON deltas, a stop
event) — so until now the policy never ran on a streamed call at all. An app
that streams had scanning but no gating, which from outside is
indistinguishable from gating that works.

The assemblers below rebuild each call and hand it over the moment it is
complete, which is before the caller can act on it: a tool call is executed by
the caller after the stream yields it, not by the SDK. So evaluating at
completion is genuinely in time. Under ``enforce_tool_policy`` a blocked call
raises ShieldBlockedToolError out of the iterator, which is the streaming
equivalent of stripping the block.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from .output import ToolCall


class ShieldBlockedToolError(Exception):
    """
    Raised when a blocked tool call is assembled from a stream under
    ``enforce_tool_policy``.

    A stream has already handed the caller earlier events by the time the call
    completes, so there is nothing to strip — ending the iteration loudly is
    the only way to stop the call being acted on. Catch it to fall back;
    letting it propagate is the safe default.
    """

    def __init__(self, call: ToolCall, reasons: list[str]):
        super().__init__(f'shield blocked tool call "{call.name}" mid-stream: {"; ".join(reasons)}')
        self.call = call
        self.reasons = reasons


def _parse_args(raw: str) -> Any:
    """Parse assembled argument JSON, keeping the raw string when it doesn't parse."""
    t = (raw or "").strip()
    if not t:
        return {}
    try:
        return json.loads(t)
    except (ValueError, TypeError):
        return t


def _get(ev: Any, key: str, default: Any = None) -> Any:
    """Stream events are dicts from the HTTP layer or objects from the SDK."""
    if isinstance(ev, dict):
        return ev.get(key, default)
    return getattr(ev, key, default)


class ToolAssembler:
    """Feed events with push(); it returns the calls each event completed."""

    def push(self, ev: Any) -> list[ToolCall]:  # pragma: no cover - interface
        raise NotImplementedError

    def flush(self) -> list[ToolCall]:  # pragma: no cover - interface
        raise NotImplementedError


class AnthropicToolAssembler(ToolAssembler):
    """content_block_start(tool_use) → input_json_delta run → content_block_stop, keyed by index."""

    def __init__(self) -> None:
        self._open: dict[Any, dict] = {}

    def push(self, ev: Any) -> list[ToolCall]:
        kind = _get(ev, "type")
        if kind == "content_block_start":
            block = _get(ev, "content_block")
            if _get(block, "type") == "tool_use":
                self._open[_get(ev, "index")] = {
                    "name": _get(block, "name") or "", "id": _get(block, "id"), "json": ""}
            return []
        if kind == "content_block_delta":
            delta = _get(ev, "delta")
            if _get(delta, "type") == "input_json_delta":
                slot = self._open.get(_get(ev, "index"))
                if slot is not None:
                    slot["json"] += _get(delta, "partial_json") or ""
            return []
        if kind == "content_block_stop":
            slot = self._open.pop(_get(ev, "index"), None)
            if slot is None:
                return []
            return [ToolCall(name=slot["name"], input=_parse_args(slot["json"]), id=slot["id"])]
        return []

    def flush(self) -> list[ToolCall]:
        # A stream cut off mid-call still shows what the model was reaching for.
        rest = [ToolCall(name=s["name"], input=_parse_args(s["json"]), id=s["id"])
                for s in self._open.values() if s["name"]]
        self._open.clear()
        return rest


class OpenAIChatToolAssembler(ToolAssembler):
    """delta.tool_calls fragments keyed by index, finished by finish_reason "tool_calls"."""

    def __init__(self) -> None:
        self._open: dict[int, dict] = {}

    def _drain(self) -> list[ToolCall]:
        out = [ToolCall(name=s["name"], input=_parse_args(s["json"]), id=s.get("id"))
               for s in self._open.values() if s["name"]]
        self._open.clear()
        return out

    def push(self, ev: Any) -> list[ToolCall]:
        choices = _get(ev, "choices") or []
        if not choices:
            return []
        choice = choices[0]
        delta = _get(choice, "delta")
        frags = _get(delta, "tool_calls") or []
        for f in frags:
            idx = _get(f, "index")
            i = idx if isinstance(idx, int) else 0
            slot = self._open.setdefault(i, {"name": "", "json": "", "id": None})
            if _get(f, "id"):
                slot["id"] = _get(f, "id")
            fn = _get(f, "function")
            # The name itself arrives in pieces; concatenate rather than assign,
            # or the policy gets looked up for a truncated tool name.
            if _get(fn, "name"):
                slot["name"] += _get(fn, "name")
            if _get(fn, "arguments"):
                slot["json"] += _get(fn, "arguments")
        # finish_reason arrives on its own final chunk, after every fragment.
        return self._drain() if _get(choice, "finish_reason") == "tool_calls" else []

    def flush(self) -> list[ToolCall]:
        return self._drain()


class OpenAIResponsesToolAssembler(ToolAssembler):
    """output_item.added(function_call) → arguments.delta run → arguments.done, keyed by item id."""

    def __init__(self) -> None:
        self._open: dict[Any, dict] = {}

    def push(self, ev: Any) -> list[ToolCall]:
        kind = _get(ev, "type")
        if kind == "response.output_item.added":
            item = _get(ev, "item")
            if _get(item, "type") == "function_call":
                key = _get(item, "id") or _get(item, "call_id") or _get(ev, "output_index", 0)
                self._open[key] = {"name": _get(item, "name") or "",
                                   "id": _get(item, "call_id") or _get(item, "id"), "json": ""}
            return []
        if kind == "response.function_call_arguments.delta":
            slot = self._open.get(_get(ev, "item_id"))
            if slot is not None:
                slot["json"] += _get(ev, "delta") or ""
            return []
        if kind == "response.function_call_arguments.done":
            slot = self._open.pop(_get(ev, "item_id"), None)
            if slot is None:
                return []
            # The done event carries the complete arguments; prefer it over our
            # accumulation, which a dropped delta would leave short.
            raw = _get(ev, "arguments")
            return [ToolCall(name=slot["name"],
                             input=_parse_args(raw if raw is not None else slot["json"]),
                             id=slot["id"])]
        return []

    def flush(self) -> list[ToolCall]:
        rest = [ToolCall(name=s["name"], input=_parse_args(s["json"]), id=s["id"])
                for s in self._open.values() if s["name"]]
        self._open.clear()
        return rest


def assembler_for(kind: str) -> Optional[ToolAssembler]:
    """`kind` is "anthropic", "openai_chat" or "openai_responses"."""
    if kind == "anthropic":
        return AnthropicToolAssembler()
    if kind == "openai_chat":
        return OpenAIChatToolAssembler()
    if kind == "openai_responses":
        return OpenAIResponsesToolAssembler()
    return None
