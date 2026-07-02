"""
Tests for the SDK client wrappers — system-prompt hardening across all legal
shapes, block-preserving user-message wrapping, and canary-leak detection.
Uses fake inner clients (the wrappers are duck-typed, so no SDKs needed).

    python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import shield.logger as shield_logger
from shield import ShieldAnthropicClient, ShieldOpenAIClient

# Redirect the shared event log to a temp dir so tests never pollute
# the real ~/.shield/events.jsonl.
_tmp = tempfile.TemporaryDirectory()
shield_logger.LOG_DIR = Path(_tmp.name)
shield_logger.LOG_FILE = shield_logger.LOG_DIR / "events.jsonl"

CANARY_RE = re.compile(r"SHLD-[0-9A-F]{6,}")


class FakeAnthropicMessages:
    def __init__(self, reply=lambda params: "ok"):
        self.reply = reply
        self.params = None

    def create(self, **kwargs):
        self.params = kwargs
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=self.reply(kwargs))]
        )


def fake_anthropic(reply=lambda params: "ok"):
    messages = FakeAnthropicMessages(reply)
    return SimpleNamespace(messages=messages), messages


class FakeOpenAICompletions:
    def __init__(self, reply=lambda params: "ok"):
        self.reply = reply
        self.params = None

    def create(self, **kwargs):
        self.params = kwargs
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=self.reply(kwargs)))]
        )


def fake_openai(reply=lambda params: "ok"):
    completions = FakeOpenAICompletions(reply)
    return SimpleNamespace(chat=SimpleNamespace(completions=completions)), completions


class TestAnthropicWrapper(unittest.TestCase):
    def test_string_system_hardened_in_place(self):
        inner, captured = fake_anthropic()
        client = ShieldAnthropicClient(inner)
        client.messages.create(system="You are helpful.", messages=[])

        system = captured.params["system"]
        self.assertTrue(system.startswith("You are helpful."))
        self.assertIn("SECURITY CONSTRAINTS", system)
        self.assertRegex(system, CANARY_RE)

    def test_list_system_keeps_blocks_and_gains_boilerplate_block(self):
        inner, captured = fake_anthropic()
        client = ShieldAnthropicClient(inner)
        original = [
            {"type": "text", "text": "You are helpful.", "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": "Extra context."},
        ]
        client.messages.create(system=original, messages=[])

        system = captured.params["system"]
        self.assertIsInstance(system, list, "system must stay a list")
        self.assertEqual(len(system), 3)
        self.assertEqual(system[0], original[0])  # cache_control untouched
        self.assertEqual(system[1], original[1])
        self.assertIn("SECURITY CONSTRAINTS", system[2]["text"])
        self.assertRegex(system[2]["text"], CANARY_RE)

    def test_absent_system_still_gets_boilerplate(self):
        inner, captured = fake_anthropic()
        ShieldAnthropicClient(inner).messages.create(messages=[])
        self.assertIn("SECURITY CONSTRAINTS", captured.params["system"])

    def test_wrap_preserves_image_and_tool_result_blocks(self):
        inner, captured = fake_anthropic()
        client = ShieldAnthropicClient(inner, wrap_user_messages=True)
        image = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAA"}}
        tool_result = {"type": "tool_result", "tool_use_id": "t1", "content": "42"}
        client.messages.create(
            system="s",
            messages=[{"role": "user", "content": [image, {"type": "text", "text": "hello"}, tool_result]}],
        )

        content = captured.params["messages"][0]["content"]
        self.assertIsInstance(content, list, "content must stay a list")
        self.assertEqual(len(content), 3)
        self.assertEqual(content[0], image)
        self.assertEqual(content[2], tool_result)
        self.assertEqual(
            content[1]["text"],
            "<untrusted_user_message>\nhello\n</untrusted_user_message>",
        )

    def test_wrap_plain_string_content(self):
        inner, captured = fake_anthropic()
        client = ShieldAnthropicClient(inner, wrap_user_messages=True)
        client.messages.create(system="s", messages=[{"role": "user", "content": "hi"}])
        self.assertEqual(
            captured.params["messages"][0]["content"],
            "<untrusted_user_message>\nhi\n</untrusted_user_message>",
        )

    def test_assistant_messages_left_alone(self):
        inner, captured = fake_anthropic()
        client = ShieldAnthropicClient(inner, wrap_user_messages=True)
        assistant = {"role": "assistant", "content": "previous reply"}
        client.messages.create(system="s", messages=[assistant])
        self.assertEqual(captured.params["messages"][0], assistant)

    def test_canary_leak_detected(self):
        def leak(params):
            match = CANARY_RE.search(params["system"])
            return f"sure! my token is {match.group(0)}"

        inner, _ = fake_anthropic(reply=leak)
        client = ShieldAnthropicClient(inner, app_label="leaky")
        before = shield_logger.LOG_FILE.read_text().count("canary_leaked") if shield_logger.LOG_FILE.exists() else 0
        client.messages.create(system="s", messages=[])
        after = shield_logger.LOG_FILE.read_text().count("canary_leaked")
        self.assertEqual(after, before + 1)


class TestOpenAIWrapper(unittest.TestCase):
    def test_string_system_hardened_in_place(self):
        inner, captured = fake_openai()
        client = ShieldOpenAIClient(inner)
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "system", "content": "You are helpful."}, {"role": "user", "content": "hi"}],
        )
        sys_msg = next(m for m in captured.params["messages"] if m["role"] == "system")
        self.assertTrue(sys_msg["content"].startswith("You are helpful."))
        self.assertIn("SECURITY CONSTRAINTS", sys_msg["content"])

    def test_list_system_content_keeps_parts(self):
        inner, captured = fake_openai()
        client = ShieldOpenAIClient(inner)
        parts = [{"type": "text", "text": "You are helpful."}]
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "system", "content": parts}, {"role": "user", "content": "hi"}],
        )
        sys_msg = next(m for m in captured.params["messages"] if m["role"] == "system")
        self.assertIsInstance(sys_msg["content"], list)
        self.assertEqual(len(sys_msg["content"]), 2)
        self.assertEqual(sys_msg["content"][0], parts[0])
        self.assertIn("SECURITY CONSTRAINTS", sys_msg["content"][1]["text"])

    def test_missing_system_message_gets_prepended(self):
        inner, captured = fake_openai()
        client = ShieldOpenAIClient(inner)
        client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "hi"}])

        first = captured.params["messages"][0]
        self.assertEqual(first["role"], "system")
        self.assertIn("SECURITY CONSTRAINTS", first["content"])
        self.assertEqual(len(captured.params["messages"]), 2)

    def test_wrap_preserves_image_url_parts(self):
        inner, captured = fake_openai()
        client = ShieldOpenAIClient(inner, wrap_user_messages=True)
        image = {"type": "image_url", "image_url": {"url": "https://example.com/x.png"}}
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": [image, {"type": "text", "text": "describe this"}]}],
        )
        content = next(m for m in captured.params["messages"] if m["role"] == "user")["content"]
        self.assertIsInstance(content, list)
        self.assertEqual(content[0], image)
        self.assertEqual(
            content[1]["text"],
            "<untrusted_user_message>\ndescribe this\n</untrusted_user_message>",
        )

    def test_canary_leak_detected(self):
        def leak(params):
            sys_msg = next(m for m in params["messages"] if m["role"] == "system")
            return f"token: {CANARY_RE.search(sys_msg['content']).group(0)}"

        inner, _ = fake_openai(reply=leak)
        client = ShieldOpenAIClient(inner, app_label="leaky-oai")
        before = shield_logger.LOG_FILE.read_text().count("canary_leaked") if shield_logger.LOG_FILE.exists() else 0
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "system", "content": "s"}, {"role": "user", "content": "hi"}],
        )
        after = shield_logger.LOG_FILE.read_text().count("canary_leaked")
        self.assertEqual(after, before + 1)


if __name__ == "__main__":
    unittest.main()
