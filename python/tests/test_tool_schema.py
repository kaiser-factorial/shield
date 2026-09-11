"""
Per-tool argument schemas. Mirrors test/tool-schema.test.ts.

`argument_rules` matches a regex against the JSON-serialized arguments. That
cannot tell which field matched, cannot express "this field must be one of
three values", and — the gap that matters most — cannot notice an argument
that should not be there at all. A schema can.
"""
from __future__ import annotations

import os
import re
import unittest

os.environ.setdefault("SHIELD_QUIET", "1")

from shield import ToolCall, ToolParamSchema, ToolPolicy, ToolSchema, validate_tool_arguments
from shield.output import evaluate_tool_call

READ_FILE = ToolSchema(
    tool="read_file",
    required=["path"],
    properties={"path": ToolParamSchema(type="string", format="path", max_length=200)},
)

HTTP_POST = ToolSchema(
    tool="http_post",
    required=["url"],
    properties={
        "url": ToolParamSchema(type="string", format="url", allowed_hosts=["api.example.com"]),
        "retries": ToolParamSchema(type="integer", minimum=0, maximum=5),
    },
)


def call(name, inp):
    return ToolCall(name=name, input=inp)


class TestToolSchema(unittest.TestCase):
    def test_conforming_call_passes(self):
        self.assertEqual(validate_tool_arguments(call("read_file", {"path": "docs/readme.md"}), READ_FILE), [])
        self.assertEqual(
            validate_tool_arguments(call("http_post", {"url": "https://api.example.com/v1", "retries": 2}), HTTP_POST),
            [])

    def test_path_traversal_including_percent_encoded(self):
        self.assertIn("traversal", validate_tool_arguments(call("read_file", {"path": "../../etc/passwd"}), READ_FILE)[0])
        # %2e%2e%2f is the oldest way past a check that only looks at literal dots.
        self.assertIn("traversal", validate_tool_arguments(call("read_file", {"path": "a/%2e%2e%2fetc/passwd"}), READ_FILE)[0])

    def test_absolute_paths(self):
        self.assertIn("absolute", validate_tool_arguments(call("read_file", {"path": "/etc/shadow"}), READ_FILE)[0])
        permissive = ToolSchema(tool="read_file", required=["path"],
                                properties={"path": ToolParamSchema(type="string", format="path", allow_absolute=True)})
        self.assertEqual(validate_tool_arguments(call("read_file", {"path": "/srv/data.csv"}), permissive), [])

    def test_non_http_schemes_rejected(self):
        for url in ("file:///etc/passwd", "data:text/html,<script>", "javascript:alert(1)"):
            v = validate_tool_arguments(call("http_post", {"url": url}), HTTP_POST)
            self.assertIn("not an http(s) URL", v[0], url)

    def test_host_allow_list(self):
        self.assertIn("unlisted host",
                      validate_tool_arguments(call("http_post", {"url": "https://evil.example/x"}), HTTP_POST)[0])
        self.assertEqual(
            validate_tool_arguments(call("http_post", {"url": "https://eu.api.example.com/v1"}), HTTP_POST), [])
        # userinfo before the host is how a URL is made to *look* like it points
        # somewhere allowed: https://api.example.com@evil.example/ goes to evil.
        self.assertIn("unlisted host evil.example",
                      validate_tool_arguments(call("http_post", {"url": "https://api.example.com@evil.example/"}), HTTP_POST)[0])

    def test_undeclared_argument_is_a_violation_by_default(self):
        v = validate_tool_arguments(call("read_file", {"path": "ok.txt", "encoding": "utf8"}), READ_FILE)
        self.assertIn('"encoding" is not a declared argument', v[0])
        loose = ToolSchema(tool="read_file", required=["path"], additional_properties=True,
                           properties={"path": ToolParamSchema(type="string", format="path")})
        self.assertEqual(validate_tool_arguments(call("read_file", {"path": "ok.txt", "encoding": "utf8"}), loose), [])

    def test_required_and_type_errors(self):
        self.assertIn('"path" is required', validate_tool_arguments(call("read_file", {}), READ_FILE)[0])
        # A type mismatch makes the other checks meaningless, so it reports alone.
        self.assertEqual(validate_tool_arguments(call("read_file", {"path": 42}), READ_FILE),
                         ['"path" should be string, got number'])

    def test_numeric_bounds_and_enums(self):
        self.assertIn("above 5", validate_tool_arguments(
            call("http_post", {"url": "https://api.example.com", "retries": 9}), HTTP_POST)[0])
        self.assertIn("should be integer", validate_tool_arguments(
            call("http_post", {"url": "https://api.example.com", "retries": 1.5}), HTTP_POST)[0])
        mode = ToolSchema(tool="set_mode", properties={"mode": ToolParamSchema(enum=["read", "write"])})
        self.assertIn("not one of the allowed values",
                      validate_tool_arguments(call("set_mode", {"mode": "admin"}), mode)[0])

    def test_array_items(self):
        s = ToolSchema(tool="read_many", properties={
            "paths": ToolParamSchema(type="array", items=ToolParamSchema(type="string", format="path"))})
        v = validate_tool_arguments(call("read_many", {"paths": ["ok.txt", "../secrets"]}), s)
        self.assertEqual(len(v), 1)
        self.assertIn('"paths[1]" contains a path traversal', v[0])

    def test_unparsed_arguments_are_a_violation(self):
        # A truncated stream hands over the raw string. A schema that quietly
        # does not run is worse than no schema: it reads as a check that passed.
        v = validate_tool_arguments(call("read_file", '{"path":"../../etc/pas'), READ_FILE)
        self.assertIn("did not parse as JSON", v[0])

    def test_evaluate_tool_call_blocks_and_names_the_field(self):
        d = evaluate_tool_call(call("read_file", {"path": "../../etc/passwd"}),
                               ToolPolicy(schemas=[READ_FILE]))
        self.assertEqual(d.decision, "block")
        self.assertTrue(d.reasons[0].startswith('schema: "path" contains a path traversal'))

    def test_flag_action_and_tool_scoping(self):
        soft = ToolSchema(tool="read_file", required=["path"], action="flag",
                          properties={"path": ToolParamSchema(type="string", format="path")})
        self.assertEqual(evaluate_tool_call(call("read_file", {"path": "../x"}),
                                            ToolPolicy(schemas=[soft])).decision, "flag")
        # A schema for another tool must not touch this call.
        self.assertEqual(evaluate_tool_call(call("other_tool", {"anything": 1}),
                                            ToolPolicy(schemas=[READ_FILE])).decision, "allow")


if __name__ == "__main__":
    unittest.main()
