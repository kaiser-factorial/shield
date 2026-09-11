/**
 * Per-tool argument schemas.
 *
 * `argumentRules` matches a regex against the JSON-serialized arguments. That
 * cannot tell which field matched, cannot express "this field must be one of
 * three values", and — the gap that matters most — cannot notice an argument
 * that should not be there at all. A schema can.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { evaluateToolCall, validateToolArguments, type ToolSchema } from "../src/output.js";

const readFile: ToolSchema = {
  tool: "read_file",
  required: ["path"],
  properties: { path: { type: "string", format: "path", maxLength: 200 } },
};

const httpPost: ToolSchema = {
  tool: "http_post",
  required: ["url"],
  properties: {
    url: { type: "string", format: "url", allowedHosts: ["api.example.com"] },
    retries: { type: "integer", minimum: 0, maximum: 5 },
  },
};

const call = (name: string, input: unknown) => ({ name, input });

test("a conforming call passes", () => {
  assert.deepEqual(validateToolArguments(call("read_file", { path: "docs/readme.md" }), readFile), []);
  assert.deepEqual(
    validateToolArguments(call("http_post", { url: "https://api.example.com/v1", retries: 2 }), httpPost),
    [],
  );
});

test("path traversal is caught, including percent-encoded", () => {
  assert.match(validateToolArguments(call("read_file", { path: "../../etc/passwd" }), readFile)[0]!, /traversal/);
  // %2e%2e%2f is the oldest way past a check that only looks at literal dots.
  assert.match(validateToolArguments(call("read_file", { path: "a/%2e%2e%2fetc/passwd" }), readFile)[0]!, /traversal/);
});

test("absolute paths are rejected unless allowed", () => {
  assert.match(validateToolArguments(call("read_file", { path: "/etc/shadow" }), readFile)[0]!, /absolute/);
  const permissive: ToolSchema = { ...readFile, properties: { path: { type: "string", format: "path", allowAbsolute: true } } };
  assert.deepEqual(validateToolArguments(call("read_file", { path: "/srv/data.csv" }), permissive), []);
});

test("non-http URL schemes are rejected", () => {
  for (const url of ["file:///etc/passwd", "data:text/html,<script>", "javascript:alert(1)"]) {
    const v = validateToolArguments(call("http_post", { url }), httpPost);
    assert.match(v[0]!, /not an http\(s\) URL/, url);
  }
});

test("a URL to an unlisted host is rejected, and a subdomain of an allowed one is not", () => {
  assert.match(validateToolArguments(call("http_post", { url: "https://evil.example/x" }), httpPost)[0]!, /unlisted host/);
  assert.deepEqual(validateToolArguments(call("http_post", { url: "https://eu.api.example.com/v1" }), httpPost), []);
  // userinfo before the host is how a URL is made to *look* like it points
  // somewhere allowed: https://api.example.com@evil.example/ goes to evil.
  assert.match(
    validateToolArguments(call("http_post", { url: "https://api.example.com@evil.example/" }), httpPost)[0]!,
    /unlisted host evil\.example/,
  );
});

test("an undeclared argument is a violation by default", () => {
  const v = validateToolArguments(call("read_file", { path: "ok.txt", encoding: "utf8" }), readFile);
  assert.match(v[0]!, /"encoding" is not a declared argument/);
  const loose: ToolSchema = { ...readFile, additionalProperties: true };
  assert.deepEqual(validateToolArguments(call("read_file", { path: "ok.txt", encoding: "utf8" }), loose), []);
});

test("missing required arguments and wrong types are reported", () => {
  assert.match(validateToolArguments(call("read_file", {}), readFile)[0]!, /"path" is required/);
  const v = validateToolArguments(call("read_file", { path: 42 }), readFile);
  // A type mismatch makes the other checks meaningless, so it reports alone.
  assert.deepEqual(v, ['"path" should be string, got number']);
});

test("numeric bounds and enums", () => {
  assert.match(validateToolArguments(call("http_post", { url: "https://api.example.com", retries: 9 }), httpPost)[0]!, /above 5/);
  assert.match(validateToolArguments(call("http_post", { url: "https://api.example.com", retries: 1.5 }), httpPost)[0]!, /should be integer/);
  const mode: ToolSchema = { tool: "set_mode", properties: { mode: { enum: ["read", "write"] } } };
  assert.match(validateToolArguments(call("set_mode", { mode: "admin" }), mode)[0]!, /not one of the allowed values/);
});

test("array elements are checked against items", () => {
  const s: ToolSchema = { tool: "read_many", properties: { paths: { type: "array", items: { type: "string", format: "path" } } } };
  const v = validateToolArguments(call("read_many", { paths: ["ok.txt", "../secrets"] }), s);
  assert.equal(v.length, 1);
  assert.match(v[0]!, /"paths\[1\]" contains a path traversal/);
});

test("arguments that never parsed are a violation, not a silent pass", () => {
  // A truncated stream hands over the raw string. A schema that quietly does
  // not run is worse than no schema: it reads as a check that passed.
  const v = validateToolArguments(call("read_file", '{"path":"../../etc/pas'), readFile);
  assert.match(v[0]!, /did not parse as JSON/);
});

test("evaluateToolCall blocks on a schema violation and says which field", () => {
  const d = evaluateToolCall(call("read_file", { path: "../../etc/passwd" }), { schemas: [readFile] });
  assert.equal(d.decision, "block");
  assert.match(d.reasons[0]!, /^schema: "path" contains a path traversal/);
});

test("a schema can flag instead of block, and only applies to its own tool", () => {
  const soft: ToolSchema = { ...readFile, action: "flag" };
  assert.equal(evaluateToolCall(call("read_file", { path: "../x" }), { schemas: [soft] }).decision, "flag");
  // A schema for another tool must not touch this call.
  assert.equal(evaluateToolCall(call("other_tool", { anything: 1 }), { schemas: [readFile] }).decision, "allow");
});
