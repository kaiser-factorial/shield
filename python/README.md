# prompt-shield

Prompt injection defense for LLM apps. Detects injection attempts in untrusted
input, fences that input so the model can tell it apart from your
instructions, hardens your system prompt with a canary, watches model output
for leaked secrets and exfiltration channels, and gates the tool calls the
model asks for.

The distribution is `prompt-shield`; the import is `shield`.

```bash
pip install prompt-shield
pip install "prompt-shield[anthropic]"   # or [openai], or [all]
```

Zero required dependencies. The SDKs are optional extras.

## The four things it does

**Detect.** Thirty bounded regex patterns covering instruction override, role
hijacking, jailbreak boilerplate, system-prompt extraction, chat-delimiter
spoofing, exfiltration setup and tag breakout. Input is normalized first, so
zero-width characters, fullwidth forms and `i-g-n-o-r-e` don't slip past.

It is a tripwire, not a gate: translation, encoding and paraphrase still evade
it. The measured rate on the repo's committed benchmark corpus is 93.2%
precision and 74.5% recall, and the number is in CI so it cannot quietly rot.
Add a `Detector` for what regexes can't reach.

**Wrap.** Untrusted content goes inside `<untrusted_*>` boundaries, with
breakout attempts neutralized, so an instruction in a fetched page reads to
the model as data rather than as something you said.

**Harden.** A canary token is embedded in the system prompt. If it appears in
output, something extracted your instructions.

**Watch.** Output is scanned for credential shapes, registered secrets, PII,
exfiltration channels and echoed injections. Tool calls are evaluated against
a policy before your code runs them.

## Usage

```python
from shield import create_shield, shield_anthropic, ToolPolicy, ToolSchema, ToolParamSchema
import anthropic

shield = create_shield(
    app="support-bot",
    secrets=[os.environ["DB_PASSWORD"]],          # never emitted, never logged
    allowed_hosts=["example.com"],                # links elsewhere look like exfil
    tool_policy=ToolPolicy(
        deny=["run_shell"],
        side_effects=["send_email", "http_post"], # gated after untrusted input
        block_side_effects_after_untrusted=True,
        schemas=[ToolSchema(
            tool="read_file",
            required=["path"],
            properties={"path": ToolParamSchema(type="string", format="path")},
        )],
    ),
)

client = shield_anthropic(anthropic.Anthropic(), shield=shield, enforce_tool_policy=True)
# Use client.messages.create / .parse / .stream exactly as before.
```

Or drive the pipeline yourself:

```python
from shield import detect_injection, wrap_untrusted, harden_system_prompt

prompt, canary = harden_system_prompt(BASE_PROMPT)
scan = detect_injection(page_text)
safe = wrap_untrusted(page_text, "web_page")
out = shield.scan_output(reply, canary=canary, input_scans=[scan])
verdict = shield.check_tool_call(call, untrusted_input_seen=True)
if verdict.decision == "block":
    ...   # don't run it
```

Streaming tool calls are evaluated as they are assembled. With
`enforce_tool_policy=True` a blocked call raises `ShieldBlockedToolError` out
of the iterator, before your code can act on it.

## Coverage is deny-by-default

The wrappers refuse to hand you an unshielded path by accident. Data-only
surfaces pass through; anything that could carry a prompt to the model and
isn't covered raises `ShieldCoverageError` at access time rather than silently
skipping protection. Opt a surface out by name if you really need it.

## Knowing what wasn't checked

Content shield cannot read — a base64 PDF, an image, a remote URL fetched
server-side — raises `content_not_scanned` rather than passing silently. A log
that cannot tell "we looked and it was fine" from "we never opened it" is not
a security log.

## Parity

The TypeScript and Python packages are kept at feature parity by hand and
share a benchmark corpus, so detection cannot drift between them without a
test failing. Full docs, including the TypeScript API:
https://github.com/kaiser-factorial/shield

MIT licensed.
