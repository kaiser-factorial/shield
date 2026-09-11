/**
 * `prompt-shield/anthropic` — the Anthropic client wrapper on its own.
 *
 * The root entry exports both SDK wrappers. An app that uses one SDK has no
 * reason to pull in the other's types, and a narrow import makes the
 * dependency legible at the call site.
 */

export {
  shieldAnthropic,
  ShieldAnthropicClient,
  type ShieldAnthropicOptions,
  type AnthropicLike,
  type AnthropicMessagesLike,
} from "./client-anthropic.js";

export { ShieldCoverageError } from "./coverage.js";
export { ShieldBlockedToolError } from "./output.js";
