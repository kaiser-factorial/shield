/**
 * Browser entry point — selected by bundlers via the "browser" export
 * condition. Same core API as the main entry, minus the Node-only modules
 * (file logger, process watch, child_process) so nothing here references
 * `fs`, `os`, or `child_process`.
 */
export {
  SHIELD_VERSION,
  PATTERN_COUNT,
  MAX_SCAN_CHARS,
  announceShield,
  type AnnounceOptions,
  detectInjection,
  normalizeForScan,
  scanDetail,
  sanitizeUntrusted,
  normalizeLabel,
  wrapUntrusted,
  wrapChatHistory,
  hardenSystemPrompt,
  securityBoilerplate,
  generateCanary,
  outputLeakedCanary,
  gateUserMessage,
  onShieldEvent,
  offShieldEvent,
  emitShieldEvent,
  type InjectionScan,
  type InjectionExcerpt,
  type HardenResult,
  type ShieldEvent,
  type MessageGateResult,
  type SubscribeOptions,
} from "./shield.js";

export {
  shieldAnthropic,
  ShieldAnthropicClient,
  type ShieldAnthropicOptions,
  type AnthropicLike,
  type AnthropicMessagesLike,
} from "./client-anthropic.js";
export {
  shieldOpenAI,
  ShieldOpenAIClient,
  type ShieldOpenAIOptions,
  type OpenAILike,
  type OpenAICompletionsLike,
  type OpenAIResponsesLike,
} from "./client-openai.js";
export { ShieldCoverageError } from "./coverage.js";
