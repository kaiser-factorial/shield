// Core detection, wrapping, hardening
export {
  SHIELD_VERSION,
  PATTERN_COUNT,
  announceShield,
  type AnnounceOptions,
  detectInjection,
  sanitizeUntrusted,
  wrapUntrusted,
  wrapChatHistory,
  hardenSystemPrompt,
  securityBoilerplate,
  generateCanary,
  outputLeakedCanary,
  gateUserMessage,
  onShieldEvent,
  emitShieldEvent,
  type InjectionScan,
  type HardenResult,
  type ShieldEvent,
  type MessageGateResult,
} from "./shield.js";

// Headless-browser / automation watch (Node.js only)
export {
  HEADLESS_SIGNATURES,
  matchHeadless,
  scanHeadlessProcesses,
  reportHeadless,
  type HeadlessSignature,
  type HeadlessProcess,
} from "./headless.js";

// SDK wrappers
export { ShieldAnthropicClient, type ShieldAnthropicOptions } from "./client-anthropic.js";
export { ShieldOpenAIClient, type ShieldOpenAIOptions } from "./client-openai.js";

// File logger (Node.js only — no-ops in browser)
export {
  initFileLogger,
  readEvents,
  summarizeStatus,
  LOG_FILE,
  type ReadEventsOptions,
  type AppStatus,
} from "./logger.js";
