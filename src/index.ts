// Core detection, wrapping, hardening
export {
  detectInjection,
  wrapUntrusted,
  wrapChatHistory,
  hardenSystemPrompt,
  outputLeakedCanary,
  gateUserMessage,
  onShieldEvent,
  emitShieldEvent,
  type InjectionScan,
  type HardenResult,
  type ShieldEvent,
  type MessageGateResult,
} from "./shield.js";

// SDK wrappers
export { ShieldAnthropicClient, type ShieldAnthropicOptions } from "./client-anthropic.js";
export { ShieldOpenAIClient, type ShieldOpenAIOptions } from "./client-openai.js";

// File logger (Node.js only — no-ops in browser)
export { initFileLogger, readEvents, LOG_FILE, type ReadEventsOptions } from "./logger.js";
