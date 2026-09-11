// Core detection, wrapping, hardening
export {
  SHIELD_VERSION,
  PATTERN_COUNT,
  announceShield,
  type AnnounceOptions,
  detectInjection,
  normalizeForScan,
  MAX_SCAN_CHARS,
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
  type ShieldEventType,
  type MessageGateResult,
  type SubscribeOptions,
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

// Pluggable detectors (semantic slot)
export {
  runDetectors,
  runDetectorsAsync,
  combineScore,
  type Detector,
  type DetectorContext,
  type DetectorFinding,
  type DetectorRun,
  type DetectorSide,
} from "./detectors.js";

// Output-side pipeline + tool-call policy
export {
  scanOutput,
  outputDetail,
  evaluateToolCall,
  SECRET_PATTERNS,
  PII_PATTERNS,
  type OutputScan,
  type OutputFinding,
  type OutputCategory,
  type OutputScanContext,
  type ToolCall,
  type ToolCallContext,
  type ToolPolicy,
  type ToolArgumentRule,
  type ToolDecision,
  type ToolDecisionKind,
} from "./output.js";

// Instance API
export {
  createShield,
  getDefaultShield,
  Shield,
  type ShieldConfig,
  type OutputConfig,
  type ScanInputOptions,
  type Sink,
} from "./instance.js";

// File logger (Node.js only — no-ops in browser)
export {
  initFileLogger,
  readEvents,
  summarizeStatus,
  sanitizeForTerminal,
  LOG_FILE,
  type ReadEventsOptions,
  type AppStatus,
} from "./logger.js";
