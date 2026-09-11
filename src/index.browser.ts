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
  type ShieldEventType,
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
  ShieldBlockedToolError,
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
