/**
 * `prompt-shield/openai` — the OpenAI / OpenRouter client wrapper on its own.
 * See ./anthropic.ts for why the wrappers get their own entry points.
 */

export {
  shieldOpenAI,
  ShieldOpenAIClient,
  type ShieldOpenAIOptions,
  type OpenAILike,
  type OpenAICompletionsLike,
  type OpenAIResponsesLike,
} from "./client-openai.js";

export { ShieldCoverageError } from "./coverage.js";
export { ShieldBlockedToolError } from "./output.js";
