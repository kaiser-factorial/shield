/**
 * `prompt-shield/node` — the surface that only exists under Node.
 *
 * The file logger and the headless-browser watch both need real process and
 * filesystem access. They are re-exported from the root entry too, where the
 * browser build replaces them with no-ops; importing them from here says
 * plainly that this code path is server-side, and keeps a bundler from
 * following `fs` into a browser build in the first place.
 */

export {
  initFileLogger,
  readEvents,
  summarizeStatus,
  sanitizeForTerminal,
  LOG_FILE,
  type ReadEventsOptions,
  type AppStatus,
} from "./logger.js";

export {
  HEADLESS_SIGNATURES,
  matchHeadless,
  scanHeadlessProcesses,
  reportHeadless,
  type HeadlessSignature,
  type HeadlessProcess,
} from "./headless.js";
