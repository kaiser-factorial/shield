/**
 * Deny-by-default proxying for the SDK client wrappers.
 *
 * The wrappers used to hand-build a partial object (TS) or forward every
 * unknown attribute to the inner client (Python). Both failed the same test:
 * `client.responses.create(...)`, `client.beta.messages.create(...)`,
 * `client.chat.completions.parse(...)` either threw `undefined is not a
 * function` or — worse — went straight to the model with no hardening while
 * the startup banner said "shield active".
 *
 * A protection that fails to load looks exactly like no protection, so the
 * rule here is explicit: every attribute reached through a shielded client is
 * one of
 *   - intercepted  → shielded implementation,
 *   - allowed      → known not to send prompts to a model, forwarded as-is,
 *   - passthrough  → the consumer opted a surface out by name, forwarded as-is,
 *   - anything else → ShieldCoverageError, at access time, naming the path.
 */

export class ShieldCoverageError extends Error {
  constructor(public readonly path: string) {
    super(
      `[shield] "${path}" is not covered by the shield wrapper. It may send prompts to the model ` +
        `without hardening or scanning. Either use a covered surface, or opt out explicitly with ` +
        `passthrough: ["${path.split(".").slice(1).join(".") || path}"] in the wrapper options.`,
    );
    this.name = "ShieldCoverageError";
  }
}

export interface GuardSpec {
  /** Dotted path for error messages, e.g. "client.chat.completions". */
  path: string;
  /** Attribute → factory for its shielded replacement (memoized per proxy). */
   
  intercept: Record<string, (inner: any) => unknown>;
  /** Attributes forwarded unchanged: known not to carry prompts to a model. */
  allow: readonly string[];
  /**
   * Consumer opt-outs, as paths relative to this level ("beta" on the client,
   * "batches" on messages). A dotted entry ("beta.messages") applies to the
   * first segment here and the remainder is passed down to a nested guard.
   */
  passthrough?: readonly string[];
}

/**
 * Wrap `inner` in a Proxy that enforces the spec. Functions forwarded from
 * `inner` are bound to it so SDK methods keep their `this`.
 */
export function guarded<T extends object>(inner: T, spec: GuardSpec): T {
  const cache = new Map<string, unknown>();
  const passthrough = new Set((spec.passthrough ?? []).map((p) => p.split(".")[0]));

  return new Proxy(inner, {
    get(target, prop, receiver) {
      if (typeof prop === "symbol") return Reflect.get(target, prop, receiver);
      // Never look thenable: `await client` must not hang or throw.
      if (prop === "then") return undefined;
      if (prop === "constructor" || prop === "toJSON" || prop === "toString") return Reflect.get(target, prop, target);

      if (Object.prototype.hasOwnProperty.call(spec.intercept, prop)) {
        if (!cache.has(prop)) cache.set(prop, spec.intercept[prop](target));
        return cache.get(prop);
      }

      // SDK-internal plumbing (`_client`, `_options`, …) never carries prompts.
      if (prop.startsWith("_") || spec.allow.includes(prop) || passthrough.has(prop)) {
        const v = Reflect.get(target, prop, target);
        return typeof v === "function" ? v.bind(target) : v;
      }

      throw new ShieldCoverageError(`${spec.path}.${prop}`);
    },
    has(target, prop) {
      return typeof prop === "symbol" || prop in spec.intercept || Reflect.has(target, prop);
    },
  });
}

/** Passthrough entries that apply beneath `segment` (e.g. "beta.messages" → ["messages"]). */
export function nestedPassthrough(passthrough: readonly string[] | undefined, segment: string): string[] {
  return (passthrough ?? [])
    .filter((p) => p.startsWith(`${segment}.`))
    .map((p) => p.slice(segment.length + 1));
}
