/**
 * Streaming support for the SDK client wrappers.
 *
 * Canary checking on streamed responses used to be skipped entirely — the
 * response body only exists as it's consumed. The tap below closes that gap
 * without buffering anything itself: it wraps the stream's own async
 * iterator so text deltas accumulate as the CALLER consumes them, and the
 * canary check runs when the stream ends (or is abandoned early, on whatever
 * accumulated by then). Everything else on the stream object is untouched.
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function tapEventStream(stream: any, extract: (ev: any) => string, onDone: (text: string) => void): any {
  if (!stream || typeof stream[Symbol.asyncIterator] !== "function") return stream;
  const makeIter = stream[Symbol.asyncIterator].bind(stream);
  Object.defineProperty(stream, Symbol.asyncIterator, {
    configurable: true,
    value: () => {
      const it = makeIter();
      let buf = "";
      let finished = false;
      const finish = () => {
        if (finished) return;
        finished = true;
        try { onDone(buf); } catch { /* canary observation must never break streaming */ }
      };
      return {
        async next() {
          let r;
          try {
            r = await it.next();
          } catch (e) {
            // A stream that fails partway still emitted text, and that text can
            // still contain the canary. Without this the partial output was
            // never checked — the one case where a leak is most likely to slip
            // through is a response that broke off mid-answer.
            finish();
            throw e;
          }
          if (r.done) finish();
          else {
            // A malformed chunk must not throw into the consumer's loop.
            try { buf += extract(r.value) ?? ""; } catch { /* ignore */ }
          }
          return r;
        },
        async return(v?: unknown) {
          finish();
          return it.return ? it.return(v) : { done: true, value: v };
        },
        async throw(e?: unknown) {
          // Same reasoning as the catch above: abandoning via throw() still
          // leaves accumulated text worth checking. `return()` already did this;
          // the two paths disagreeing was an oversight, not a decision.
          finish();
          if (it.throw) return it.throw(e);
          throw e;
        },
        [Symbol.asyncIterator]() { return this; },
      };
    },
  });
  return stream;
}
