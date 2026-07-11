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
          const r = await it.next();
          if (r.done) finish();
          else buf += extract(r.value);
          return r;
        },
        async return(v?: unknown) {
          finish();
          return it.return ? it.return(v) : { done: true, value: v };
        },
        async throw(e?: unknown) {
          if (it.throw) return it.throw(e);
          throw e;
        },
        [Symbol.asyncIterator]() { return this; },
      };
    },
  });
  return stream;
}
