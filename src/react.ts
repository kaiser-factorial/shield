/**
 * React integration for shield — for browser apps that can't write to a filesystem.
 *
 * Usage:
 *   // In your app root:
 *   import { ShieldProvider } from "prompt-shield/react";
 *   <ShieldProvider><App /></ShieldProvider>
 *
 *   // Anywhere in your tree:
 *   import { useShield } from "prompt-shield/react";
 *   const { events, scan, wrap } = useShield();
 */

// This file uses React but declares it as a peer dep so the package stays lean.
// The importing app must have React installed.
import { useState, useEffect, useCallback, useMemo, createContext, useContext, createElement, type ReactNode } from "react";
import { onShieldEvent, detectInjection, wrapUntrusted, type ShieldEvent, type InjectionScan } from "./shield.js";

export interface ShieldContextValue {
  /** All shield events captured since the provider mounted */
  events: ShieldEvent[];
  /** Run injection detection on a string. Pure, no side effects. */
  scan: (text: string) => InjectionScan;
  /** Wrap untrusted content in semantic boundary tags */
  wrap: (content: string, label: string) => string;
  /** Clear the in-memory event log */
  clearEvents: () => void;
}

const ShieldContext = createContext<ShieldContextValue | null>(null);

export function ShieldProvider({ children, maxEvents = 500 }: { children: ReactNode; maxEvents?: number }) {
  const [events, setEvents] = useState<ShieldEvent[]>([]);

  // Subscribe on mount, unsubscribe on unmount. The cleanup matters: without
  // it every remount stacked another handler for the life of the process,
  // each one calling setState on an unmounted component.
  useEffect(() => {
    return onShieldEvent((ev) => {
      setEvents((prev) => {
        const next = [...prev, ev];
        return next.length > maxEvents ? next.slice(-maxEvents) : next;
      });
    });
  }, [maxEvents]);

  const scan = useCallback((text: string) => detectInjection(text), []);
  const wrap = useCallback((content: string, label: string) => wrapUntrusted(content, label), []);
  const clearEvents = useCallback(() => setEvents([]), []);

  // Memoize so consumers only re-render when events actually change, not on
  // every render of whatever happens to contain the provider.
  const value = useMemo(() => ({ events, scan, wrap, clearEvents }), [events, scan, wrap, clearEvents]);
  return createElement(ShieldContext.Provider, { value }, children);
}

export function useShield(): ShieldContextValue {
  const ctx = useContext(ShieldContext);
  if (!ctx) throw new Error("useShield must be used inside <ShieldProvider>");
  return ctx;
}

/** Minimal hook for one-off scanning without a provider */
export function useInjectionScan(text: string): InjectionScan {
  return detectInjection(text);
}
