/**
 * React integration for shield — for browser apps that can't write to a filesystem.
 *
 * Usage:
 *   // In your app root:
 *   import { ShieldProvider } from "@local/shield/react";
 *   <ShieldProvider><App /></ShieldProvider>
 *
 *   // Anywhere in your tree:
 *   import { useShield } from "@local/shield/react";
 *   const { events, scan, wrap } = useShield();
 */

// This file uses React but declares it as a peer dep so the package stays lean.
// The importing app must have React installed.
import { useState, useEffect, useCallback, createContext, useContext, createElement, useRef, type ReactNode } from "react";
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
  const registeredRef = useRef(false);

  useEffect(() => {
    if (registeredRef.current) return;
    registeredRef.current = true;
    onShieldEvent((ev) => {
      setEvents((prev) => {
        const next = [...prev, ev];
        return next.length > maxEvents ? next.slice(-maxEvents) : next;
      });
    });
  }, [maxEvents]);

  const scan = useCallback((text: string) => detectInjection(text), []);
  const wrap = useCallback((content: string, label: string) => wrapUntrusted(content, label), []);
  const clearEvents = useCallback(() => setEvents([]), []);

  return createElement(ShieldContext.Provider, { value: { events, scan, wrap, clearEvents } }, children);
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
