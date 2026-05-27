import { createContext, useContext, useRef, type ReactNode } from 'react';

// WebSocket URL per ADR-015 / ADR-011. Read from Vite env at module load time.
const DEFAULT_WS_URL = 'ws://localhost:9090/ws';

// Vite replaces import.meta.env.VITE_* at build time; the type is ImportMetaEnv.
function resolveWsUrl(): string {
  try {
    return import.meta.env.VITE_DAEMON_WS_URL ?? DEFAULT_WS_URL;
  } catch {
    return DEFAULT_WS_URL;
  }
}

interface StoreContextValue {
  daemonWsUrl: string;
}

const StoreContext = createContext<StoreContextValue | null>(null);

export function StoreProvider({ children }: { children: ReactNode }) {
  // Read once at mount; env vars don't change at runtime.
  const wsUrlRef = useRef<string>(resolveWsUrl());

  return (
    <StoreContext.Provider value={{ daemonWsUrl: wsUrlRef.current }}>
      {children}
    </StoreContext.Provider>
  );
}

export function useDaemonWsUrl(): string {
  const ctx = useContext(StoreContext);
  if (ctx === null) {
    throw new Error('useDaemonWsUrl must be used inside StoreProvider');
  }
  return ctx.daemonWsUrl;
}
