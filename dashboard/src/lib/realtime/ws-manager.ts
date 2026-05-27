// WebSocket connection manager — WS-16.
// State machine: IDLE → CONNECTING → CONNECTED → DISCONNECTED → RECONNECTING → CONNECTING...
// Never fabricates events during disconnect. Server timestamps only for ordering.

import type { ConnectionState } from '../../types/events';

export interface MessageMeta {
  receivedAt: number; // performance.now() at receipt, for latency measurement only
}

export interface ClientMessage {
  type: string;
  [key: string]: unknown;
}

export interface ConnectionMetrics {
  reconnectCount: number;
  lastConnectedAt: number;
  lastDisconnectedAt: number;
  latencyMs: number;
  clockOffsetMs: number;
}

export interface IWebSocketManager {
  connect(): void;
  disconnect(): void;
  send(message: ClientMessage): void;
  onMessage(handler: (raw: string, meta: MessageMeta) => void): () => void;
  getState(): ConnectionState;
  getMetrics(): ConnectionMetrics;
}

// Exponential backoff delays in ms: 1s, 2s, 4s, 8s, 16s, then capped.
const BACKOFF_DELAYS = [1000, 2000, 4000, 8000, 16000];
const HEARTBEAT_DEAD_THRESHOLD_MS = 60_000;
const TAB_BUFFER_CAPACITY = 500;

export function createWebSocketManager(wsUrl: string): IWebSocketManager {
  let ws: WebSocket | null = null;
  let state: ConnectionState = 'IDLE';
  let reconnectAttempt = 0;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let heartbeatTimer: ReturnType<typeof setTimeout> | null = null;
  let lastHeartbeatAt = 0;
  let lastSequenceId = 0;
  let tabHidden = false;
  const tabBuffer: string[] = [];
  const handlers: Array<(raw: string, meta: MessageMeta) => void> = [];
  const metrics: ConnectionMetrics = {
    reconnectCount: 0,
    lastConnectedAt: 0,
    lastDisconnectedAt: 0,
    latencyMs: 0,
    clockOffsetMs: 0,
  };

  function setState(next: ConnectionState): void {
    state = next;
  }

  function clearTimers(): void {
    if (reconnectTimer !== null) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    if (heartbeatTimer !== null) { clearTimeout(heartbeatTimer); heartbeatTimer = null; }
  }

  function scheduleHeartbeatCheck(): void {
    if (heartbeatTimer !== null) clearTimeout(heartbeatTimer);
    heartbeatTimer = setTimeout(() => {
      const elapsed = Date.now() - lastHeartbeatAt;
      if (elapsed > HEARTBEAT_DEAD_THRESHOLD_MS && state === 'CONNECTED') {
        // Connection is dead — force a reconnect.
        ws?.close();
        scheduleReconnect();
      } else if (state === 'CONNECTED') {
        scheduleHeartbeatCheck();
      }
    }, HEARTBEAT_DEAD_THRESHOLD_MS);
  }

  function scheduleReconnect(): void {
    setState('RECONNECTING');
    metrics.reconnectCount++;
    metrics.lastDisconnectedAt = Date.now();
    const delay = BACKOFF_DELAYS[Math.min(reconnectAttempt, BACKOFF_DELAYS.length - 1)];
    const jitter = Math.random() * delay * 0.1; // 10% jitter
    reconnectAttempt++;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      openConnection();
    }, delay + jitter);
  }

  function openConnection(): void {
    if (state === 'CONNECTED' || state === 'CONNECTING') return;
    setState('CONNECTING');
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      setState('CONNECTED');
      metrics.lastConnectedAt = Date.now();
      lastHeartbeatAt = Date.now();
      reconnectAttempt = 0;
      scheduleHeartbeatCheck();

      // On reconnect, send resumeFrom so daemon can backfill missed events.
      if (lastSequenceId > 0) {
        manager.send({ type: 'subscribe.filter', resumeFrom: lastSequenceId });
      }

      // Flush buffered messages from when the tab was hidden.
      if (tabBuffer.length > 0) {
        const buffered = tabBuffer.splice(0);
        for (const raw of buffered) {
          dispatch(raw);
        }
      }
    };

    ws.onmessage = (ev: MessageEvent) => {
      const raw = typeof ev.data === 'string' ? ev.data : '';
      if (!raw) return;

      // Track sequence from heartbeat to update clockOffset.
      try {
        const parsed = JSON.parse(raw) as Record<string, unknown>;
        if (parsed.type === 'stream.heartbeat' && typeof parsed.serverTime === 'number') {
          metrics.clockOffsetMs = parsed.serverTime as number - Date.now();
          lastHeartbeatAt = Date.now();
          scheduleHeartbeatCheck();
        }
        if (typeof parsed.aegissequence === 'number') {
          lastSequenceId = Math.max(lastSequenceId, parsed.aegissequence as number);
        }
      } catch {
        // Non-JSON messages are allowed (e.g. pong); ignore parse failure here.
      }

      if (tabHidden) {
        if (tabBuffer.length < TAB_BUFFER_CAPACITY) {
          tabBuffer.push(raw);
        }
        // Drop silently when buffer is full rather than creating backpressure.
      } else {
        dispatch(raw);
      }
    };

    ws.onerror = () => {
      // onerror is always followed by onclose; let onclose handle reconnect.
    };

    ws.onclose = () => {
      clearTimers();
      if (state !== 'IDLE') {
        metrics.lastDisconnectedAt = Date.now();
        scheduleReconnect();
      }
    };
  }

  function dispatch(raw: string): void {
    const meta: MessageMeta = { receivedAt: performance.now() };
    for (const h of handlers) {
      h(raw, meta);
    }
  }

  // Listen to Page Visibility API to buffer messages when tab is hidden.
  if (typeof document !== 'undefined') {
    document.addEventListener('visibilitychange', () => {
      tabHidden = document.visibilityState === 'hidden';
      if (!tabHidden && tabBuffer.length > 0) {
        // Tab became visible — flush buffer.
        const buffered = tabBuffer.splice(0);
        for (const raw of buffered) {
          dispatch(raw);
        }
      }
    });
  }

  const manager: IWebSocketManager = {
    connect() {
      openConnection();
    },

    disconnect() {
      clearTimers();
      setState('IDLE');
      reconnectAttempt = 0;
      ws?.close();
      ws = null;
    },

    send(message) {
      if (ws !== null && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(message));
      }
    },

    onMessage(handler) {
      handlers.push(handler);
      return () => {
        const idx = handlers.indexOf(handler);
        if (idx >= 0) handlers.splice(idx, 1);
      };
    },

    getState() {
      return state;
    },

    getMetrics() {
      return { ...metrics };
    },
  };

  return manager;
}
