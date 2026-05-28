import { create } from 'zustand';
import { immer } from 'zustand/middleware/immer';
import type { ConnectionState } from '../types/events';

export interface ConnectionMetrics {
  reconnectCount: number;
  lastConnectedAt: number;
  lastDisconnectedAt: number;
  latencyMs: number;
  // Server clock offset relative to client (ms). Used for server-timestamp ordering.
  clockOffsetMs: number;
  droppedMessages: number;
}

const MAX_BUFFERED = 500;

interface StreamState {
  connectionState: ConnectionState;
  lastSequenceId: number;
  metrics: ConnectionMetrics;
  // Messages buffered while the tab is backgrounded.
  backgroundBuffer: string[];
  parseErrorCount: number;
  requestMockMode: boolean;

  setConnectionState(state: ConnectionState): void;
  updateLastSequence(seq: number): void;
  updateMetrics(update: Partial<ConnectionMetrics>): void;
  bufferMessage(raw: string): void;
  flushBuffer(): string[];
  recordParseError(): void;
  reset(): void;
  setRequestMockMode(v: boolean): void;
}

export const useStreamStore = create<StreamState>()(
  immer((set, get) => ({
    connectionState: 'IDLE',
    lastSequenceId: 0,
    metrics: {
      reconnectCount: 0,
      lastConnectedAt: 0,
      lastDisconnectedAt: 0,
      latencyMs: 0,
      clockOffsetMs: 0,
      droppedMessages: 0,
    },
    backgroundBuffer: [],
    parseErrorCount: 0,
    requestMockMode: false,

    setConnectionState(state) {
      set((draft) => {
        draft.connectionState = state;
        if (state === 'CONNECTED') {
          draft.metrics.lastConnectedAt = Date.now();
        } else if (state === 'DISCONNECTED') {
          draft.metrics.lastDisconnectedAt = Date.now();
        } else if (state === 'RECONNECTING') {
          draft.metrics.reconnectCount++;
        }
      });
    },

    updateLastSequence(seq) {
      set((draft) => {
        if (seq > draft.lastSequenceId) {
          draft.lastSequenceId = seq;
        }
      });
    },

    updateMetrics(update) {
      set((draft) => {
        Object.assign(draft.metrics, update);
      });
    },

    bufferMessage(raw) {
      set((draft) => {
        if (draft.backgroundBuffer.length >= MAX_BUFFERED) {
          draft.backgroundBuffer.shift();
          draft.metrics.droppedMessages++;
        }
        draft.backgroundBuffer.push(raw);
      });
    },

    flushBuffer() {
      const messages = get().backgroundBuffer;
      set((draft) => {
        draft.backgroundBuffer = [];
      });
      return messages;
    },

    recordParseError() {
      set((draft) => {
        draft.parseErrorCount++;
      });
    },

    reset() {
      set((draft) => {
        draft.connectionState = 'IDLE';
        draft.lastSequenceId = 0;
        draft.backgroundBuffer = [];
        draft.parseErrorCount = 0;
      });
    },

    setRequestMockMode(v) {
      set((draft) => {
        draft.requestMockMode = v;
      });
    },
  })),
);
