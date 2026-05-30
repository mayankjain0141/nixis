import { create } from 'zustand';
import { immer } from 'zustand/middleware/immer';
import type { SecurityLabel } from '../types/nixis';
import type { LabelState } from '../types/events';

export interface LatticeNode {
  sessionId: string;
  label: SecurityLabel;
  state: LabelState;
  escalationCount: number;
  lastEscalatedAt: number;
}

const MAX_SESSIONS = 100;

interface LatticeState {
  nodes: Map<string, LatticeNode>;
  selectedSessionId: string | null;

  upsertNode(sessionId: string, label: SecurityLabel, state: LabelState): void;
  removeNode(sessionId: string): void;
  selectSession(id: string | null): void;
  getNode(sessionId: string): LatticeNode | undefined;
}

export const useLatticeStore = create<LatticeState>()(
  immer((set, get) => ({
    nodes: new Map(),
    selectedSessionId: null,

    upsertNode(sessionId, label, state) {
      set((draft) => {
        const existing = draft.nodes.get(sessionId);
        if (existing) {
          const wasEscalation =
            label.confidentiality > existing.label.confidentiality ||
            label.integrity > existing.label.integrity ||
            (label.categories & ~existing.label.categories) !== 0;
          draft.nodes.set(sessionId, {
            sessionId,
            label,
            state,
            escalationCount: existing.escalationCount + (wasEscalation ? 1 : 0),
            lastEscalatedAt: wasEscalation ? Date.now() : existing.lastEscalatedAt,
          });
        } else {
          if (draft.nodes.size >= MAX_SESSIONS) {
            // Evict the oldest node (smallest lastEscalatedAt).
            let oldestKey = '';
            let oldestTime = Infinity;
            for (const [k, v] of draft.nodes) {
              if (v.lastEscalatedAt < oldestTime) {
                oldestTime = v.lastEscalatedAt;
                oldestKey = k;
              }
            }
            if (oldestKey) draft.nodes.delete(oldestKey);
          }
          draft.nodes.set(sessionId, {
            sessionId,
            label,
            state,
            escalationCount: 0,
            lastEscalatedAt: 0,
          });
        }
      });
    },

    removeNode(sessionId) {
      set((draft) => {
        draft.nodes.delete(sessionId);
        if (draft.selectedSessionId === sessionId) {
          draft.selectedSessionId = null;
        }
      });
    },

    selectSession(id) {
      set((draft) => {
        draft.selectedSessionId = id;
      });
    },

    getNode(sessionId) {
      return get().nodes.get(sessionId);
    },
  })),
);
