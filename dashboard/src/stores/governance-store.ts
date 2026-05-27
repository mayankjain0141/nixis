import { create } from 'zustand';
import { immer } from 'zustand/middleware/immer';
import type { SecurityLabel } from '../types/aegis';
import type { Verdict, LabelState } from '../types/events';

export interface GovernanceEvent {
  id: string;
  sessionId: string;
  tool: string;
  verdict: Verdict;
  reason: string;
  policyId: string;
  enforcingLayer: string;
  label: SecurityLabel;
  labelState: LabelState;
  latencyNs: number;
  aegisSequence: number;
  timestamp: number;
}

export interface SessionLabelEntry {
  sessionId: string;
  label: SecurityLabel;
  state: LabelState;
  updatedAt: number;
}

const MAX_EVENTS = 1000;

// elevate: raises each dimension to the maximum of current and incoming.
// Labels are one-way-up — no regression allowed (invariant INV-004).
function elevate(current: SecurityLabel, incoming: SecurityLabel): SecurityLabel {
  return {
    confidentiality: Math.max(current.confidentiality, incoming.confidentiality),
    integrity: Math.max(current.integrity, incoming.integrity),
    categories: current.categories | incoming.categories,
  };
}

interface GovernanceState {
  events: GovernanceEvent[];
  sessionLabels: Map<string, SessionLabelEntry>;
  totalDenials: number;
  totalAllows: number;

  appendEvent(event: GovernanceEvent): void;
  // updateLabel applies elevate semantics — never overwrites with a lower value.
  updateLabel(sessionId: string, incoming: SecurityLabel, state: LabelState): void;
  clear(): void;
}

export const useGovernanceStore = create<GovernanceState>()(
  immer((set) => ({
    events: [],
    sessionLabels: new Map(),
    totalDenials: 0,
    totalAllows: 0,

    appendEvent(event) {
      set((draft) => {
        draft.events.push(event);
        if (draft.events.length > MAX_EVENTS) {
          draft.events.splice(0, draft.events.length - MAX_EVENTS);
        }
        if (event.verdict === 'deny' || event.verdict === 'require_approval') {
          draft.totalDenials++;
        } else {
          draft.totalAllows++;
        }
      });
    },

    updateLabel(sessionId, incoming, state) {
      set((draft) => {
        const existing = draft.sessionLabels.get(sessionId);
        const elevated = existing ? elevate(existing.label, incoming) : incoming;
        draft.sessionLabels.set(sessionId, {
          sessionId,
          label: elevated,
          state,
          updatedAt: Date.now(),
        });
      });
    },

    clear() {
      set((draft) => {
        draft.events = [];
        draft.sessionLabels = new Map();
        draft.totalDenials = 0;
        draft.totalAllows = 0;
      });
    },
  })),
);
