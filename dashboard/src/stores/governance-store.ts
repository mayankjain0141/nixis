import { create } from 'zustand';
import { immer } from 'zustand/middleware/immer';
import type { SecurityLabel } from '../types/aegis';
import type { Verdict, LabelState } from '../types/events';

export interface DelegationHop {
  hopIndex: number;
  delegatorId: string;
  delegateeId: string;
  grantedLabel: {
    confidentiality: number;
    integrity: number;
    categories: number;
  };
  ceilingLabel: {
    confidentiality: number;
    integrity: number;
    categories: number;
  };
  expiresAt?: number;
}

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
  // Optional fields populated by policy.evaluated / policy.denied events
  securityLabel?: SecurityLabel;
  requestedLabel?: SecurityLabel;
  capabilityCeiling?: SecurityLabel;
  celExpression?: string;
  requestArgs?: string;   // the actual command / path / query that was evaluated
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
  delegationChains: Map<string, DelegationHop[]>;
  totalDenials: number;
  totalAllows: number;
  filterVerdict: string | null;

  appendEvent(event: GovernanceEvent): void;
  // updateLabel applies elevate semantics — never overwrites with a lower value.
  updateLabel(sessionId: string, incoming: SecurityLabel, state: LabelState): void;
  updateDelegationChain(sessionId: string, hops: DelegationHop[]): void;
  setFilterVerdict(verdict: string | null): void;
  clear(): void;
}

export const useGovernanceStore = create<GovernanceState>()(
  immer((set) => ({
    events: [],
    sessionLabels: new Map(),
    delegationChains: new Map(),
    totalDenials: 0,
    totalAllows: 0,
    filterVerdict: null,

    appendEvent(event) {
      set((draft) => {
        // Deduplicate by ID — guards against StrictMode double-mount where two
        // generator instances start with the same sequence counter (both emit
        // id="mock-1", "mock-2", …) and the first run's events stay in the store.
        if (draft.events.some((e) => e.id === event.id)) return;
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

    updateDelegationChain(sessionId, hops) {
      set((draft) => {
        draft.delegationChains.set(sessionId, hops);
      });
    },

    setFilterVerdict(verdict) {
      set((draft) => {
        draft.filterVerdict = verdict;
      });
    },

    clear() {
      set((draft) => {
        draft.events.length = 0;
        draft.sessionLabels.clear();
        draft.delegationChains = new Map();
        draft.totalDenials = 0;
        draft.totalAllows = 0;
      });
    },
  })),
);
