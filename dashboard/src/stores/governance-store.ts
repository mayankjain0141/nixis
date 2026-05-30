import { create } from 'zustand';
import { immer } from 'zustand/middleware/immer';
import { enableMapSet } from 'immer';
import type { SecurityLabel } from '../types/nixis';
import type { Verdict, LabelState } from '../types/events';

enableMapSet();

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
  reason?: string;
  capabilities?: string[];
}

export interface AuditCheckpoint {
  sequence: number;
  hash: string;
  prevHash: string | null;
  eventCount: number;
  timestamp: number;
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
  nixisSequence: number;
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
const MAX_AUDIT_CHECKPOINTS = 500;

// elevate: raises each dimension to the maximum of current and incoming.
// Labels are one-way-up — no regression allowed (invariant INV-004).
function elevate(current: SecurityLabel, incoming: SecurityLabel): SecurityLabel {
  return {
    confidentiality: Math.max(current.confidentiality, incoming.confidentiality),
    integrity: Math.max(current.integrity, incoming.integrity),
    categories: current.categories | incoming.categories,
  };
}

function computeChainIntact(checkpoints: AuditCheckpoint[]): boolean {
  for (let i = 0; i < checkpoints.length; i++) {
    if (i === 0) {
      if (checkpoints[i].prevHash !== null) return false;
    } else {
      if (checkpoints[i].prevHash !== checkpoints[i - 1].hash) return false;
    }
  }
  return true;
}

function sumEventCounts(checkpoints: AuditCheckpoint[]): number {
  return checkpoints.reduce((acc, cp) => acc + cp.eventCount, 0);
}

interface GovernanceState {
  events: GovernanceEvent[];
  sessionLabels: Map<string, SessionLabelEntry>;
  delegationChains: Map<string, DelegationHop[]>;
  totalDenials: number;
  totalAllows: number;
  filterVerdict: string | null;
  filterSession: string | null;
  filterPolicy: string | null;

  // Session display names: sessionId → "You (main)" | "Agent 1" | etc.
  sessionDisplayNames: Map<string, string>;

  // Per-session allow/deny counters
  sessionCounters: Map<string, { allows: number; denies: number }>;

  // Typed audit checkpoints
  auditCheckpoints: AuditCheckpoint[];
  auditChainIntact: boolean;
  totalSealedEvents: number;

  // Audit modal open state
  auditModalOpen: boolean;

  appendEvent(event: GovernanceEvent): void;
  // updateLabel applies elevate semantics — never overwrites with a lower value.
  updateLabel(sessionId: string, incoming: SecurityLabel, state: LabelState): void;
  updateDelegationChain(sessionId: string, hops: DelegationHop[]): void;
  setFilterVerdict(verdict: string | null): void;
  setFilterSession(sessionId: string | null): void;
  setFilterPolicy(policyId: string | null): void;
  setSessionDisplayName(sessionId: string, name: string): void;
  incrementSessionCounter(sessionId: string, verdict: 'allow' | 'deny'): void;
  appendAuditCheckpoint(checkpoint: AuditCheckpoint): void;
  setAuditModalOpen(open: boolean): void;
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
    filterSession: null,
    filterPolicy: null,
    sessionDisplayNames: new Map(),
    sessionCounters: new Map(),
    auditCheckpoints: [],
    auditChainIntact: true,
    totalSealedEvents: 0,
    auditModalOpen: false,

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
        if (event.verdict === 'allow' || event.verdict === 'deny') {
          const sid = event.sessionId;
          const current = draft.sessionCounters.get(sid) ?? { allows: 0, denies: 0 };
          draft.sessionCounters.set(sid, {
            allows: event.verdict === 'allow' ? current.allows + 1 : current.allows,
            denies: event.verdict === 'deny' ? current.denies + 1 : current.denies,
          });
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

    setFilterSession(sessionId) {
      set((draft) => {
        draft.filterSession = sessionId;
      });
    },

    setFilterPolicy(policyId) {
      set((draft) => {
        draft.filterPolicy = policyId;
      });
    },

    setSessionDisplayName(sessionId, name) {
      set((draft) => {
        draft.sessionDisplayNames.set(sessionId, name);
      });
    },

    incrementSessionCounter(sessionId, verdict) {
      set((draft) => {
        const current = draft.sessionCounters.get(sessionId) ?? { allows: 0, denies: 0 };
        draft.sessionCounters.set(sessionId, {
          allows: verdict === 'allow' ? current.allows + 1 : current.allows,
          denies: verdict === 'deny' ? current.denies + 1 : current.denies,
        });
      });
    },

    appendAuditCheckpoint(checkpoint) {
      set((draft) => {
        draft.auditCheckpoints.push(checkpoint);
        if (draft.auditCheckpoints.length > MAX_AUDIT_CHECKPOINTS) {
          draft.auditCheckpoints.splice(0, draft.auditCheckpoints.length - MAX_AUDIT_CHECKPOINTS);
        }
        draft.auditChainIntact = computeChainIntact(draft.auditCheckpoints);
        draft.totalSealedEvents = sumEventCounts(draft.auditCheckpoints);
      });
    },

    setAuditModalOpen(open) {
      set((draft) => {
        draft.auditModalOpen = open;
      });
    },

    clear() {
      set((draft) => {
        draft.events.length = 0;
        draft.sessionLabels.clear();
        draft.delegationChains = new Map();
        draft.totalDenials = 0;
        draft.totalAllows = 0;
        draft.sessionDisplayNames = new Map();
        draft.sessionCounters = new Map();
        draft.auditCheckpoints = [];
        draft.auditChainIntact = true;
        draft.totalSealedEvents = 0;
        draft.auditModalOpen = false;
      });
    },
  })),
);
