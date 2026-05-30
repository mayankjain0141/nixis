import { create } from 'zustand';
import { immer } from 'zustand/middleware/immer';

export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface ThreatEvent {
  id: string;
  type: 'secret.found' | 'label.tainted' | 'system.error';
  sessionId: string;
  tool: string;
  severity: ThreatSeverity;
  description: string;
  aegisSequence: number;
  timestamp: number;
  acknowledged: boolean;
  humanDescription: string;
  impact: string;
  relatedSessionName: string;
}

const MAX_THREATS = 200;

interface ThreatState {
  threats: ThreatEvent[];
  unacknowledgedCount: number;

  appendThreat(threat: ThreatEvent): void;
  acknowledge(id: string): void;
  acknowledgeAll(): void;
  clear(): void;
}

export const useThreatStore = create<ThreatState>()(
  immer((set) => ({
    threats: [],
    unacknowledgedCount: 0,

    appendThreat(threat) {
      set((draft) => {
        draft.threats.unshift(threat); // newest first
        if (draft.threats.length > MAX_THREATS) {
          draft.threats.length = MAX_THREATS;
        }
        if (!threat.acknowledged) {
          draft.unacknowledgedCount++;
        }
      });
    },

    acknowledge(id) {
      set((draft) => {
        const t = draft.threats.find(x => x.id === id);
        if (t && !t.acknowledged) {
          t.acknowledged = true;
          draft.unacknowledgedCount = Math.max(0, draft.unacknowledgedCount - 1);
        }
      });
    },

    acknowledgeAll() {
      set((draft) => {
        for (const t of draft.threats) {
          t.acknowledged = true;
        }
        draft.unacknowledgedCount = 0;
      });
    },

    clear() {
      set((draft) => {
        draft.threats = [];
        draft.unacknowledgedCount = 0;
      });
    },
  })),
);
