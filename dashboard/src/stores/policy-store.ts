import { create } from 'zustand';
import { immer } from 'zustand/middleware/immer';

export interface PolicySummary {
  id: string;
  name: string;
  layer: 'cel' | 'ifc' | 'adapter' | 'delegation' | 'secret-scan';
  enabled: boolean;
  bundleVersion: number;
  celExpression?: string;
  description?: string;
}

export interface BundleStatus {
  version: number;
  previousVersion: number;
  hash: string;
  signatureVerified: boolean;
  policyCount: number;
  adapterCount: number;
  activatedAt: number;
}

const MAX_POLICIES = 900;

interface PolicyState {
  policies: PolicySummary[];
  bundleStatus: BundleStatus | null;
  selectedPolicyId: string | null;

  setPolicies(policies: PolicySummary[]): void;
  mergePolicies(policies: PolicySummary[]): void;
  upsertPolicy(policy: PolicySummary): void;
  mergePolicies(policies: PolicySummary[]): void;
  setBundleStatus(status: BundleStatus): void;
  selectPolicy(id: string | null): void;
}

export const usePolicyStore = create<PolicyState>()(
  immer((set) => ({
    policies: [],
    bundleStatus: null,
    selectedPolicyId: null,

    setPolicies(policies) {
      set((draft) => {
        draft.policies = policies.slice(0, MAX_POLICIES);
      });
    },

    // Updates existing policies by ID (preserving celExpression if incoming lacks one)
    // and appends new policies — never removes existing entries.
    mergePolicies(incoming) {
      set((draft) => {
        for (const p of incoming) {
          const idx = draft.policies.findIndex(e => e.id === p.id);
          if (idx >= 0) {
            draft.policies[idx] = {
              ...p,
              celExpression: p.celExpression ?? draft.policies[idx].celExpression,
            };
          } else if (draft.policies.length < MAX_POLICIES) {
            draft.policies.push(p);
          }
        }
      });
    },

    upsertPolicy(policy) {
      set((draft) => {
        const idx = draft.policies.findIndex(p => p.id === policy.id);
        if (idx >= 0) {
          draft.policies[idx] = policy;
        } else if (draft.policies.length < MAX_POLICIES) {
          draft.policies.push(policy);
        }
      });
    },

    mergePolicies(policies) {
      set((draft) => {
        for (const p of policies) {
          const idx = draft.policies.findIndex(existing => existing.id === p.id);
          if (idx >= 0) {
            draft.policies[idx] = p;
          } else if (draft.policies.length < MAX_POLICIES) {
            draft.policies.push(p);
          }
        }
      });
    },

    setBundleStatus(status) {
      set((draft) => {
        draft.bundleStatus = status;
      });
    },

    selectPolicy(id) {
      set((draft) => {
        draft.selectedPolicyId = id;
      });
    },
  })),
);
