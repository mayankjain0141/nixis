import { describe, it, expect, beforeEach } from 'vitest';
import { useGovernanceStore } from './governance-store';
import type { GovernanceEvent } from './governance-store';
import type { SecurityLabel } from '../types/aegis';
import type { DelegationHop } from './governance-store';

function makeEvent(overrides: Partial<GovernanceEvent> = {}): GovernanceEvent {
  return {
    id: `evt-${Math.random().toString(36).slice(2)}`,
    sessionId: 'sess-1',
    tool: 'Shell',
    verdict: 'allow',
    reason: '',
    policyId: 'pol-1',
    enforcingLayer: 'adapter',
    label: { confidentiality: 0, integrity: 0, categories: 0 },
    labelState: 'fresh',
    latencyNs: 1000,
    aegisSequence: 1,
    timestamp: Date.now(),
    ...overrides,
  };
}

describe('useGovernanceStore', () => {
  beforeEach(() => {
    useGovernanceStore.getState().clear();
  });

  describe('appendEvent', () => {
    it('adds events to the store', () => {
      useGovernanceStore.getState().appendEvent(makeEvent({ verdict: 'allow' }));
      expect(useGovernanceStore.getState().events).toHaveLength(1);
    });

    it('counts denials and allows separately', () => {
      useGovernanceStore.getState().appendEvent(makeEvent({ verdict: 'allow' }));
      useGovernanceStore.getState().appendEvent(makeEvent({ verdict: 'deny' }));
      useGovernanceStore.getState().appendEvent(makeEvent({ verdict: 'require_approval' }));
      useGovernanceStore.getState().appendEvent(makeEvent({ verdict: 'audit' }));
      const s = useGovernanceStore.getState();
      expect(s.totalAllows).toBe(2);  // allow + audit
      expect(s.totalDenials).toBe(2); // deny + require_approval
    });

    it('caps the event buffer at MAX_EVENTS (1000)', () => {
      for (let i = 0; i < 1005; i++) {
        useGovernanceStore.getState().appendEvent(makeEvent({ aegisSequence: i }));
      }
      expect(useGovernanceStore.getState().events.length).toBe(1000);
    });

    it('retains the most recent events when capped', () => {
      for (let i = 0; i < 1005; i++) {
        useGovernanceStore.getState().appendEvent(makeEvent({ aegisSequence: i, id: `evt-${i}` }));
      }
      const events = useGovernanceStore.getState().events;
      expect(events[0].aegisSequence).toBe(5);
      expect(events[999].aegisSequence).toBe(1004);
    });
  });

  describe('updateLabel — elevate semantics', () => {
    const base: SecurityLabel = { confidentiality: 16384, integrity: 16384, categories: 0 };

    it('sets a new label for a new session', () => {
      useGovernanceStore.getState().updateLabel('sess-new', base, 'fresh');
      const entry = useGovernanceStore.getState().sessionLabels.get('sess-new');
      expect(entry?.label.confidentiality).toBe(16384);
    });

    it('raises confidentiality when incoming is higher (elevate)', () => {
      useGovernanceStore.getState().updateLabel('sess-1', base, 'fresh');
      useGovernanceStore.getState().updateLabel('sess-1', { confidentiality: 32768, integrity: 0, categories: 0 }, 'escalated');
      const entry = useGovernanceStore.getState().sessionLabels.get('sess-1');
      expect(entry?.label.confidentiality).toBe(32768);
    });

    it('never lowers confidentiality (label regression is forbidden)', () => {
      useGovernanceStore.getState().updateLabel('sess-1', { confidentiality: 32768, integrity: 0, categories: 0 }, 'escalated');
      useGovernanceStore.getState().updateLabel('sess-1', { confidentiality: 0, integrity: 0, categories: 0 }, 'fresh');
      const entry = useGovernanceStore.getState().sessionLabels.get('sess-1');
      expect(entry?.label.confidentiality).toBe(32768);
    });

    it('ORs category bits (never loses category information)', () => {
      useGovernanceStore.getState().updateLabel('sess-1', { confidentiality: 0, integrity: 0, categories: 0b001 }, 'fresh');
      useGovernanceStore.getState().updateLabel('sess-1', { confidentiality: 0, integrity: 0, categories: 0b010 }, 'escalated');
      const entry = useGovernanceStore.getState().sessionLabels.get('sess-1');
      expect(entry?.label.categories).toBe(0b011);
    });

    it('never overwrites with {conf:3} when current is {conf:5}', () => {
      useGovernanceStore.getState().updateLabel('s', { confidentiality: 5, integrity: 0, categories: 0 }, 'fresh');
      useGovernanceStore.getState().updateLabel('s', { confidentiality: 3, integrity: 0, categories: 0 }, 'fresh');
      expect(useGovernanceStore.getState().sessionLabels.get('s')?.label.confidentiality).toBe(5);
    });
  });

  describe('clear', () => {
    it('resets all state', () => {
      useGovernanceStore.getState().appendEvent(makeEvent());
      useGovernanceStore.getState().updateLabel('s', { confidentiality: 1, integrity: 0, categories: 0 }, 'fresh');
      useGovernanceStore.getState().clear();
      const s = useGovernanceStore.getState();
      expect(s.events).toHaveLength(0);
      expect(s.sessionLabels.size).toBe(0);
      expect(s.totalDenials).toBe(0);
      expect(s.totalAllows).toBe(0);
    });
  });

  describe('updateDelegationChain', () => {
    it('stores hops without overwriting other sessions', () => {
      const hop: DelegationHop = {
        hopIndex: 0,
        delegatorId: 'alice',
        delegateeId: 'bob',
        grantedLabel: { confidentiality: 32768, integrity: 16384, categories: 0 },
        ceilingLabel: { confidentiality: 16384, integrity: 8192, categories: 0 },
      };
      useGovernanceStore.getState().updateDelegationChain('session-1', [hop]);
      useGovernanceStore.getState().updateDelegationChain('session-2', []);

      const chains = useGovernanceStore.getState().delegationChains;
      const s1 = chains instanceof Map ? chains.get('session-1') : (chains as Record<string, DelegationHop[]>)['session-1'];
      expect(s1).toHaveLength(1);
      expect(s1![0].delegatorId).toBe('alice');
    });
  });

  describe('setFilterSession', () => {
    it('sets filterSession to the given id', () => {
      useGovernanceStore.getState().setFilterSession('sess-abc');
      expect(useGovernanceStore.getState().filterSession).toBe('sess-abc');
    });

    it('calling with same id twice clears to null on second call via external toggle', () => {
      useGovernanceStore.getState().setFilterSession('sess-abc');
      const current = useGovernanceStore.getState().filterSession;
      useGovernanceStore.getState().setFilterSession(current === 'sess-abc' ? null : 'sess-abc');
      expect(useGovernanceStore.getState().filterSession).toBeNull();
    });

    it('clears filterSession when called with null', () => {
      useGovernanceStore.getState().setFilterSession('sess-abc');
      useGovernanceStore.getState().setFilterSession(null);
      expect(useGovernanceStore.getState().filterSession).toBeNull();
    });

    it('initialises to null', () => {
      expect(useGovernanceStore.getState().filterSession).toBeNull();
    });
  });

  describe('setFilterPolicy', () => {
    it('sets filterPolicy to the given id', () => {
      useGovernanceStore.getState().setFilterPolicy('pol-xyz');
      expect(useGovernanceStore.getState().filterPolicy).toBe('pol-xyz');
    });

    it('calling with same id twice clears to null on second call via external toggle', () => {
      useGovernanceStore.getState().setFilterPolicy('pol-xyz');
      const current = useGovernanceStore.getState().filterPolicy;
      useGovernanceStore.getState().setFilterPolicy(current === 'pol-xyz' ? null : 'pol-xyz');
      expect(useGovernanceStore.getState().filterPolicy).toBeNull();
    });

    it('clears filterPolicy when called with null', () => {
      useGovernanceStore.getState().setFilterPolicy('pol-xyz');
      useGovernanceStore.getState().setFilterPolicy(null);
      expect(useGovernanceStore.getState().filterPolicy).toBeNull();
    });

    it('initialises to null', () => {
      expect(useGovernanceStore.getState().filterPolicy).toBeNull();
    });
  });

  // TestStore_ElevateSemantics: updateLabel({conf:3}, {conf:5}) → result {conf:5}, never {conf:3}
  describe('TestStore_ElevateSemantics', () => {
    it('updateLabel({conf:3}, {conf:5}) → confidentiality becomes 5, never reverts to 3', () => {
      useGovernanceStore.getState().updateLabel('sess-elev', { confidentiality: 3, integrity: 0, categories: 0 }, 'fresh');
      useGovernanceStore.getState().updateLabel('sess-elev', { confidentiality: 5, integrity: 0, categories: 0 }, 'escalated');
      const entry = useGovernanceStore.getState().sessionLabels.get('sess-elev');
      expect(entry?.label.confidentiality).toBe(5);
    });

    it('a subsequent lower-confidentiality update never reverts the raised value', () => {
      useGovernanceStore.getState().updateLabel('sess-elev2', { confidentiality: 5, integrity: 0, categories: 0 }, 'escalated');
      useGovernanceStore.getState().updateLabel('sess-elev2', { confidentiality: 3, integrity: 0, categories: 0 }, 'fresh');
      const entry = useGovernanceStore.getState().sessionLabels.get('sess-elev2');
      expect(entry?.label.confidentiality).toBe(5);
    });

    it('integrity is elevated using max (both high-water marks preserved)', () => {
      useGovernanceStore.getState().updateLabel('sess-int', { confidentiality: 0, integrity: 8, categories: 0 }, 'fresh');
      useGovernanceStore.getState().updateLabel('sess-int', { confidentiality: 0, integrity: 3, categories: 0 }, 'escalated');
      const entry = useGovernanceStore.getState().sessionLabels.get('sess-int');
      expect(entry?.label.integrity).toBe(8);
    });
  });
});
