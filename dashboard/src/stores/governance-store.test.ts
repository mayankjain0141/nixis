import { describe, it, expect, beforeEach } from 'vitest';
import { useGovernanceStore } from './governance-store';
import type { GovernanceEvent } from './governance-store';
import type { SecurityLabel } from '../types/aegis';

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
});
