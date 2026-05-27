import { describe, it, expect } from 'vitest';
import { GovernanceInvariantChecker } from './invariants';
import type { InvariantCheckerDeps } from './invariants';

function makeDeps(overrides: Partial<InvariantCheckerDeps> = {}): InvariantCheckerDeps {
  return {
    getGovernanceEvents: () => [],
    getSessionLabels: () => new Map(),
    getPolicyBundleVersion: () => null,
    getStreamBundleVersion: () => null,
    ...overrides,
  };
}

describe('GovernanceInvariantChecker', () => {
  describe('checkMonotonicSequence', () => {
    it('passes when events are in strictly increasing sequence order', () => {
      const checker = new GovernanceInvariantChecker(makeDeps({
        getGovernanceEvents: () => [
          { id: 'a', aegisSequence: 1, verdict: 'allow' },
          { id: 'b', aegisSequence: 2, verdict: 'allow' },
          { id: 'c', aegisSequence: 5, verdict: 'deny' },
        ],
      }));
      expect(checker.checkMonotonicSequence().passed).toBe(true);
    });

    it('fails when a sequence regression is detected', () => {
      const checker = new GovernanceInvariantChecker(makeDeps({
        getGovernanceEvents: () => [
          { id: 'a', aegisSequence: 5, verdict: 'allow' },
          { id: 'b', aegisSequence: 3, verdict: 'allow' },
        ],
      }));
      const result = checker.checkMonotonicSequence();
      expect(result.passed).toBe(false);
      expect(result.severity).toBe('P0-security');
      expect(result.message).toMatch(/regression/i);
    });

    it('fails when a duplicate sequence number appears', () => {
      const checker = new GovernanceInvariantChecker(makeDeps({
        getGovernanceEvents: () => [
          { id: 'a', aegisSequence: 4, verdict: 'allow' },
          { id: 'b', aegisSequence: 4, verdict: 'deny' },
        ],
      }));
      expect(checker.checkMonotonicSequence().passed).toBe(false);
    });

    it('passes with an empty event list', () => {
      expect(new GovernanceInvariantChecker(makeDeps()).checkMonotonicSequence().passed).toBe(true);
    });

    it('passes with a single event', () => {
      const checker = new GovernanceInvariantChecker(makeDeps({
        getGovernanceEvents: () => [{ id: 'a', aegisSequence: 100, verdict: 'deny' }],
      }));
      expect(checker.checkMonotonicSequence().passed).toBe(true);
    });
  });

  describe('checkDenyEdgesNeverGreen', () => {
    it('passes when all events have canonical verdicts', () => {
      const checker = new GovernanceInvariantChecker(makeDeps({
        getGovernanceEvents: () => [
          { id: 'a', aegisSequence: 1, verdict: 'deny' },
          { id: 'b', aegisSequence: 2, verdict: 'allow' },
          { id: 'c', aegisSequence: 3, verdict: 'require_approval' },
          { id: 'd', aegisSequence: 4, verdict: 'audit' },
        ],
      }));
      expect(checker.checkDenyEdgesNeverGreen().passed).toBe(true);
    });

    it('fails when an event has non-canonical verdict "escalate"', () => {
      const checker = new GovernanceInvariantChecker(makeDeps({
        getGovernanceEvents: () => [
          { id: 'a', aegisSequence: 1, verdict: 'allow' },
          { id: 'b', aegisSequence: 2, verdict: 'escalate' },
        ],
      }));
      const result = checker.checkDenyEdgesNeverGreen();
      expect(result.passed).toBe(false);
      expect(result.severity).toBe('P0-security');
      expect(result.message).toContain('escalate');
    });

    it('fails when an event has verdict "HITL"', () => {
      const checker = new GovernanceInvariantChecker(makeDeps({
        getGovernanceEvents: () => [{ id: 'x', aegisSequence: 1, verdict: 'HITL' }],
      }));
      expect(checker.checkDenyEdgesNeverGreen().passed).toBe(false);
    });

    it('fails when an event has verdict "block"', () => {
      const checker = new GovernanceInvariantChecker(makeDeps({
        getGovernanceEvents: () => [{ id: 'x', aegisSequence: 1, verdict: 'block' }],
      }));
      expect(checker.checkDenyEdgesNeverGreen().passed).toBe(false);
    });

    it('passes with empty event list', () => {
      expect(new GovernanceInvariantChecker(makeDeps()).checkDenyEdgesNeverGreen().passed).toBe(true);
    });
  });

  describe('checkVersionConsistency', () => {
    it('passes when both versions are null', () => {
      expect(new GovernanceInvariantChecker(makeDeps()).checkVersionConsistency().passed).toBe(true);
    });

    it('passes when only policy version is known', () => {
      const checker = new GovernanceInvariantChecker(makeDeps({
        getPolicyBundleVersion: () => 42,
        getStreamBundleVersion: () => null,
      }));
      expect(checker.checkVersionConsistency().passed).toBe(true);
    });

    it('passes when both versions match', () => {
      const checker = new GovernanceInvariantChecker(makeDeps({
        getPolicyBundleVersion: () => 42,
        getStreamBundleVersion: () => 42,
      }));
      expect(checker.checkVersionConsistency().passed).toBe(true);
    });

    it('fails when versions diverge', () => {
      const checker = new GovernanceInvariantChecker(makeDeps({
        getPolicyBundleVersion: () => 42,
        getStreamBundleVersion: () => 43,
      }));
      const result = checker.checkVersionConsistency();
      expect(result.passed).toBe(false);
      expect(result.severity).toBe('P1-correctness');
      expect(result.message).toContain('42');
      expect(result.message).toContain('43');
    });
  });

  describe('runAll', () => {
    it('returns three InvariantResults', () => {
      expect(new GovernanceInvariantChecker(makeDeps()).runAll()).toHaveLength(3);
    });

    it('every result has all required fields', () => {
      for (const result of new GovernanceInvariantChecker(makeDeps()).runAll()) {
        expect(typeof result.id).toBe('string');
        expect(typeof result.passed).toBe('boolean');
        expect(typeof result.severity).toBe('string');
        expect(typeof result.message).toBe('string');
      }
    });

    it('all-pass for clean state', () => {
      for (const r of new GovernanceInvariantChecker(makeDeps()).runAll()) {
        expect(r.passed).toBe(true);
      }
    });

    it('surfaces a failure when sequence regresses', () => {
      const checker = new GovernanceInvariantChecker(makeDeps({
        getGovernanceEvents: () => [
          { id: 'a', aegisSequence: 10, verdict: 'allow' },
          { id: 'b', aegisSequence: 5, verdict: 'allow' },
        ],
      }));
      expect(checker.runAll().some(r => !r.passed)).toBe(true);
    });
  });
});
