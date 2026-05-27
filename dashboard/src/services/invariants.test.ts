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
  describe('checkMonotonicLabelEscalation', () => {
    it('passes when events are in order', () => {
      const checker = new GovernanceInvariantChecker(makeDeps({
        getGovernanceEvents: () => [
          { id: 'a', aegisSequence: 1, verdict: 'allow' },
          { id: 'b', aegisSequence: 2, verdict: 'allow' },
          { id: 'c', aegisSequence: 5, verdict: 'deny' },
        ],
      }));
      expect(checker.checkMonotonicLabelEscalation().passed).toBe(true);
    });

    it('fails when a sequence regression is detected', () => {
      const checker = new GovernanceInvariantChecker(makeDeps({
        getGovernanceEvents: () => [
          { id: 'a', aegisSequence: 5, verdict: 'allow' },
          { id: 'b', aegisSequence: 3, verdict: 'allow' }, // regression
        ],
      }));
      const result = checker.checkMonotonicLabelEscalation();
      expect(result.passed).toBe(false);
      expect(result.severity).toBe('P0-security');
    });

    it('passes with an empty event list', () => {
      const checker = new GovernanceInvariantChecker(makeDeps());
      expect(checker.checkMonotonicLabelEscalation().passed).toBe(true);
    });
  });

  describe('checkDenyEdgesNeverGreen', () => {
    it('passes when no deny events are misrepresented', () => {
      const checker = new GovernanceInvariantChecker(makeDeps({
        getGovernanceEvents: () => [
          { id: 'a', aegisSequence: 1, verdict: 'deny' },
          { id: 'b', aegisSequence: 2, verdict: 'allow' },
        ],
      }));
      expect(checker.checkDenyEdgesNeverGreen().passed).toBe(true);
    });
  });

  describe('checkVersionConsistency', () => {
    it('passes when both versions are null', () => {
      const checker = new GovernanceInvariantChecker(makeDeps());
      expect(checker.checkVersionConsistency().passed).toBe(true);
    });

    it('passes when versions match', () => {
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
    });
  });

  describe('runAll', () => {
    it('returns three results', () => {
      const checker = new GovernanceInvariantChecker(makeDeps());
      expect(checker.runAll()).toHaveLength(3);
    });

    it('returns all-pass for clean state', () => {
      const checker = new GovernanceInvariantChecker(makeDeps());
      const results = checker.runAll();
      for (const r of results) {
        expect(r.passed).toBe(true);
      }
    });
  });
});
