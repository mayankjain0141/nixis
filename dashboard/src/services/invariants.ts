// GovernanceInvariantChecker: reads cross-store state via injected selectors.
// This is the ONLY place allowed to read from multiple stores at once.
// Stores themselves never import from each other.

import type { SecurityLabel } from '../types/aegis';
import { VERDICTS } from '../types/events';

export interface InvariantResult {
  id: string;
  passed: boolean;
  severity: 'P0-security' | 'P1-correctness' | 'P2-performance';
  message: string;
}

const VALID_VERDICT_SET = new Set<string>(VERDICTS);

// Selectors are injected so this service never imports store modules directly.
export interface InvariantCheckerDeps {
  getGovernanceEvents(): Array<{
    id: string;
    aegisSequence: number;
    verdict: string;
  }>;
  getSessionLabels(): Map<string, { label: SecurityLabel; updatedAt: number }>;
  getPolicyBundleVersion(): number | null;
  getStreamBundleVersion(): number | null;
}

export class GovernanceInvariantChecker {
  private readonly deps: InvariantCheckerDeps;

  constructor(deps: InvariantCheckerDeps) {
    this.deps = deps;
  }

  // INV: aegisSequence values in the event list are strictly increasing.
  // A regression means an out-of-order or duplicate event was accepted into the store.
  checkMonotonicSequence(): InvariantResult {
    const events = this.deps.getGovernanceEvents();
    let lastSeq = -1;
    for (const e of events) {
      if (e.aegisSequence <= lastSeq) {
        return {
          id: 'version-monotonic',
          passed: false,
          severity: 'P0-security',
          message: `Sequence regression: event "${e.id}" has aegisSequence ${e.aegisSequence} after ${lastSeq}`,
        };
      }
      lastSeq = e.aegisSequence;
    }
    return { id: 'version-monotonic', passed: true, severity: 'P0-security', message: 'OK' };
  }

  // INV: Every stored event has a canonical verdict from the four-value vocabulary.
  // Non-canonical strings ('escalate', 'HITL', 'block', etc.) indicate a fabricated
  // or mis-validated event reached the store — a P0 security violation.
  checkDenyEdgesNeverGreen(): InvariantResult {
    const events = this.deps.getGovernanceEvents();
    for (const e of events) {
      if (!VALID_VERDICT_SET.has(e.verdict)) {
        return {
          id: 'deny-edge-never-green',
          passed: false,
          severity: 'P0-security',
          message: `Event "${e.id}" has non-canonical verdict "${e.verdict}" — expected one of: ${VERDICTS.join(', ')}`,
        };
      }
    }
    return { id: 'deny-edge-never-green', passed: true, severity: 'P0-security', message: 'OK' };
  }

  // INV: Policy bundle version in the policy store matches the stream store's latest bundle event.
  // A mismatch means the UI is displaying stale policy state.
  checkVersionConsistency(): InvariantResult {
    const policyVersion = this.deps.getPolicyBundleVersion();
    const streamVersion = this.deps.getStreamBundleVersion();
    if (policyVersion !== null && streamVersion !== null && policyVersion !== streamVersion) {
      return {
        id: 'version-consistency',
        passed: false,
        severity: 'P1-correctness',
        message: `Policy bundle version ${policyVersion} does not match stream version ${streamVersion}`,
      };
    }
    return { id: 'version-consistency', passed: true, severity: 'P1-correctness', message: 'OK' };
  }

  runAll(): InvariantResult[] {
    return [
      this.checkMonotonicSequence(),
      this.checkDenyEdgesNeverGreen(),
      this.checkVersionConsistency(),
    ];
  }
}
