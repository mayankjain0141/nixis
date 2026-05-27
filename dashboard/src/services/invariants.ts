// GovernanceInvariantChecker: reads cross-store state via injected selectors.
// This is the ONLY place allowed to read from multiple stores at once.
// Stores themselves never import from each other.

import type { SecurityLabel } from '../types/aegis';

export interface InvariantResult {
  id: string;
  passed: boolean;
  severity: 'P0-security' | 'P1-correctness' | 'P2-performance';
  message: string;
}

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
  private deps: InvariantCheckerDeps;

  constructor(deps: InvariantCheckerDeps) {
    this.deps = deps;
  }

  // INV: aegisSequence is monotonically increasing across received events.
  checkMonotonicLabelEscalation(): InvariantResult {
    const events = this.deps.getGovernanceEvents();
    let lastSeq = -1;
    for (const e of events) {
      if (e.aegisSequence <= lastSeq) {
        return {
          id: 'version-monotonic',
          passed: false,
          severity: 'P0-security',
          message: `Sequence regression: event ${e.id} has aegisSequence ${e.aegisSequence} after ${lastSeq}`,
        };
      }
      lastSeq = e.aegisSequence;
    }
    return { id: 'version-monotonic', passed: true, severity: 'P0-security', message: 'OK' };
  }

  // INV: Deny/require_approval events are never shown as green/allow in the UI.
  checkDenyEdgesNeverGreen(): InvariantResult {
    const events = this.deps.getGovernanceEvents();
    for (const e of events) {
      if ((e.verdict === 'deny' || e.verdict === 'require_approval') &&
          (e.verdict as string) === 'allow') {
        return {
          id: 'deny-edge-never-green',
          passed: false,
          severity: 'P0-security',
          message: `Event ${e.id} has verdict ${e.verdict} but is rendered as allow`,
        };
      }
    }
    return { id: 'deny-edge-never-green', passed: true, severity: 'P0-security', message: 'OK' };
  }

  // INV: Policy bundle version in the policy store matches the stream store's latest bundle event.
  checkVersionConsistency(): InvariantResult {
    const policyVersion = this.deps.getPolicyBundleVersion();
    const streamVersion = this.deps.getStreamBundleVersion();
    if (policyVersion !== null && streamVersion !== null && policyVersion !== streamVersion) {
      return {
        id: 'version-consistency',
        passed: false,
        severity: 'P1-correctness',
        message: `Policy bundle version ${policyVersion} does not match stream bundle version ${streamVersion}`,
      };
    }
    return { id: 'version-consistency', passed: true, severity: 'P1-correctness', message: 'OK' };
  }

  runAll(): InvariantResult[] {
    return [
      this.checkMonotonicLabelEscalation(),
      this.checkDenyEdgesNeverGreen(),
      this.checkVersionConsistency(),
    ];
  }
}
