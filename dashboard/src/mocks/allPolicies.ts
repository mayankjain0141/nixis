import type { PolicySummary } from '../stores/policy-store';

// Glob-based loading removed. Policy loading now handled by lib/policy-loader.ts.
// getAllImportedPolicies kept for demoScenario.ts compatibility — returns [].
export function getAllImportedPolicies(_bundleVersion: number = 1): PolicySummary[] {
  return [];
}

export function getEnabledPolicyCount(): number {
  return 0;
}

export function getTotalPolicyCount(): number {
  return 0;
}
