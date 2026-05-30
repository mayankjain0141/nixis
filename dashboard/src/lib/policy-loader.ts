import { getDaemonApiBase } from './api';
import type { PolicySummary } from '../stores/policy-store';

interface DaemonPolicy {
  id: string;
  name: string;
  layer: string;
  enabled: boolean;
  cel_expression?: string;
  description?: string;
}

interface StaticPolicy extends DaemonPolicy {
  celExpression?: string;
}

function toPolicySummary(p: StaticPolicy, bundleVersion: number): PolicySummary {
  return {
    id: p.id,
    name: p.name,
    layer: (p.layer as PolicySummary['layer']) || 'cel',
    enabled: p.enabled ?? true,
    bundleVersion,
    celExpression: p.cel_expression ?? p.celExpression,
    description: p.description,
  };
}

async function loadFromDaemon(): Promise<PolicySummary[] | null> {
  try {
    const res = await fetch(`${getDaemonApiBase()}/policies`, {
      signal: AbortSignal.timeout(2000),
    });
    if (!res.ok) return null;
    const data: DaemonPolicy[] = await res.json();
    if (data.length === 0) return null;
    return data.map(p => toPolicySummary(p, 1));
  } catch {
    return null;
  }
}

async function loadFromStatic(): Promise<PolicySummary[]> {
  try {
    const res = await fetch('/policies.json');
    if (!res.ok) return [];
    const data: StaticPolicy[] = await res.json();
    return data.map(p => toPolicySummary(p, 1));
  } catch {
    return [];
  }
}

export async function loadPolicies(): Promise<PolicySummary[]> {
  const live = await loadFromDaemon();
  if (live !== null) return live;
  return loadFromStatic();
}
