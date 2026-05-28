import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { AuditHashChain } from './AuditHashChain';
import { useGovernanceStore, type GovernanceEvent } from '../../stores/governance-store';

function makeAuditEvent(n: number): GovernanceEvent {
  return {
    id: `audit-evt-${n}`,
    sessionId: `session-${n}`,
    tool: 'audit',
    verdict: 'allow',
    reason: 'checkpoint',
    policyId: `policy-${n}`,
    enforcingLayer: 'gateway',
    label: { confidentiality: 0, integrity: 0, categories: 0 },
    labelState: 'fresh',
    latencyNs: 1000,
    aegisSequence: n,
    timestamp: Date.now(),
  };
}

beforeEach(() => {
  useGovernanceStore.getState().clear();
});

describe('AuditHashChain', () => {
  it('renders without crashing', () => {
    const { container } = render(<AuditHashChain />);
    expect(container).toBeTruthy();
  });

  it('TestAuditHashChain_EmptyState: shows no-checkpoints message when empty', () => {
    render(<AuditHashChain />);
    expect(screen.getByText(/No audit checkpoints/)).toBeTruthy();
  });

  it('TestAuditHashChain_ShowsCheckpoints: renders audit events from store', () => {
    useGovernanceStore.getState().appendEvent(makeAuditEvent(1));
    useGovernanceStore.getState().appendEvent(makeAuditEvent(2));
    render(<AuditHashChain />);
    expect(screen.getByText('#1')).toBeTruthy();
    expect(screen.getByText('#2')).toBeTruthy();
  });

  it('TestAuditHashChain_FiltersNonAudit: non-audit events are not shown', () => {
    const nonAudit: GovernanceEvent = {
      ...makeAuditEvent(99),
      id: 'non-audit-99',
      tool: 'bash',
    };
    useGovernanceStore.getState().appendEvent(nonAudit);
    render(<AuditHashChain />);
    expect(screen.getByText(/No audit checkpoints/)).toBeTruthy();
  });

  it('TestAuditHashChain_SequenceAttribute: data-sequence attribute is set correctly', () => {
    useGovernanceStore.getState().appendEvent(makeAuditEvent(42));
    const { container } = render(<AuditHashChain />);
    const node = container.querySelector('[data-sequence="42"]');
    expect(node).toBeTruthy();
  });
});
