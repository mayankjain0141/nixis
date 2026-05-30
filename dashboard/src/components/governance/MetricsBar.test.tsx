import { render, screen } from '@testing-library/react';
import { describe, it, expect, beforeEach } from 'vitest';
import { MetricsBar } from './MetricsBar';
import { useGovernanceStore } from '../../stores/governance-store';
import { useStreamStore } from '../../stores/stream-store';
import type { GovernanceEvent } from '../../stores/governance-store';

function makeEvent(verdict: GovernanceEvent['verdict'], n: number): GovernanceEvent {
  return {
    id: `evt-${n}`,
    sessionId: 'sess_0',
    tool: 'Shell',
    verdict,
    reason: '',
    policyId: 'p1',
    enforcingLayer: 'cel',
    label: { confidentiality: 0, integrity: 0, categories: 0 },
    labelState: 'fresh',
    latencyNs: 1_000_000,
    nixisSequence: n,
    timestamp: Date.now() * 1_000_000,
  };
}

beforeEach(() => {
  useGovernanceStore.getState().clear();
  useStreamStore.getState().reset();
});

describe('MetricsBar', () => {
  it('shows deny rate from store', () => {
    const store = useGovernanceStore.getState();
    // 3 denials + 7 allows = 30% deny rate
    for (let i = 0; i < 3; i++) store.appendEvent(makeEvent('deny', i));
    for (let i = 3; i < 10; i++) store.appendEvent(makeEvent('allow', i));

    render(<MetricsBar />);
    expect(screen.getByText('30%')).toBeInTheDocument();
  });

  it('highlights deny rate when above 10%', () => {
    const store = useGovernanceStore.getState();
    for (let i = 0; i < 3; i++) store.appendEvent(makeEvent('deny', i));
    for (let i = 3; i < 10; i++) store.appendEvent(makeEvent('allow', i));

    render(<MetricsBar />);
    const denySpan = screen.getByText('30%');
    expect(denySpan).toHaveAttribute('data-high-deny', 'true');
  });

  it('does not highlight deny rate when at or below 10%', () => {
    const store = useGovernanceStore.getState();
    // 1 denial + 9 allows = 10% — not above 10, so no highlight
    store.appendEvent(makeEvent('deny', 0));
    for (let i = 1; i < 10; i++) store.appendEvent(makeEvent('allow', i));

    render(<MetricsBar />);
    const denySpan = screen.getByText('10%');
    expect(denySpan).toHaveAttribute('data-high-deny', 'false');
  });

  it('shows Mock indicator when connectionState is MOCK', () => {
    useStreamStore.getState().setConnectionState('MOCK');
    render(<MetricsBar />);
    expect(screen.getByText('Mock')).toBeInTheDocument();
  });
});
