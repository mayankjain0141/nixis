import { render, screen } from '@testing-library/react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { EventStream } from './EventStream';
import { useGovernanceStore, type GovernanceEvent } from '../../stores/governance-store';

// react-window v2 uses ResizeObserver internally; jsdom doesn't provide it.
vi.stubGlobal('ResizeObserver', class {
  observe = vi.fn();
  unobserve = vi.fn();
  disconnect = vi.fn();
});

function makeEvent(n: number): GovernanceEvent {
  return {
    id: `evt-${n}`,
    sessionId: `sess_${n}`,
    tool: `Tool${n}`,
    verdict: 'allow',
    reason: `reason ${n}`,
    policyId: `pol-${n}`,
    enforcingLayer: 'cel',
    label: { confidentiality: 0, integrity: 0, categories: 0 },
    labelState: 'fresh',
    latencyNs: 1_000_000,
    aegisSequence: n,
    timestamp: Date.now() * 1_000_000,
  };
}

beforeEach(() => {
  useGovernanceStore.getState().clear();
});

describe('EventStream', () => {
  it('renders empty state when store is empty', () => {
    render(<EventStream />);
    expect(screen.getByText('No events yet')).toBeInTheDocument();
  });

  it('renders events when store has events', () => {
    const store = useGovernanceStore.getState();
    for (let i = 1; i <= 10; i++) {
      store.appendEvent(makeEvent(i));
    }
    render(<EventStream />);
    // Verify the list is rendered (not empty state) and tool names are present.
    expect(screen.queryByText('No events yet')).not.toBeInTheDocument();
    // At least some tool names should be visible in the virtualized list.
    expect(screen.getByText('Tool1')).toBeInTheDocument();
  });
});
