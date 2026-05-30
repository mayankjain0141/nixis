import { render, screen, fireEvent, act } from '@testing-library/react';
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
    nixisSequence: n,
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
    expect(screen.queryByText('No events yet')).not.toBeInTheDocument();
    expect(screen.getByText('Tool1')).toBeInTheDocument();
  });

  it('pauses auto-scroll when user scrolls up', async () => {
    const store = useGovernanceStore.getState();
    // 50 events → totalHeight=1800px, containerHeight=720px.
    // At scrollTop=0: 0 < (1800 - 720 - 36) = 1044 → atBottom=false → paused=true.
    for (let i = 1; i <= 50; i++) {
      store.appendEvent(makeEvent(i));
    }

    render(<EventStream />);

    // Flush requestAnimationFrame from the initial auto-scroll so the
    // programmatic scroll counter returns to zero before we fire a user scroll.
    await act(async () => {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    });

    // Resume button absent before any user scroll.
    expect(screen.queryByRole('button', { name: /resume auto-scroll/i })).not.toBeInTheDocument();

    const grid = screen.getByRole('grid');

    // jsdom sets scrollTop=0 by default, which is far from the bottom.
    // Firing scroll with scrollTop=0 → atBottom=false → paused=true.
    Object.defineProperty(grid, 'scrollTop', { value: 0, writable: true, configurable: true });
    fireEvent.scroll(grid);

    // Resume button must now be visible.
    expect(screen.getByRole('button', { name: /resume auto-scroll/i })).toBeInTheDocument();

    // Clicking resume clears paused state.
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /resume auto-scroll/i }));
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    });
    expect(screen.queryByRole('button', { name: /resume auto-scroll/i })).not.toBeInTheDocument();
  });
});
