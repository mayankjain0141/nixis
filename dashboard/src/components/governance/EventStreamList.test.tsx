import { render, screen, fireEvent, act } from '@testing-library/react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { EventStreamList } from './EventStreamList';
import { useGovernanceStore, type GovernanceEvent } from '../../stores/governance-store';
import { useUIStore } from '../../stores/ui-store';

// react-window v2 uses ResizeObserver internally — already polyfilled in test-setup.ts,
// but also mock scrollToRow on the imperative API since jsdom has no real scroll.
vi.mock('react-window', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-window')>();
  return {
    ...mod,
  };
});

function makeEvent(overrides: Partial<GovernanceEvent> = {}): GovernanceEvent {
  return {
    id: `evt-${Math.random().toString(36).slice(2)}`,
    sessionId: 'sess-default',
    tool: 'DefaultTool',
    verdict: 'allow',
    reason: '',
    policyId: 'pol-default',
    enforcingLayer: 'cel',
    label: { confidentiality: 0, integrity: 0, categories: 0 },
    labelState: 'fresh',
    latencyNs: 1_000_000,
    nixisSequence: 1,
    timestamp: Date.now() * 1_000_000,
    ...overrides,
  };
}

beforeEach(() => {
  useGovernanceStore.getState().clear();
  useGovernanceStore.getState().setFilterVerdict(null);
  useGovernanceStore.getState().setFilterSession(null);
  useGovernanceStore.getState().setFilterPolicy(null);
});

describe('EventStreamList', () => {
  it('renders empty state when no events match filter', () => {
    render(<EventStreamList />);
    expect(screen.getByText('Waiting for events…')).toBeInTheDocument();
  });

  it('renders with 1000 events without throwing (virtual scroll — no DOM cap)', () => {
    const store = useGovernanceStore.getState();
    for (let i = 0; i < 1000; i++) {
      store.appendEvent(makeEvent({ id: `evt-${i}`, nixisSequence: i }));
    }
    expect(() => render(<EventStreamList />)).not.toThrow();
    // List component mounts — aria-label is present
    expect(screen.getByLabelText('Live event stream')).toBeInTheDocument();
  });

  describe('filterSession filter chain', () => {
    it('shows only events matching filterSession when set', () => {
      const store = useGovernanceStore.getState();
      store.appendEvent(makeEvent({ id: 'e1', sessionId: 'sess-A', tool: 'ToolA' }));
      store.appendEvent(makeEvent({ id: 'e2', sessionId: 'sess-B', tool: 'ToolB' }));
      store.appendEvent(makeEvent({ id: 'e3', sessionId: 'sess-A', tool: 'ToolA2' }));

      store.setFilterSession('sess-A');
      render(<EventStreamList />);

      // Session pill shows the active filter
      expect(screen.getByText(/Session:.*— 2 events/)).toBeInTheDocument();
    });

    it('clear button for filterSession calls setFilterSession(null)', () => {
      const store = useGovernanceStore.getState();
      store.appendEvent(makeEvent({ id: 'e1', sessionId: 'sess-A', tool: 'ToolA' }));
      store.setFilterSession('sess-A');
      render(<EventStreamList />);

      const clearButtons = screen.getAllByText('✕ clear');
      // Click the session filter's clear button (first one since only session filter is active)
      fireEvent.click(clearButtons[0]);

      expect(useGovernanceStore.getState().filterSession).toBeNull();
    });
  });

  describe('filterPolicy filter chain', () => {
    it('shows only events matching filterPolicy when set', () => {
      const store = useGovernanceStore.getState();
      store.appendEvent(makeEvent({ id: 'e1', policyId: 'pol-A', tool: 'ToolA' }));
      store.appendEvent(makeEvent({ id: 'e2', policyId: 'pol-B', tool: 'ToolB' }));
      store.appendEvent(makeEvent({ id: 'e3', policyId: 'pol-A', tool: 'ToolA2' }));

      store.setFilterPolicy('pol-A');
      render(<EventStreamList />);

      // Policy pill shows the active filter with count
      expect(screen.getByText(/pol-A.*— 2 events/)).toBeInTheDocument();
    });

    it('clear button for filterPolicy calls setFilterPolicy(null)', () => {
      const store = useGovernanceStore.getState();
      store.appendEvent(makeEvent({ id: 'e1', policyId: 'pol-A' }));
      store.setFilterPolicy('pol-A');
      render(<EventStreamList />);

      const clearButtons = screen.getAllByText('✕ clear');
      fireEvent.click(clearButtons[0]);

      expect(useGovernanceStore.getState().filterPolicy).toBeNull();
    });
  });

  describe('badge click — setFilterVerdict, not openInspector', () => {
    it('badge click calls setFilterVerdict and does not open inspector', async () => {
      const store = useGovernanceStore.getState();
      const openInspectorSpy = vi.fn();

      // Patch openInspector via ui-store
      const original = useUIStore.getState().openInspector;
      useUIStore.setState({ openInspector: openInspectorSpy });

      store.appendEvent(makeEvent({ id: 'badge-evt', verdict: 'deny', tool: 'BadgeTool' }));
      render(<EventStreamList />);

      // Find verdict badge — it has the label text matching VERDICT_STYLE
      const badge = screen.getByText('DENY');
      await act(async () => {
        fireEvent.click(badge);
      });

      expect(useGovernanceStore.getState().filterVerdict).toBe('deny');
      expect(openInspectorSpy).not.toHaveBeenCalled();

      // Restore
      useUIStore.setState({ openInspector: original });
    });

    it('row body click calls openInspector (badge click does not bubble)', async () => {
      const store = useGovernanceStore.getState();
      const openInspectorSpy = vi.fn();

      const original = useUIStore.getState().openInspector;
      useUIStore.setState({ openInspector: openInspectorSpy });

      store.appendEvent(makeEvent({ id: 'row-evt', verdict: 'allow', tool: 'RowTool' }));
      render(<EventStreamList />);

      // Click on the tool name text — row body, not badge
      const toolText = screen.getByText('RowTool');
      await act(async () => {
        fireEvent.click(toolText);
      });

      expect(openInspectorSpy).toHaveBeenCalledWith('row-evt');

      useUIStore.setState({ openInspector: original });
    });
  });

  describe('fail_open verdict badge', () => {
    it('renders fail_open verdict with OPEN label and amber background', () => {
      const store = useGovernanceStore.getState();
      store.appendEvent(makeEvent({ id: 'fo-evt', verdict: 'fail_open' as GovernanceEvent['verdict'], tool: 'FailOpenTool' }));
      render(<EventStreamList />);

      const badge = screen.getByText('OPEN');
      expect(badge).toBeInTheDocument();
      expect(badge).toHaveStyle({ background: '#d29922' });
    });
  });
});
