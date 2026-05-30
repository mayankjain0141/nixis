import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, beforeEach } from 'vitest';
import { Inspector } from './Inspector';
import { useUIStore } from '../../stores/ui-store';
import { useGovernanceStore, type GovernanceEvent } from '../../stores/governance-store';

function makeEvent(overrides: Partial<GovernanceEvent> = {}): GovernanceEvent {
  return {
    id: 'evt-1',
    sessionId: 'sess_abc',
    tool: 'bash',
    verdict: 'allow',
    reason: 'Allowed by default policy',
    policyId: 'pol-default',
    enforcingLayer: 'cel',
    label: { confidentiality: 0, integrity: 0, categories: 0 },
    labelState: 'fresh',
    latencyNs: 1_500_000,
    aegisSequence: 1,
    timestamp: 1_700_000_000_000_000_000,
    ...overrides,
  };
}

beforeEach(() => {
  useGovernanceStore.getState().clear();
  useUIStore.getState().closeInspector();
  if (useUIStore.getState().isPaused) {
    useUIStore.getState().togglePause();
  }
});

describe('Inspector', () => {
  it('renders empty state when no target selected', () => {
    render(<Inspector />);
    expect(screen.getByText('Click an event to inspect')).toBeInTheDocument();
  });

  it('shows empty state when target does not match any event', () => {
    useUIStore.getState().openInspector('nonexistent');
    render(<Inspector />);
    expect(screen.getByText('Click an event to inspect')).toBeInTheDocument();
  });

  it('shows tool name when event is selected', () => {
    const event = makeEvent({ tool: 'read_file', id: 'evt-1' });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-1');

    render(<Inspector />);

    expect(screen.getAllByText('read_file').length).toBeGreaterThanOrEqual(1);
  });

  it('shows verdict prominently for deny event', () => {
    const event = makeEvent({ id: 'evt-deny', verdict: 'deny', reason: 'label dominance failure' });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-deny');

    render(<Inspector />);

    expect(screen.getByText('DENY')).toBeInTheDocument();
    expect(document.querySelector('[data-verdict="deny"]')).not.toBeNull();
    expect(screen.getAllByText('label dominance failure').length).toBeGreaterThanOrEqual(1);
  });

  it('TestInspector_WhyDenied_OnlyOnDeny: no deny data-verdict for allow events', () => {
    const event = makeEvent({ id: 'evt-allow', verdict: 'allow' });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-allow');

    render(<Inspector />);

    expect(screen.getByText('ALLOW')).toBeInTheDocument();
    // deny verdict attribute is absent for allow events
    expect(document.querySelector('[data-verdict="deny"]')).toBeNull();
  });

  it('shows sequence number in header', () => {
    const event = makeEvent({ id: 'evt-seq', aegisSequence: 42 });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-seq');

    render(<Inspector />);

    expect(screen.getAllByText('#42').length).toBeGreaterThanOrEqual(1);
  });

  it('shows latency formatted correctly for >1ms', () => {
    const event = makeEvent({ id: 'evt-lat', latencyNs: 2_500_000 });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-lat');

    render(<Inspector />);

    expect(screen.getByText('2.50ms')).toBeInTheDocument();
  });

  it('shows latency formatted correctly for <1ms', () => {
    const event = makeEvent({ id: 'evt-lat2', latencyNs: 850_000 });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-lat2');

    render(<Inspector />);

    expect(screen.getByText('850us')).toBeInTheDocument();
  });

  it('Security Label section toggles open on click', () => {
    const event = makeEvent({
      id: 'evt-label',
      label: { confidentiality: 32768, integrity: 0, categories: 0 },
    });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-label');

    render(<Inspector />);

    // Section is open by default
    expect(screen.getByText('Confidentiality')).toBeInTheDocument();
    expect(screen.getByText('Confidential')).toBeInTheDocument();

    const secBtn = screen.getByRole('button', { name: /security label/i });
    fireEvent.click(secBtn);

    // Clicking closes it
    expect(screen.queryByText('Confidentiality')).not.toBeInTheDocument();

    fireEvent.click(secBtn);

    // Clicking again re-opens it
    expect(screen.getByText('Confidentiality')).toBeInTheDocument();
  });

  it('TestInspector_DominatesComputed: IFC Reasoning section shows Dominates YES', () => {
    const event = makeEvent({
      id: 'evt-dom',
      label: { confidentiality: 32768, integrity: 16384, categories: 3 },
      ...({ requestedLabel: { confidentiality: 16384, integrity: 8192, categories: 1 } } as object),
    });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-dom');

    render(<Inspector />);

    const ifcBtn = screen.getByRole('button', { name: /ifc reasoning/i });
    fireEvent.click(ifcBtn);

    expect(screen.getByText(/Dominates\(\): YES/)).toBeInTheDocument();
  });

  it('TestInspector_DominatesComputed: IFC Reasoning section shows Dominates NO when not dominant', () => {
    const event = makeEvent({
      id: 'evt-nodom',
      label: { confidentiality: 0, integrity: 0, categories: 0 },
      ...({ requestedLabel: { confidentiality: 32768, integrity: 16384, categories: 1 } } as object),
    });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-nodom');

    render(<Inspector />);

    const ifcBtn = screen.getByRole('button', { name: /ifc reasoning/i });
    fireEvent.click(ifcBtn);

    expect(screen.getByText(/Dominates\(\): NO/)).toBeInTheDocument();
  });

  it('TestInspector_PauseButtonPresent: pause button toggles isPaused', () => {
    const event = makeEvent({ id: 'evt-pause' });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-pause');

    render(<Inspector />);

    const pauseBtn = screen.getByRole('button', { name: /pause/i });
    expect(pauseBtn).toBeInTheDocument();
    expect(useUIStore.getState().isPaused).toBe(false);

    fireEvent.click(pauseBtn);
    expect(useUIStore.getState().isPaused).toBe(true);

    expect(screen.getByRole('button', { name: /resume/i })).toBeInTheDocument();
  });

  it('IFC Reasoning section is absent when no requestedLabel', () => {
    const event = makeEvent({ id: 'evt-noifc' });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-noifc');

    render(<Inspector />);

    expect(screen.queryByRole('button', { name: /ifc reasoning/i })).toBeNull();
  });

  it('shows CEL expression when celExpression field is present', () => {
    const event = makeEvent({
      id: 'evt-cel',
      celExpression: 'tool == "Bash" && request.args.command.matches(".*--force.*")',
    });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-cel');

    render(<Inspector />);

    expect(screen.getByText(/tool == "Bash"/)).toBeInTheDocument();
  });
});
