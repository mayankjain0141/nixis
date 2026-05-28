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
});

describe('Inspector', () => {
  it('shows empty state when no target selected', () => {
    render(<Inspector />);
    expect(screen.getByText('Select an event to inspect')).toBeInTheDocument();
  });

  it('shows classification section with tool name', () => {
    const event = makeEvent({ tool: 'read_file', id: 'evt-1' });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-1');

    render(<Inspector />);

    expect(screen.getByText('Classification')).toBeInTheDocument();
    // tool name appears in header and in classification row — both are valid
    expect(screen.getAllByText('read_file').length).toBeGreaterThanOrEqual(1);
  });

  it('shows security label badge in labels section', () => {
    const event = makeEvent({
      id: 'evt-2',
      label: { confidentiality: 32768, integrity: 0, categories: 1 },
    });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-2');

    render(<Inspector />);

    // Expand security labels section
    const securityBtn = screen.getByRole('button', { name: /security labels/i });
    fireEvent.click(securityBtn);

    // SecurityLabelBadge renders with role="img" and an aria-label
    const badge = screen.getByRole('img');
    expect(badge).toBeInTheDocument();
  });

  it('shows latency in ms when >1ms', () => {
    const event = makeEvent({ id: 'evt-3', latencyNs: 2_500_000 });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-3');

    render(<Inspector />);

    // Expand latency section
    const latencyBtn = screen.getByRole('button', { name: /latency breakdown/i });
    fireEvent.click(latencyBtn);

    expect(screen.getByText('2.50 ms')).toBeInTheDocument();
  });

  it('shows latency in ns when <1ms', () => {
    const event = makeEvent({ id: 'evt-4', latencyNs: 850_000 });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-4');

    render(<Inspector />);

    const latencyBtn = screen.getByRole('button', { name: /latency breakdown/i });
    fireEvent.click(latencyBtn);

    expect(screen.getByText('850,000 ns')).toBeInTheDocument();
  });

  it('accordion section toggles on click', () => {
    const event = makeEvent({ id: 'evt-5' });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-5');

    render(<Inspector />);

    // Classification is open by default — find a closed section (Policy Evaluation)
    const policyBtn = screen.getByRole('button', { name: /policy evaluation/i });
    expect(policyBtn).toHaveAttribute('aria-expanded', 'false');

    // Open it
    fireEvent.click(policyBtn);
    expect(policyBtn).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText('pol-default')).toBeInTheDocument();

    // Close it
    fireEvent.click(policyBtn);
    expect(policyBtn).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByText('pol-default')).not.toBeInTheDocument();
  });
});
