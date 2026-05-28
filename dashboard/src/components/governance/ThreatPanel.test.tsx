import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, beforeEach } from 'vitest';
import { ThreatPanel } from './ThreatPanel';
import { useThreatStore, type ThreatEvent } from '../../stores/threat-store';

function makeThreat(n: number): ThreatEvent {
  return {
    id: `threat-${n}`,
    type: 'secret.found',
    sessionId: `session-${n}`,
    tool: `tool_${n}`,
    severity: 'critical',
    description: `Threat description ${n}`,
    aegisSequence: n,
    timestamp: Date.now(),
    acknowledged: false,
  };
}

beforeEach(() => {
  useThreatStore.getState().clear();
});

describe('ThreatPanel', () => {
  it('TestThreatPanel_ShowsUnacknowledgedCount', () => {
    const store = useThreatStore.getState();
    store.appendThreat(makeThreat(1));
    store.appendThreat(makeThreat(2));
    store.appendThreat(makeThreat(3));

    render(<ThreatPanel />);

    const badge = screen.getByTestId('unacknowledged-count');
    expect(badge).toHaveTextContent('3');
  });

  it('TestThreatPanel_AcknowledgeButtonRemovesThreat', () => {
    const store = useThreatStore.getState();
    store.appendThreat(makeThreat(1));

    render(<ThreatPanel />);

    expect(screen.getByTestId('unacknowledged-count')).toHaveTextContent('1');

    const ackBtn = screen.getByRole('button', { name: /acknowledge threat threat-1/i });
    fireEvent.click(ackBtn);

    expect(useThreatStore.getState().unacknowledgedCount).toBe(0);
    expect(screen.queryByTestId('unacknowledged-count')).not.toBeInTheDocument();
  });

  it('TestThreatPanel_EmptyState', () => {
    render(<ThreatPanel />);
    expect(screen.getByText('No active threats')).toBeInTheDocument();
  });
});
