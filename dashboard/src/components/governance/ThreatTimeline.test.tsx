import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render } from '@testing-library/react';
import { ThreatTimeline } from './ThreatTimeline';
import { useThreatStore, type ThreatEvent } from '../../stores/threat-store';

function makeThreat(n: number): ThreatEvent {
  return {
    id: `threat-${n}`,
    type: 'secret.found',
    sessionId: `session-${n}`,
    tool: `tool_${n}`,
    severity: 'critical',
    description: `Threat ${n}`,
    aegisSequence: n,
    timestamp: Date.now(),
    acknowledged: false,
    humanDescription: '',
    impact: '',
    relatedSessionName: '',
  };
}

beforeEach(() => {
  useThreatStore.getState().clear();
  vi.stubGlobal('requestAnimationFrame', (_cb: FrameRequestCallback) => 1);
  vi.stubGlobal('cancelAnimationFrame', vi.fn());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('ThreatTimeline', () => {
  it('TestThreatTimeline_CanvasPresent: canvas element is rendered', () => {
    const { container } = render(<ThreatTimeline />);
    expect(container.querySelector('canvas')).toBeTruthy();
  });

  it('TestThreatTimeline_RafCancelledOnUnmount: cleanup on unmount', () => {
    const { unmount } = render(<ThreatTimeline />);
    unmount();
    expect(cancelAnimationFrame).toHaveBeenCalled();
  });

  it('TestThreatTimeline_A11yTable: accessibility table is present', () => {
    const { container } = render(<ThreatTimeline />);
    expect(container.querySelector('table[aria-label]')).toBeTruthy();
  });

  it('TestThreatTimeline_A11yTableRows: threat rows appear in accessibility table', () => {
    useThreatStore.getState().appendThreat(makeThreat(1));
    useThreatStore.getState().appendThreat(makeThreat(2));
    const { container } = render(<ThreatTimeline />);
    const rows = container.querySelectorAll('table[aria-label] tbody tr');
    expect(rows.length).toBe(2);
  });

  it('TestThreatTimeline_AriaLabel: wrapper has correct aria-label', () => {
    const { container } = render(<ThreatTimeline />);
    expect(container.querySelector('[aria-label="Threat timeline"]')).toBeTruthy();
  });
});
