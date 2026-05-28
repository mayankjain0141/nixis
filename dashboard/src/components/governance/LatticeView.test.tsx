import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { LatticeView } from './LatticeView';
import { useLatticeStore } from '../../stores/lattice-store';
import type { LabelState } from '../../types/events';
import type { SecurityLabel } from '../../types/aegis';

function makeLabel(overrides: Partial<SecurityLabel> = {}): SecurityLabel {
  return { confidentiality: 0, integrity: 0, categories: 0, ...overrides };
}

function seedNode(sessionId: string, state: LabelState, label: SecurityLabel = makeLabel()) {
  useLatticeStore.getState().upsertNode(sessionId, label, state);
}

beforeEach(() => {
  // Reset store between tests.
  useLatticeStore.setState({ nodes: new Map(), selectedSessionId: null });
});

describe('LatticeView', () => {
  it('TestLatticeView_EmptyState — empty nodes map shows no active sessions', () => {
    render(<LatticeView />);
    expect(screen.getByText('No active sessions')).toBeInTheDocument();
  });

  it('TestLatticeView_ShowsSessionRows — 2 nodes in store renders 2 rows', () => {
    seedNode('aabbccdd-1111-2222-3333-444444444444', 'fresh');
    seedNode('eeff0011-5555-6666-7777-888888888888', 'fresh');
    render(<LatticeView />);
    const rows = screen.getAllByTestId('session-row');
    expect(rows).toHaveLength(2);
  });

  it('TestLatticeView_LabelStateBadge — escalated state shows orange badge', () => {
    seedNode('aabbccdd-1111-2222-3333-444444444444', 'escalated');
    render(<LatticeView />);
    const badge = screen.getByTestId('state-badge');
    expect(badge).toHaveStyle({ backgroundColor: '#d29922' });
    expect(badge).toHaveAttribute('data-state', 'escalated');
  });

  it('TestLatticeView_SelectSession — clicking row calls selectSession with correct ID', () => {
    const sessionId = 'aabbccdd-1111-2222-3333-444444444444';
    seedNode(sessionId, 'fresh');

    render(<LatticeView />);
    const row = screen.getByTestId('session-row');
    fireEvent.click(row);

    // The component calls useLatticeStore's selectSession on click;
    // verify the real store reflects the selection.
    expect(useLatticeStore.getState().selectedSessionId).toBe(sessionId);
  });
});
