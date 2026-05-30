import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/react';
import { LatticeHasseDiagram } from './LatticeHasseDiagram';
import { useLatticeStore } from '../../stores/lattice-store';
import { useGovernanceStore } from '../../stores/governance-store';

beforeEach(() => {
  useLatticeStore.setState({ nodes: new Map(), selectedSessionId: null });
  useGovernanceStore.setState({ sessionLabels: new Map() } as never);
});

describe('LatticeHasseDiagram', () => {
  it('TestIFC_HasseSeparateFromOverlay: hasse-static SVG and hasse-overlay div are distinct elements', () => {
    const { container } = render(<LatticeHasseDiagram />);
    const staticSvg = container.querySelector('.hasse-static');
    const overlay = container.querySelector('.hasse-overlay');
    expect(staticSvg).toBeTruthy();
    expect(overlay).toBeTruthy();
    expect(staticSvg).not.toBe(overlay);
  });

  it('TestIFC_ScreenReaderList: accessibility list is present', () => {
    const { container } = render(<LatticeHasseDiagram />);
    const list = container.querySelector('[aria-label="IFC Lattice sessions"]');
    expect(list).toBeTruthy();
  });

  it('TestIFC_CountBadgeLabelState: count badge has data-label-state attribute', () => {
    useLatticeStore.getState().upsertNode('s1', { confidentiality: 57344, integrity: 100, categories: 0 }, 'escalated');
    const { container } = render(<LatticeHasseDiagram />);
    const badge = container.querySelector('.count-badge');
    expect(badge).toBeTruthy();
    expect(badge?.getAttribute('data-label-state')).toBe('escalated');
  });

  it('TestIFC_SessionInList: session appears in screen reader list with level and state', () => {
    useLatticeStore.getState().upsertNode('sess-42', { confidentiality: 0, integrity: 0, categories: 0 }, 'fresh');
    const { container } = render(<LatticeHasseDiagram />);
    const list = container.querySelector('[aria-label="IFC Lattice sessions"]');
    expect(list?.textContent).toContain('sess-42');
    expect(list?.textContent).toContain('Unclassified');
  });

  it('TestIFC_NoSessionsNoBadges: empty store renders no count badges', () => {
    const { container } = render(<LatticeHasseDiagram />);
    const badges = container.querySelectorAll('.count-badge');
    expect(badges.length).toBe(0);
  });

  it('TestIFC_HeaderText: header shows "Data Classification Lattice"', () => {
    const { getByText } = render(<LatticeHasseDiagram />);
    expect(getByText('Data Classification Lattice')).toBeTruthy();
  });

  it('TestIFC_FooterLegend: footer legend is present when sessions exist', () => {
    useLatticeStore.getState().upsertNode('sess-99', { confidentiality: 0, integrity: 0, categories: 0 }, 'fresh');
    const { getByText } = render(<LatticeHasseDiagram />);
    expect(getByText('fresh')).toBeTruthy();
    expect(getByText('escalated')).toBeTruthy();
    expect(getByText('tainted')).toBeTruthy();
  });

  it('TestIFC_EmptyStateOverlay: idle message shown when no sessions', () => {
    const { container, getByText } = render(<LatticeHasseDiagram />);
    expect(getByText(/Lattice is idle/)).toBeTruthy();
    const svg = container.querySelector('.hasse-static') as SVGSVGElement | null;
    expect(svg?.style.opacity).toBe('0.3');
  });

  it('TestIFC_NodeClickOpensDetailPanel: clicking a level node opens the detail panel', () => {
    useLatticeStore.getState().upsertNode('sess-ab', { confidentiality: 57344, integrity: 0, categories: 0 }, 'fresh');
    const { container, getByText } = render(<LatticeHasseDiagram />);
    const restrictedNode = container.querySelector('[aria-label^="Restricted:"]') as Element;
    expect(restrictedNode).toBeTruthy();
    fireEvent.click(restrictedNode);
    expect(getByText(/Restricted \(1 session\)/)).toBeTruthy();
  });

  it('TestIFC_SessionRowCallsSetFilterSession: clicking a session row calls setFilterSession', () => {
    useLatticeStore.getState().upsertNode('sess-cd1234', { confidentiality: 57344, integrity: 0, categories: 0 }, 'fresh');
    const spy = vi.spyOn(useGovernanceStore.getState(), 'setFilterSession');
    const { container, getByText } = render(<LatticeHasseDiagram />);
    const restrictedNode = container.querySelector('[aria-label^="Restricted:"]') as Element;
    fireEvent.click(restrictedNode);
    const sessionRow = getByText('sess-cd1');
    fireEvent.click(sessionRow);
    expect(spy).toHaveBeenCalledWith('sess-cd1234');
    spy.mockRestore();
  });
});
