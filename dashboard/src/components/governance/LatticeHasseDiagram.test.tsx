import { describe, it, expect, beforeEach } from 'vitest';
import { render } from '@testing-library/react';
import { LatticeHasseDiagram } from './LatticeHasseDiagram';
import { useLatticeStore } from '../../stores/lattice-store';

beforeEach(() => {
  useLatticeStore.setState({ nodes: new Map(), selectedSessionId: null });
});

describe('LatticeHasseDiagram', () => {
  it('TestIFC_HasseSeparateFromOverlay: two SVG elements with correct classes', () => {
    const { container } = render(<LatticeHasseDiagram />);
    const staticSvg = container.querySelector('.hasse-static');
    const overlaySvg = container.querySelector('.hasse-overlay');
    expect(staticSvg).toBeTruthy();
    expect(overlaySvg).toBeTruthy();
    expect(staticSvg).not.toBe(overlaySvg);
  });

  it('TestIFC_StaticLayerNeverChanges: static layer renders 4 level nodes', () => {
    const { container } = render(<LatticeHasseDiagram />);
    expect(container.querySelector('.hasse-overlay')).toBeTruthy();
    expect(container.querySelector('.hasse-static')).toBeTruthy();
  });

  it('TestIFC_ScreenReaderList: accessibility list is present', () => {
    const { container } = render(<LatticeHasseDiagram />);
    const list = container.querySelector('[aria-label="IFC Lattice sessions"]');
    expect(list).toBeTruthy();
  });

  it('TestIFC_SessionDotLabelState: session dots have data-label-state attribute', () => {
    useLatticeStore.getState().upsertNode('s1', { confidentiality: 57344, integrity: 100, categories: 0 }, 'escalated');
    const { container } = render(<LatticeHasseDiagram />);
    const dot = container.querySelector('.session-dot');
    expect(dot).toBeTruthy();
    expect(dot?.getAttribute('data-label-state')).toBe('escalated');
  });

  it('TestIFC_SessionInList: session appears in screen reader list', () => {
    useLatticeStore.getState().upsertNode('sess-42', { confidentiality: 0, integrity: 0, categories: 0 }, 'fresh');
    const { container } = render(<LatticeHasseDiagram />);
    const list = container.querySelector('[aria-label="IFC Lattice sessions"]');
    expect(list?.textContent).toContain('sess-42');
    expect(list?.textContent).toContain('Unclassified');
  });

  it('TestIFC_NoSessionsNoOverlayDots: empty store renders no session dots', () => {
    const { container } = render(<LatticeHasseDiagram />);
    const dots = container.querySelectorAll('.session-dot');
    expect(dots.length).toBe(0);
  });
});
