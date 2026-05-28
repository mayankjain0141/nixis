import { describe, it, expect, beforeEach } from 'vitest';
import { render } from '@testing-library/react';
import { DelegationTree } from './DelegationTree';
import { useGovernanceStore, type DelegationHop } from '../../stores/governance-store';

function makeHop(i: number): DelegationHop {
  return {
    hopIndex: i,
    delegatorId: `delegator-${i}`,
    delegateeId: `delegatee-${i}`,
    grantedLabel: { confidentiality: 16384, integrity: 0, categories: 0 },
    ceilingLabel: { confidentiality: 32768, integrity: 0, categories: 0 },
  };
}

beforeEach(() => {
  useGovernanceStore.getState().clear();
});

describe('DelegationTree', () => {
  it('renders without crashing', () => {
    const { container } = render(<DelegationTree />);
    expect(container.querySelector('[aria-label="Delegation chain tree"]')).toBeTruthy();
  });

  it('TestDelegationTree_SVGPresent: svg element is rendered', () => {
    const { container } = render(<DelegationTree />);
    expect(container.querySelector('svg')).toBeTruthy();
  });

  it('TestDelegationTree_EmptyState: shows no-chains text when store is empty', () => {
    const { container } = render(<DelegationTree />);
    const svg = container.querySelector('svg');
    expect(svg).toBeTruthy();
    // D3 appends a text node with the empty message
    const texts = svg!.querySelectorAll('text');
    expect(texts.length).toBeGreaterThan(0);
    expect(texts[0].textContent).toMatch(/No delegation chains active/);
  });

  it('TestDelegationTree_RendersChain: nodes appear when delegation chain is present', () => {
    useGovernanceStore.getState().updateDelegationChain('session-1', [makeHop(0), makeHop(1)]);
    const { container } = render(<DelegationTree />);
    const circles = container.querySelectorAll('circle');
    // root node + 2 hops = 3 nodes
    expect(circles.length).toBe(3);
  });
});
