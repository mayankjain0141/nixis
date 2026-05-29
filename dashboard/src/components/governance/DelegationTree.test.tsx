import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { DelegationTree } from './DelegationTree';
import { useGovernanceStore } from '../../stores/governance-store';

beforeEach(() => {
  useGovernanceStore.getState().clear();
});

describe('DelegationTree', () => {
  it('renders without crashing', () => {
    const { container } = render(<DelegationTree />);
    expect(container.querySelector('[aria-label="Delegation chain tree"]')).toBeTruthy();
  });

  it('TestDelegationTree_EmptyState: shows no-chains message when store is empty', () => {
    render(<DelegationTree />);
    expect(screen.getByText(/No delegation chains active/i)).toBeTruthy();
  });

  it('TestDelegationTree_RendersChain: renders chain nodes when delegation data present', () => {
    useGovernanceStore.getState().updateDelegationChain('sess_delegatee', [{
      hopIndex: 0,
      delegatorId: 'sess_origin',
      delegateeId: 'sess_delegatee',
      grantedLabel: { confidentiality: 49152, integrity: 32768, categories: 7 },
      ceilingLabel: { confidentiality: 8192,  integrity: 8192,  categories: 0 },
    }]);

    const { container } = render(<DelegationTree />);

    // Should not show empty state
    expect(screen.queryByText(/No delegation chains active/i)).toBeNull();

    // Should show delegation connector text
    expect(container.textContent).toContain('delegates');

    // Should show attenuation indicator since ceiling < granted
    // Use "↓ attenuated from" — the legend also contains the word "attenuated" but
    // only chain nodes emit the "↓ attenuated from <level>" indicator text.
    expect(container.textContent).toContain('↓ attenuated from');
  });

  it('TestDelegationTree_NoAttenuation: no attenuation shown when ceiling equals granted', () => {
    useGovernanceStore.getState().updateDelegationChain('sess_equal', [{
      hopIndex: 0,
      delegatorId: 'sess_parent',
      delegateeId: 'sess_equal',
      grantedLabel: { confidentiality: 8192, integrity: 8192, categories: 0 },
      ceilingLabel: { confidentiality: 8192, integrity: 8192, categories: 0 },
    }]);

    const { container } = render(<DelegationTree />);
    // Only chain nodes emit "↓ attenuated from <level>" — legend text is different
    expect(container.textContent).not.toContain('↓ attenuated from');
  });
});
