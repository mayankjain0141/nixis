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
  // reset isPaused to false between tests
  if (useUIStore.getState().isPaused) {
    useUIStore.getState().togglePause();
  }
});

describe('Inspector', () => {
  it('renders nothing when inspectorOpen is false', () => {
    const { container } = render(<Inspector />);
    expect(container.firstChild).toBeNull();
  });

  it('shows empty state when no target selected', () => {
    // open the panel without a matching event so the empty state renders
    useUIStore.getState().openInspector('nonexistent');
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

  it('TestInspector_WhyDenied_OnlyOnDeny: no deny section for allow events', () => {
    const event = makeEvent({ id: 'evt-allow', verdict: 'allow' });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-allow');

    render(<Inspector />);

    expect(screen.queryByText('Why Denied')).not.toBeInTheDocument();
    expect(document.querySelector('[data-verdict="deny"]')).toBeNull();
  });

  it('TestInspector_WhyDenied_OnlyOnDeny: deny section present for deny events', () => {
    const event = makeEvent({ id: 'evt-deny', verdict: 'deny', reason: 'label dominance failure' });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-deny');

    render(<Inspector />);

    expect(screen.getByText('Why Denied')).toBeInTheDocument();
    expect(document.querySelector('[data-verdict="deny"]')).not.toBeNull();
    // reason text is visible inside the deny section
    expect(screen.getAllByText('label dominance failure').length).toBeGreaterThanOrEqual(1);
  });

  it('TestInspector_DominatesComputed: computes YES when subject dominates object', () => {
    const event = makeEvent({
      id: 'evt-dom',
      label: { confidentiality: 32768, integrity: 16384, categories: 3 },
      // requestedLabel is an extended field not in GovernanceEvent — cast via spread
      ...({ requestedLabel: { confidentiality: 16384, integrity: 8192, categories: 1 } } as object),
    });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-dom');

    render(<Inspector />);

    // Expand IFC Reasoning section
    const ifcBtn = screen.getByRole('button', { name: /ifc reasoning/i });
    fireEvent.click(ifcBtn);

    expect(screen.getByText(/Dominates\(\): YES/)).toBeInTheDocument();
  });

  it('TestInspector_DelegationChainRenders: renders hops and removes MVP-1 stub', () => {
    // Inject delegationChains into the store state directly
    const store = useGovernanceStore as unknown as { setState: (s: object) => void };
    store.setState({
      delegationChains: {
        'sess_chain': [
          { hopIndex: 0, delegatorId: 'agent-A', delegateeId: 'agent-B', grantedLabel: { confidentiality: 16384, integrity: 0, categories: 0 }, ceilingLabel: { confidentiality: 32768, integrity: 0, categories: 0 } },
          { hopIndex: 1, delegatorId: 'agent-B', delegateeId: 'agent-C', grantedLabel: { confidentiality: 8192, integrity: 0, categories: 0 }, ceilingLabel: { confidentiality: 16384, integrity: 0, categories: 0 } },
        ],
      },
    });

    const event = makeEvent({ id: 'evt-chain', sessionId: 'sess_chain' });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-chain');

    render(<Inspector />);

    // Expand Delegation Chain section
    const chainBtn = screen.getByRole('button', { name: /delegation chain/i });
    fireEvent.click(chainBtn);

    expect(screen.getByText(/Hop 0: agent-A → agent-B/)).toBeInTheDocument();
    expect(screen.getByText(/Hop 1: agent-B → agent-C/)).toBeInTheDocument();
    expect(screen.queryByText(/MVP-1/)).not.toBeInTheDocument();
  });

  it('TestInspector_PauseButtonPresent: pause button is in header and toggles isPaused', () => {
    const event = makeEvent({ id: 'evt-pause' });
    useGovernanceStore.getState().appendEvent(event);
    useUIStore.getState().openInspector('evt-pause');

    render(<Inspector />);

    const pauseBtn = screen.getByRole('button', { name: /pause inspector/i });
    expect(pauseBtn).toBeInTheDocument();
    expect(useUIStore.getState().isPaused).toBe(false);

    fireEvent.click(pauseBtn);
    expect(useUIStore.getState().isPaused).toBe(true);

    // Button label changes to Resume
    expect(screen.getByRole('button', { name: /resume inspector/i })).toBeInTheDocument();
  });
});
