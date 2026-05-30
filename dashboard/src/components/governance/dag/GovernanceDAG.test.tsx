import { render } from '@testing-library/react';
import { describe, it, expect, beforeEach } from 'vitest';
import { governanceNodeTypes } from './GovernanceDAG';
import { PolicyNode } from './nodes/PolicyNode';
import { useGovernanceStore } from '../../../stores/governance-store';
import { ReactFlowProvider } from '@xyflow/react';
import type { NodeProps } from '@xyflow/react';
import type { ReactNode } from 'react';

function withFlow(children: ReactNode) {
  return <ReactFlowProvider>{children}</ReactFlowProvider>;
}

describe('GovernanceDAG', () => {
  it('TestDAG_AllNodeTypesExist: governanceNodeTypes has exactly 8 keys', () => {
    const keys = Object.keys(governanceNodeTypes);
    expect(keys).toHaveLength(8);
    expect(keys).toContain('agent');
    expect(keys).toContain('hook');
    expect(keys).toContain('daemon');
    expect(keys).toContain('classification');
    expect(keys).toContain('ifc');
    expect(keys).toContain('policy');
    expect(keys).toContain('audit');
    expect(keys).toContain('tool');
  });

  it('TestDAG_NodeTypesAreComponents: each node type is a function/component', () => {
    for (const [key, Component] of Object.entries(governanceNodeTypes)) {
      expect(typeof Component, `${key} should be a function`).toBe('function');
    }
  });
});

// Minimal props needed to render PolicyNode — only `data` is used by the component.
function makePolicyNodeProps(data: Record<string, unknown>): NodeProps {
  return {
    id: 'policy-test',
    type: 'policy',
    data,
    dragging: false,
    zIndex: 0,
    selectable: true,
    deletable: true,
    selected: false,
    draggable: true,
    isConnectable: true,
    positionAbsoluteX: 0,
    positionAbsoluteY: 0,
  } as unknown as NodeProps;
}

describe('filterPolicy toggle logic', () => {
  beforeEach(() => {
    useGovernanceStore.getState().clear();
  });

  it('TestFilterPolicy_SetsPolicyId: setFilterPolicy stores the policy id', () => {
    useGovernanceStore.getState().setFilterPolicy('my-policy-id');
    expect(useGovernanceStore.getState().filterPolicy).toBe('my-policy-id');
  });

  it('TestFilterPolicy_Toggle: calling setFilterPolicy with same id then null clears it', () => {
    const store = useGovernanceStore.getState();
    store.setFilterPolicy('my-policy-id');
    // Simulate the toggle: filterPolicy === policyId → pass null
    const current = useGovernanceStore.getState().filterPolicy;
    store.setFilterPolicy(current === 'my-policy-id' ? null : 'my-policy-id');
    expect(useGovernanceStore.getState().filterPolicy).toBeNull();
  });

  it('TestFilterPolicy_NonPolicyNode: non-policy node IDs leave filterPolicy unchanged', () => {
    useGovernanceStore.getState().setFilterPolicy(null);
    const nodeId = 'tool-read';
    // Guard: node.id does not start with 'policy-' → no store call
    if (nodeId.startsWith('policy-')) {
      useGovernanceStore.getState().setFilterPolicy(nodeId.slice('policy-'.length));
    }
    expect(useGovernanceStore.getState().filterPolicy).toBeNull();
  });

  it('TestFilterPolicy_DifferentPolicy: clicking a different policy replaces the filter', () => {
    const store = useGovernanceStore.getState();
    store.setFilterPolicy('policy-a');
    store.setFilterPolicy('policy-b');
    expect(useGovernanceStore.getState().filterPolicy).toBe('policy-b');
  });
});

describe('PolicyNode highlight', () => {
  beforeEach(() => {
    useGovernanceStore.getState().clear();
  });

  it('TestPolicyNode_NoHighlight: PolicyNode renders without highlight when filterPolicy is null', () => {
    useGovernanceStore.getState().setFilterPolicy(null);
    const { container } = render(
      withFlow(<PolicyNode {...makePolicyNodeProps({ label: 'my-policy', policyId: 'my-policy' })} />)
    );
    // PolicyNode renders its outer div as the first child of container
    const node = container.firstElementChild as HTMLElement;
    // Non-highlighted border is 1px solid (orange, not green)
    expect(node.style.border).toContain('1px solid');
    expect(node.style.boxShadow).toBe('');
  });

  it('TestPolicyNode_HighlightWhenMatching: PolicyNode applies green highlight when filterPolicy matches data.policyId', () => {
    useGovernanceStore.getState().setFilterPolicy('my-policy');
    const { container } = render(
      withFlow(<PolicyNode {...makePolicyNodeProps({ label: 'my-policy', policyId: 'my-policy' })} />)
    );
    const node = container.firstElementChild as HTMLElement;
    // Highlighted border is 2px solid green (rgb(45, 164, 78)) and box-shadow is set
    expect(node.style.border).toContain('2px solid');
    expect(node.style.boxShadow).not.toBe('');
  });

  it('TestPolicyNode_NoHighlightWhenDifferentPolicy: PolicyNode does not highlight when filterPolicy is different', () => {
    useGovernanceStore.getState().setFilterPolicy('other-policy');
    const { container } = render(
      withFlow(<PolicyNode {...makePolicyNodeProps({ label: 'my-policy', policyId: 'my-policy' })} />)
    );
    const node = container.firstElementChild as HTMLElement;
    // Should use default 1px border, no boxShadow
    expect(node.style.border).toContain('1px solid');
    expect(node.style.boxShadow).toBe('');
  });

  it('TestPolicyNode_NoPolicyIdField: PolicyNode does not highlight when data.policyId is missing', () => {
    useGovernanceStore.getState().setFilterPolicy('my-policy');
    const { container } = render(
      // No policyId in data — simulates old nodes without the field
      withFlow(<PolicyNode {...makePolicyNodeProps({ label: 'my-policy' })} />)
    );
    const node = container.firstElementChild as HTMLElement;
    expect(node.style.border).toContain('1px solid');
    expect(node.style.boxShadow).toBe('');
  });
});
