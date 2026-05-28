import { describe, it, expect } from 'vitest';
import { governanceNodeTypes } from './GovernanceDAG';

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
