import { useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  type NodeTypes,
  type Node,
  type Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useGovernanceStore } from '../../../stores/governance-store';
import { AgentNode } from './nodes/AgentNode';
import { HookNode } from './nodes/HookNode';
import { DaemonNode } from './nodes/DaemonNode';
import { ClassificationNode } from './nodes/ClassificationNode';
import { IFCNode } from './nodes/IFCNode';
import { PolicyNode } from './nodes/PolicyNode';
import { AuditNode } from './nodes/AuditNode';
import { ToolNode } from './nodes/ToolNode';

export const governanceNodeTypes: NodeTypes = {
  agent: AgentNode,
  hook: HookNode,
  daemon: DaemonNode,
  classification: ClassificationNode,
  ifc: IFCNode,
  policy: PolicyNode,
  audit: AuditNode,
  tool: ToolNode,
} as const;

// Mulberry32 seeded PRNG — same seed = same layout
function mulberry32(seed: number) {
  return function () {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function hashNodeIds(ids: string[]): number {
  const str = [...ids].sort().join('|');
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h;
}

export function GovernanceDAG() {
  const events = useGovernanceStore((s) => s.events);

  const { nodes, edges } = useMemo(() => {
    const tools = [...new Set(events.map((e) => e.tool))];
    const policies = [...new Set(events.map((e) => e.policyId).filter(Boolean))];

    const nodeIds = [
      'daemon',
      'ifc',
      'audit',
      ...tools.map((t) => `tool-${t}`),
      ...policies.map((p) => `policy-${p}`),
    ];
    const seed = hashNodeIds(nodeIds);
    const rand = mulberry32(seed);

    const nodes: Node[] = [
      { id: 'daemon', type: 'daemon', position: { x: 300, y: 0 }, data: { label: 'aegis-daemon' } },
      { id: 'ifc', type: 'ifc', position: { x: 300, y: 100 }, data: { label: 'IFC Lattice' } },
      { id: 'audit', type: 'audit', position: { x: 300, y: 400 }, data: { label: 'Audit Chain' } },
      ...tools.map((tool, i) => ({
        id: `tool-${tool}`,
        type: 'tool' as const,
        position: { x: 50 + i * 150 + rand() * 20, y: 200 + rand() * 20 },
        data: { label: tool },
      })),
      ...policies.map((policy, i) => ({
        id: `policy-${policy}`,
        type: 'policy' as const,
        position: { x: 50 + i * 150 + rand() * 20, y: 300 + rand() * 20 },
        data: { label: policy },
      })),
    ];

    const edges: Edge[] = [
      {
        id: 'ifc-daemon',
        source: 'ifc',
        target: 'daemon',
        animated: true,
        style: { stroke: 'var(--allow, #2da44e)' },
      },
      {
        id: 'daemon-audit',
        source: 'daemon',
        target: 'audit',
        animated: false,
      },
      ...tools.flatMap((tool) =>
        policies.map((policy) => ({
          id: `${tool}-${policy}`,
          source: `tool-${tool}`,
          target: `policy-${policy}`,
          animated: true,
          style: { stroke: 'var(--allow, #2da44e)' },
        }))
      ),
      ...policies.map((policy) => ({
        id: `${policy}-daemon`,
        source: `policy-${policy}`,
        target: 'daemon',
        animated: true,
        style: { stroke: 'var(--allow, #2da44e)' },
      })),
    ];

    // LOD: >500 nodes → skeleton view
    if (nodes.length > 500) {
      return {
        nodes: [
          {
            id: 'skeleton',
            type: 'default',
            position: { x: 0, y: 0 },
            data: { label: `${nodes.length} nodes — skeleton view` },
          },
        ],
        edges: [],
      };
    }

    return { nodes, edges };
  }, [events]);

  return (
    <div style={{ width: '100%', height: 400 }} aria-label="Governance evaluation DAG">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={governanceNodeTypes}
        fitView
        onlyRenderVisibleElements={nodes.length > 200}
      >
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  );
}
