import { useMemo, useState, useEffect, useCallback, useRef } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  Panel,
  useNodesState,
  useEdgesState,
  type NodeTypes,
  type Node,
  type Edge,
  type NodeMouseHandler,
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
import { SecretNode } from './nodes/SecretNode';
import { DelegationNode } from './nodes/DelegationNode';

export const governanceNodeTypes: NodeTypes = {
  agent: AgentNode,
  hook: HookNode,
  daemon: DaemonNode,
  classification: ClassificationNode,
  ifc: IFCNode,
  policy: PolicyNode,
  audit: AuditNode,
  tool: ToolNode,
  secret: SecretNode,
  delegation: DelegationNode,
} as const;

const STORAGE_KEY = 'nixis-dag-positions';
const PIPELINE_Y = 120;
const PIPELINE_GAP = 160;

interface PipelineStage {
  id: string;
  type: string;
  label: string;
}

const PIPELINE_STAGES: PipelineStage[] = [
  { id: 'pipeline-agent', type: 'agent', label: 'Agent' },
  { id: 'pipeline-hook', type: 'hook', label: 'nixis-hook' },
  { id: 'pipeline-classify', type: 'classification', label: 'Classify' },
  { id: 'pipeline-ifc', type: 'ifc', label: 'IFC Lattice' },
  { id: 'pipeline-cel', type: 'daemon', label: 'CEL Engine' },
  { id: 'pipeline-secret', type: 'secret', label: 'Secret Scan' },
  { id: 'pipeline-delegation', type: 'delegation', label: 'Delegation' },
  { id: 'pipeline-audit', type: 'audit', label: 'Audit Chain' },
];

function loadPositions(): Record<string, { x: number; y: number }> {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
  } catch {
    return {};
  }
}

function savePositions(nodes: Node[]) {
  const positions: Record<string, { x: number; y: number }> = {};
  for (const n of nodes) positions[n.id] = n.position;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(positions));
}

function buildLayout(events: { tool: string; policyId?: string | null }[]) {
  const savedPositions = loadPositions();

  const pipelineNodes: Node[] = PIPELINE_STAGES.map((stage, i) => ({
    id: stage.id,
    type: stage.type,
    position: savedPositions[stage.id] ?? { x: i * PIPELINE_GAP, y: PIPELINE_Y },
    data: { label: stage.label },
  }));

  const pipelineEdges: Edge[] = PIPELINE_STAGES.slice(1).map((stage, i) => ({
    id: `pipe-${PIPELINE_STAGES[i].id}-${stage.id}`,
    source: PIPELINE_STAGES[i].id,
    target: stage.id,
    animated: true,
    style: { stroke: 'var(--allow, #2da44e)', strokeWidth: 2 },
  }));

  const tools = [...new Set(events.map((e) => e.tool))];
  const policies = [...new Set(events.map((e) => e.policyId).filter(Boolean))] as string[];

  const toolNodes: Node[] = tools.map((tool, i) => ({
    id: `tool-${tool}`,
    type: 'tool',
    position: savedPositions[`tool-${tool}`] ?? {
      x: 2 * PIPELINE_GAP + i * 100,
      y: PIPELINE_Y + 100 + i * 60,
    },
    data: { label: tool },
  }));

  const policyNodes: Node[] = policies.map((policy, i) => ({
    id: `policy-${policy}`,
    type: 'policy',
    position: savedPositions[`policy-${policy}`] ?? {
      x: 4 * PIPELINE_GAP + i * 80,
      y: PIPELINE_Y + 100 + i * 50,
    },
    data: { label: policy, policyId: policy },
  }));

  const dynamicEdges: Edge[] = [
    ...tools.map((tool) => ({
      id: `edge-hook-tool-${tool}`,
      source: 'pipeline-hook',
      target: `tool-${tool}`,
      animated: false,
      style: { stroke: '#4f46e5', opacity: 0.5 },
    })),
    ...policies.map((policy) => ({
      id: `edge-cel-policy-${policy}`,
      source: 'pipeline-cel',
      sourceHandle: 'children',
      target: `policy-${policy}`,
      animated: false,
      style: { stroke: '#d97706', opacity: 0.5 },
    })),
  ];

  return {
    nodes: [...pipelineNodes, ...toolNodes, ...policyNodes],
    edges: [...pipelineEdges, ...dynamicEdges],
  };
}

export function GovernanceDAG() {
  const events = useGovernanceStore((s) => s.events);
  const filterPolicy = useGovernanceStore((s) => s.filterPolicy);
  const setFilterPolicy = useGovernanceStore((s) => s.setFilterPolicy);
  const [highlightedIds, setHighlightedIds] = useState<Set<string>>(new Set());

  const layout = useMemo(() => buildLayout(events), [events]);

  const [nodes, setNodes, onNodesChange] = useNodesState(layout.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(layout.edges);

  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    setNodes(layout.nodes);
    setEdges(layout.edges);
  }, [layout, setNodes, setEdges]);

  const handleNodesChange = useCallback(
    (changes: Parameters<typeof onNodesChange>[0]) => {
      onNodesChange(changes);

      if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
      saveTimerRef.current = setTimeout(() => {
        setNodes((current) => {
          savePositions(current);
          return current;
        });
      }, 500);
    },
    [onNodesChange, setNodes],
  );

  useEffect(() => {
    function handler(e: Event) {
      const { tool } = (e as CustomEvent<{ nixisSequence?: number; tool?: string }>).detail;
      const ids = new Set<string>();
      if (tool) ids.add(`tool-${tool}`);
      setHighlightedIds(ids);
      setTimeout(() => setHighlightedIds(new Set()), 3000);
    }
    window.addEventListener('nixis:highlight-event', handler);
    return () => window.removeEventListener('nixis:highlight-event', handler);
  }, []);

  const highlightedNodes = useMemo(
    () =>
      nodes.map((node) =>
        highlightedIds.has(node.id)
          ? { ...node, style: { ...node.style, boxShadow: '0 0 0 3px #fbbf24, 0 0 12px #fbbf2466', borderRadius: 8 } }
          : node,
      ),
    [nodes, highlightedIds],
  );

  const handleResetLayout = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY);
    const fresh = buildLayout(events);
    setNodes(fresh.nodes);
    setEdges(fresh.edges);
  }, [events, setNodes, setEdges]);

  if (events.length === 0) {
    return (
      <div style={{
        height: 400, display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: 'var(--text-muted)', fontSize: 13, flexDirection: 'column', gap: 8,
      }}>
        <div style={{ fontSize: 24, opacity: 0.3 }}>&#x2B21;</div>
        <div>Governance DAG will populate as events arrive</div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Start the demo to see the evaluation pipeline</div>
      </div>
    );
  }

  if (nodes.length > 500) {
    return (
      <div style={{ height: 400, padding: 16, color: 'var(--text-secondary)', fontSize: 12 }}>
        <div style={{ fontWeight: 600, marginBottom: 8 }}>Skeleton view — {nodes.length} nodes</div>
        <div style={{ color: 'var(--text-muted)' }}>Too many nodes to render DAG. Filter by session or policy to reduce.</div>
      </div>
    );
  }

  const handleNodeClick: NodeMouseHandler = (_event, node) => {
    if (!node.id.startsWith('policy-')) return;
    const policyId = node.id.slice('policy-'.length);
    setFilterPolicy(filterPolicy === policyId ? null : policyId);
  };

  return (
    <div style={{ width: '100%', height: '100%', minHeight: 420 }} aria-label="Governance evaluation DAG">
      <ReactFlow
        nodes={highlightedNodes}
        edges={edges}
        nodeTypes={governanceNodeTypes}
        onNodesChange={handleNodesChange}
        onEdgesChange={onEdgesChange}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        onlyRenderVisibleElements={nodes.length > 200}
        onNodeClick={handleNodeClick}
      >
        <Background />
        <Controls />
        <Panel position="top-right">
          <button
            onClick={handleResetLayout}
            style={{
              padding: '4px 10px',
              fontSize: 11,
              background: '#21262d',
              border: '1px solid #30363d',
              borderRadius: 4,
              color: '#8b949e',
              cursor: 'pointer',
            }}
            title="Reset node positions to default layout"
          >
            Reset Layout
          </button>
        </Panel>
      </ReactFlow>
    </div>
  );
}
