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
const PIPELINE_Y = 160;
const PIPELINE_GAP = 180;

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

function buildLayout(events: { tool: string; policyId?: string | null; decision?: string }[]) {
  const savedPositions = loadPositions();

  // Pipeline nodes — always a straight horizontal line
  const pipelineNodes: Node[] = PIPELINE_STAGES.map((stage, i) => ({
    id: stage.id,
    type: stage.type,
    position: savedPositions[stage.id] ?? { x: i * PIPELINE_GAP, y: PIPELINE_Y },
    data: { label: stage.label },
    draggable: true,
  }));

  // Pipeline edges — sequential chain
  const pipelineEdges: Edge[] = PIPELINE_STAGES.slice(1).map((stage, i) => ({
    id: `pipe-${PIPELINE_STAGES[i].id}-${stage.id}`,
    source: PIPELINE_STAGES[i].id,
    target: stage.id,
    animated: true,
    style: { stroke: '#2da44e', strokeWidth: 2 },
  }));

  // Tool nodes — compact row below the Hook stage
  const tools = [...new Set(events.map((e) => e.tool))];
  const toolNodes: Node[] = tools.map((tool, i) => ({
    id: `tool-${tool}`,
    type: 'tool',
    position: savedPositions[`tool-${tool}`] ?? {
      x: 1 * PIPELINE_GAP + (i % 3) * 120,
      y: PIPELINE_Y + 80 + Math.floor(i / 3) * 60,
    },
    data: { label: tool },
    draggable: true,
  }));

  // Policy nodes — show at most 8 individual triggered policies, then a summary
  const allPolicies = [...new Set(events.map((e) => e.policyId).filter(Boolean))] as string[];
  const showPolicies = allPolicies.slice(0, 8);
  const hiddenCount = allPolicies.length - showPolicies.length;

  const policyNodes: Node[] = showPolicies.map((policy, i) => ({
    id: `policy-${policy}`,
    type: 'policy',
    position: savedPositions[`policy-${policy}`] ?? {
      x: 4 * PIPELINE_GAP + (i % 4) * 130,
      y: PIPELINE_Y + 80 + Math.floor(i / 4) * 55,
    },
    data: { label: policy, policyId: policy },
    draggable: true,
  }));

  // If there are more policies than shown, add a summary node
  if (hiddenCount > 0) {
    const summaryId = 'policy-overflow';
    policyNodes.push({
      id: summaryId,
      type: 'policy',
      position: savedPositions[summaryId] ?? {
        x: 4 * PIPELINE_GAP + 200,
        y: PIPELINE_Y + 80 + Math.ceil(showPolicies.length / 4) * 55,
      },
      data: { label: `+${hiddenCount} more policies` },
      draggable: true,
    });
  }

  // Edges connecting dynamic nodes to the pipeline
  const dynamicEdges: Edge[] = [
    // Tools connect from Hook
    ...tools.map((tool) => ({
      id: `edge-hook-tool-${tool}`,
      source: 'pipeline-hook',
      target: `tool-${tool}`,
      style: { stroke: '#4f46e5', strokeDasharray: '4 2', opacity: 0.6 },
    })),
    // Policies connect from CEL Engine
    ...policyNodes.map((pn) => ({
      id: `edge-cel-${pn.id}`,
      source: 'pipeline-cel',
      target: pn.id,
      style: { stroke: '#d97706', strokeDasharray: '4 2', opacity: 0.6 },
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
  const prevEventsLenRef = useRef(0);

  // Sync layout when new events arrive (new tools/policies discovered)
  useEffect(() => {
    if (events.length !== prevEventsLenRef.current) {
      prevEventsLenRef.current = events.length;
      setNodes(layout.nodes);
      setEdges(layout.edges);
    }
  }, [layout, events.length, setNodes, setEdges]);

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
        height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: 'var(--text-muted)', fontSize: 13, flexDirection: 'column', gap: 8,
      }}>
        <div style={{ fontSize: 24, opacity: 0.3 }}>&#x2B21;</div>
        <div>Governance DAG will populate as events arrive</div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Start the demo to see the evaluation pipeline</div>
      </div>
    );
  }

  const handleNodeClick: NodeMouseHandler = (_event, node) => {
    if (!node.id.startsWith('policy-')) return;
    if (node.id === 'policy-overflow') return;
    const policyId = node.id.slice('policy-'.length);
    setFilterPolicy(filterPolicy === policyId ? null : policyId);
  };

  return (
    <div style={{ width: '100%', height: '100%', minHeight: 500 }} aria-label="Governance evaluation DAG">
      <ReactFlow
        nodes={highlightedNodes}
        edges={edges}
        nodeTypes={governanceNodeTypes}
        onNodesChange={handleNodesChange}
        onEdgesChange={onEdgesChange}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        onNodeClick={handleNodeClick}
        proOptions={{ hideAttribution: true }}
        defaultEdgeOptions={{ type: 'smoothstep' }}
      >
        <Background color="#1e293b" gap={24} size={1} />
        <Controls
          showInteractive={false}
          style={{
            background: '#161b22',
            border: '1px solid #30363d',
            borderRadius: 6,
          }}
        />
        <Panel position="top-right">
          <button
            onClick={handleResetLayout}
            style={{
              padding: '5px 12px',
              fontSize: 11,
              background: '#161b22',
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
