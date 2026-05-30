import { Handle, Position, type NodeProps } from '@xyflow/react';

export function DelegationNode({ data }: NodeProps) {
  return (
    <div
      style={{
        padding: '8px 12px',
        background: '#1f1a2e',
        border: '1px solid #8b5cf6',
        borderRadius: 6,
        fontSize: 11,
        color: '#e6edf3',
        minWidth: 80,
      }}
      data-verdict={data.verdict ?? undefined}
    >
      <div style={{ fontSize: 9, color: '#a78bfa', marginBottom: 2, fontWeight: 600 }}>DELEGATION</div>
      <div>{String(data.label ?? '')}</div>
      <Handle type="target" position={Position.Left} />
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
