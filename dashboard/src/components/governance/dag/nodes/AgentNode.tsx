import { Handle, Position, type NodeProps } from '@xyflow/react';

export function AgentNode({ data }: NodeProps) {
  return (
    <div
      style={{
        padding: '8px 12px',
        background: '#1a2332',
        border: '1px solid #2563eb',
        borderRadius: 6,
        fontSize: 11,
        color: '#e6edf3',
        minWidth: 80,
      }}
      data-verdict={data.verdict ?? undefined}
    >
      <div style={{ fontSize: 9, color: '#60a5fa', marginBottom: 2, fontWeight: 600 }}>AGENT</div>
      <div>{String(data.label ?? '')}</div>
      <Handle type="target" position={Position.Top} />
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}
