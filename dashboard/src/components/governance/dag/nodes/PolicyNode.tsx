import { Handle, Position, type NodeProps } from '@xyflow/react';

export function PolicyNode({ data }: NodeProps) {
  return (
    <div
      style={{
        padding: '8px 12px',
        background: '#2a2210',
        border: '1px solid #d97706',
        borderRadius: 6,
        fontSize: 11,
        color: '#e6edf3',
        minWidth: 80,
      }}
      data-verdict={data.verdict ?? undefined}
    >
      <div style={{ fontSize: 9, color: '#fbbf24', marginBottom: 2, fontWeight: 600 }}>POLICY</div>
      <div>{String(data.label ?? '')}</div>
      <Handle type="target" position={Position.Top} />
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}
