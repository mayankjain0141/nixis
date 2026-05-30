import { Handle, Position, type NodeProps } from '@xyflow/react';

export function SecretNode({ data }: NodeProps) {
  return (
    <div
      style={{
        padding: '8px 12px',
        background: '#2a2010',
        border: '1px solid #ea580c',
        borderRadius: 6,
        fontSize: 11,
        color: '#e6edf3',
        minWidth: 80,
      }}
      data-verdict={data.verdict ?? undefined}
    >
      <div style={{ fontSize: 9, color: '#fb923c', marginBottom: 2, fontWeight: 600 }}>SECRET SCAN</div>
      <div>{String(data.label ?? '')}</div>
      <Handle type="target" position={Position.Left} />
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
