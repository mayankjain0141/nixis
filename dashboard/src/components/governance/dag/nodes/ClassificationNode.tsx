import { Handle, Position, type NodeProps } from '@xyflow/react';

export function ClassificationNode({ data }: NodeProps) {
  return (
    <div
      style={{
        padding: '8px 12px',
        background: '#2a1a1a',
        border: '1px solid #dc2626',
        borderRadius: 6,
        fontSize: 11,
        color: '#e6edf3',
        minWidth: 80,
      }}
      data-verdict={data.verdict ?? undefined}
    >
      <div style={{ fontSize: 9, color: '#f87171', marginBottom: 2, fontWeight: 600 }}>CLASSIFICATION</div>
      <div>{String(data.label ?? '')}</div>
      <Handle type="target" position={Position.Left} />
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
