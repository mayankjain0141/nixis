import { Handle, Position, type NodeProps } from '@xyflow/react';

export function AuditNode({ data }: NodeProps) {
  return (
    <div
      style={{
        padding: '8px 12px',
        background: '#1e2020',
        border: '1px solid #6b7280',
        borderRadius: 6,
        fontSize: 11,
        color: '#e6edf3',
        minWidth: 80,
      }}
      data-verdict={data.verdict ?? undefined}
    >
      <div style={{ fontSize: 9, color: '#9ca3af', marginBottom: 2, fontWeight: 600 }}>AUDIT</div>
      <div>{String(data.label ?? '')}</div>
      <Handle type="target" position={Position.Top} />
    </div>
  );
}
