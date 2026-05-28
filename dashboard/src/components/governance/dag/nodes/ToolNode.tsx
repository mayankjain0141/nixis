import { Handle, Position, type NodeProps } from '@xyflow/react';

export function ToolNode({ data }: NodeProps) {
  return (
    <div
      style={{
        padding: '8px 12px',
        background: '#1a1e2a',
        border: '1px solid #4f46e5',
        borderRadius: 6,
        fontSize: 11,
        color: '#e6edf3',
        minWidth: 80,
      }}
      data-verdict={data.verdict ?? undefined}
    >
      <div style={{ fontSize: 9, color: '#818cf8', marginBottom: 2, fontWeight: 600 }}>TOOL</div>
      <div>{String(data.label ?? '')}</div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}
