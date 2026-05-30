import { Handle, Position, type NodeProps } from '@xyflow/react';

export function HookNode({ data }: NodeProps) {
  return (
    <div
      style={{
        padding: '8px 12px',
        background: '#1e1a32',
        border: '1px solid #7c3aed',
        borderRadius: 6,
        fontSize: 11,
        color: '#e6edf3',
        minWidth: 80,
      }}
      data-verdict={data.verdict ?? undefined}
    >
      <div style={{ fontSize: 9, color: '#a78bfa', marginBottom: 2, fontWeight: 600 }}>HOOK</div>
      <div>{String(data.label ?? '')}</div>
      <Handle type="target" position={Position.Left} />
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
