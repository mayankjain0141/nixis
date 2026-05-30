import { Handle, Position, type NodeProps } from '@xyflow/react';
import { useGovernanceStore } from '../../../../stores/governance-store';

export function PolicyNode({ data }: NodeProps) {
  const filterPolicy = useGovernanceStore((s) => s.filterPolicy);
  const isFiltering = typeof data.policyId === 'string' && filterPolicy === data.policyId;

  return (
    <div
      style={{
        padding: '8px 12px',
        background: '#2a2210',
        border: isFiltering ? '2px solid #2da44e' : '1px solid #d97706',
        borderRadius: 6,
        fontSize: 11,
        color: '#e6edf3',
        minWidth: 80,
        boxShadow: isFiltering ? '0 0 0 2px rgba(45,164,78,0.3)' : undefined,
        cursor: 'pointer',
      }}
      data-verdict={data.verdict ?? undefined}
    >
      <div style={{ fontSize: 9, color: '#fbbf24', marginBottom: 2, fontWeight: 600 }}>POLICY</div>
      <div>{String(data.label ?? '')}</div>
      <Handle type="target" position={Position.Left} />
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
