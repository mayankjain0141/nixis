import React from 'react';
import { useGovernanceStore } from '../../stores/governance-store';

export function AuditHashChain() {
  const events = useGovernanceStore((s) => s.events);
  const checkpoints = events.filter((e) => e.tool === 'audit');

  if (checkpoints.length === 0) {
    return (
      <div style={{ color: '#8b949e', fontSize: 12, padding: 12 }}>
        No audit checkpoints yet
      </div>
    );
  }

  return (
    <div
      aria-label="Audit hash chain"
      style={{ display: 'flex', flexDirection: 'column', gap: 4, padding: 8 }}
    >
      {checkpoints.map((cp, i) => (
        <React.Fragment key={cp.id}>
          <div
            data-sequence={cp.aegisSequence}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              background: '#1e2a3a',
              border: '1px solid #30363d',
              borderRadius: 4,
              padding: '4px 8px',
              fontFamily: 'monospace',
              fontSize: 11,
              color: '#e6edf3',
            }}
          >
            <span style={{ color: '#58a6ff', minWidth: 24 }}>#{i + 1}</span>
            <span style={{ color: '#8b949e' }}>seq:{cp.aegisSequence}</span>
            <span style={{ color: '#2da44e' }}>{cp.id.slice(0, 8)}&hellip;</span>
            <span style={{ color: '#8b949e', fontSize: 10 }}>
              {cp.tool} / {cp.verdict}
            </span>
          </div>
          {i < checkpoints.length - 1 && (
            <div style={{ paddingLeft: 20, color: '#30363d', fontSize: 10 }}>
              &darr;
            </div>
          )}
        </React.Fragment>
      ))}
    </div>
  );
}
