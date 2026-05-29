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
      style={{ display: 'flex', flexDirection: 'column', gap: 2, padding: 8 }}
    >
      {checkpoints.map((cp, i) => {
        const isLatest = i === checkpoints.length - 1;
        // celExpression contains "hash:XXXX prev:YYYY" — extract for display
        const cel = cp.celExpression ?? '';
        const hashMatch = cel.match(/hash:([^\s]+)/);
        const prevMatch = cel.match(/prev:([^\s]+)/);
        const shortHash = hashMatch ? hashMatch[1] : cp.id.slice(0, 16);
        const shortPrev = prevMatch ? prevMatch[1] : '';

        return (
          <React.Fragment key={cp.id}>
            <div
              data-sequence={cp.aegisSequence}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                background: '#1e2a3a',
                border: `1px solid ${isLatest ? 'var(--info-blue)' : '#30363d'}`,
                borderRadius: 4,
                padding: '6px 10px',
                fontFamily: 'monospace',
                fontSize: 11,
                color: '#e6edf3',
              }}
            >
              <span style={{
                color: isLatest ? 'var(--info-blue)' : '#58a6ff',
                minWidth: 28,
                fontWeight: isLatest ? 700 : 400,
              }}>
                #{cp.aegisSequence}
              </span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2, flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ color: '#8b949e', fontSize: 10 }}>HASH</span>
                  <span style={{ color: isLatest ? 'var(--info-blue)' : '#2da44e' }}>
                    {shortHash}&hellip;
                  </span>
                </div>
                {shortPrev && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ color: '#8b949e', fontSize: 10 }}>PREV</span>
                    <span style={{ color: '#6e7681' }}>{shortPrev}&hellip;</span>
                  </div>
                )}
              </div>
              <span style={{ color: '#8b949e', fontSize: 10, flexShrink: 0 }}>
                {cp.reason}
              </span>
            </div>
            {i < checkpoints.length - 1 && (
              <div style={{ paddingLeft: 24, color: '#30363d', fontSize: 14, lineHeight: 1 }}>
                &darr;
              </div>
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}
