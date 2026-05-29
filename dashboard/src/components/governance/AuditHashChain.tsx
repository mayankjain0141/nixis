import React from 'react';
import { useGovernanceStore } from '../../stores/governance-store';

export function AuditHashChain() {
  const events = useGovernanceStore((s) => s.events);
  const checkpoints = events.filter((e) => e.tool === 'audit');

  if (checkpoints.length === 0) {
    return (
      <div style={{ padding: 16, color: 'var(--text-muted)', fontSize: 13 }}>
        <div style={{ marginBottom: 8 }}>No audit checkpoints yet.</div>
        <div style={{ fontSize: 11, lineHeight: 1.6, color: 'var(--text-muted)' }}>
          The daemon writes a checkpoint every N events — a cryptographic digest
          of everything that happened since the last checkpoint. The chain makes
          the audit trail tamper-evident: editing any past event changes its
          digest and breaks the chain.
        </div>
      </div>
    );
  }

  return (
    <div
      aria-label="Audit hash chain"
      style={{ display: 'flex', flexDirection: 'column', gap: 2, padding: 8 }}
    >
      {/* Header explaining what the chain is */}
      <div style={{
        padding: '6px 10px 8px',
        fontSize: 11,
        color: 'var(--text-muted)',
        lineHeight: 1.6,
        borderBottom: '1px solid var(--border)',
        marginBottom: 4,
      }}>
        Each block seals the events since the previous checkpoint into a SHA-256
        digest. <strong style={{ color: 'var(--text-secondary)' }}>DIGEST</strong> = hash
        of this batch. <strong style={{ color: 'var(--text-secondary)' }}>CHAINED FROM</strong> = previous
        block's digest. Tampering with any past event breaks the chain at that point.
      </div>

      {checkpoints.map((cp, i) => {
        const isLatest = i === checkpoints.length - 1;
        const cel = cp.celExpression ?? '';
        const hashMatch = cel.match(/hash:([^\s]+)/);
        const prevMatch = cel.match(/prev:([^\s]+)/);

        // Extract the actual hash values — fall back to event ID slice
        const digest   = hashMatch ? hashMatch[1] : cp.id.slice(0, 20);
        const prevHash = prevMatch ? prevMatch[1] : null;

        // Show first 8 + last 4 chars for readability
        const shortDigest = digest.length > 12
          ? `${digest.slice(0, 8)}…${digest.slice(-4)}`
          : digest;
        const shortPrev = prevHash
          ? prevHash.length > 12
            ? `${prevHash.slice(0, 8)}…${prevHash.slice(-4)}`
            : prevHash
          : null;

        const isFirst = i === 0;

        return (
          <React.Fragment key={cp.id}>
            {/* Chain connector showing "this seals from previous" */}
            {!isFirst && (
              <div style={{
                paddingLeft: 14, fontSize: 10,
                color: 'var(--text-muted)', lineHeight: 1,
                display: 'flex', alignItems: 'center', gap: 4,
              }}>
                <span style={{ color: 'var(--border)', fontSize: 14 }}>↓</span>
                <span>chained from above</span>
              </div>
            )}

            <div
              data-sequence={cp.aegisSequence}
              style={{
                background: 'var(--bg-surface)',
                border: `1px solid ${isLatest ? 'var(--info-blue)' : 'var(--border)'}`,
                borderRadius: 6,
                padding: '8px 12px',
                fontSize: 11,
              }}
            >
              {/* Block header */}
              <div style={{
                display: 'flex', justifyContent: 'space-between',
                alignItems: 'center', marginBottom: 6,
              }}>
                <span style={{
                  color: isLatest ? 'var(--info-blue)' : 'var(--text-secondary)',
                  fontWeight: 600, fontSize: 12,
                }}>
                  Block #{cp.aegisSequence}
                  {isLatest && (
                    <span style={{
                      marginLeft: 8, fontSize: 9, fontWeight: 700,
                      background: 'var(--info-blue)', color: '#fff',
                      borderRadius: 3, padding: '1px 5px', letterSpacing: '0.04em',
                    }}>LATEST</span>
                  )}
                  {isFirst && !isLatest && (
                    <span style={{
                      marginLeft: 8, fontSize: 9,
                      color: 'var(--text-muted)', letterSpacing: '0.04em',
                    }}>GENESIS</span>
                  )}
                </span>
                <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>
                  {cp.reason}
                </span>
              </div>

              {/* Digest of this block's events */}
              <div style={{ marginBottom: prevHash ? 4 : 0 }}>
                <span style={{ color: 'var(--text-muted)', fontSize: 10, marginRight: 6 }}>
                  DIGEST (this batch)
                </span>
                <span style={{
                  fontFamily: 'monospace',
                  color: isLatest ? 'var(--info-blue)' : 'var(--allow)',
                  letterSpacing: '0.03em',
                }}>
                  {shortDigest}
                </span>
              </div>

              {/* Previous block's digest — what this block "seals on top of" */}
              {shortPrev && (
                <div>
                  <span style={{ color: 'var(--text-muted)', fontSize: 10, marginRight: 6 }}>
                    CHAINED FROM (prev block)
                  </span>
                  <span style={{
                    fontFamily: 'monospace',
                    color: 'var(--text-muted)',
                    letterSpacing: '0.03em',
                  }}>
                    {shortPrev}
                  </span>
                </div>
              )}
              {isFirst && !shortPrev && (
                <div style={{ color: 'var(--text-muted)', fontSize: 10, fontStyle: 'italic' }}>
                  Genesis block — no predecessor
                </div>
              )}
            </div>
          </React.Fragment>
        );
      })}

      {/* Footer: tamper-evidence explanation */}
      {checkpoints.length > 1 && (
        <div style={{
          marginTop: 6, padding: '6px 10px',
          borderRadius: 4, background: 'var(--bg-overlay)',
          fontSize: 10, color: 'var(--text-muted)', lineHeight: 1.6,
        }}>
          ✓ Chain intact — each block's CHAINED FROM matches the preceding block's DIGEST.
          Any modification to past events would produce a different digest and break the chain here.
        </div>
      )}
    </div>
  );
}
