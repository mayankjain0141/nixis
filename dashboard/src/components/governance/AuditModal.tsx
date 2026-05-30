import { useGovernanceStore } from '../../stores/governance-store';

function formatRelativeTime(timestamp: number): string {
  const diffMs = Date.now() - timestamp;
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  return `${diffHr}h ago`;
}

function handleExport() {
  const data = useGovernanceStore.getState().auditCheckpoints;
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'audit-log.json';
  a.click();
  URL.revokeObjectURL(url);
}

export function AuditModal() {
  const auditModalOpen = useGovernanceStore((s) => s.auditModalOpen);
  const auditCheckpoints = useGovernanceStore((s) => s.auditCheckpoints);
  const auditChainIntact = useGovernanceStore((s) => s.auditChainIntact);
  const totalSealedEvents = useGovernanceStore((s) => s.totalSealedEvents);
  const setAuditModalOpen = useGovernanceStore((s) => s.setAuditModalOpen);

  if (!auditModalOpen) return null;

  const brokenAt = !auditChainIntact
    ? auditCheckpoints.findIndex((cp, i) => {
        if (i === 0) return cp.prevHash !== null;
        return cp.prevHash !== auditCheckpoints[i - 1].hash;
      })
    : -1;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Audit forensic review"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.6)',
        zIndex: 1000,
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
      }}
      onClick={() => setAuditModalOpen(false)}
    >
      <div
        style={{
          background: '#161b22',
          border: '1px solid #30363d',
          borderRadius: 8,
          width: '100%',
          maxWidth: 672,
          maxHeight: '80vh',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: '0 16px 48px rgba(0,0,0,0.6)',
          overflow: 'hidden',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '14px 18px',
          borderBottom: '1px solid #30363d',
          flexShrink: 0,
        }}>
          <span style={{ fontSize: 14, fontWeight: 600, color: '#e6edf3' }}>
            Audit Forensic Review
          </span>
          <button
            onClick={() => setAuditModalOpen(false)}
            aria-label="Close audit modal"
            style={{
              background: 'transparent',
              border: 'none',
              color: '#57606a',
              fontSize: 18,
              cursor: 'pointer',
              lineHeight: 1,
              padding: '0 2px',
              fontFamily: 'inherit',
            }}
          >
            ✕
          </button>
        </div>

        {/* Chain status */}
        <div style={{
          padding: '12px 18px',
          borderBottom: '1px solid #30363d',
          flexShrink: 0,
        }}>
          {auditChainIntact ? (
            <div style={{ fontSize: 13, color: '#3fb950' }}>
              ✓ Chain verified — {totalSealedEvents} events sealed
            </div>
          ) : (
            <div style={{ fontSize: 13, color: '#f85149' }}>
              ✗ Chain broken — events after checkpoint #{brokenAt} cannot be verified
            </div>
          )}
          <div style={{ marginTop: 6, fontSize: 11, color: '#57606a', display: 'flex', gap: 20 }}>
            <span>{auditCheckpoints.length} checkpoint{auditCheckpoints.length !== 1 ? 's' : ''}</span>
            <span>{totalSealedEvents} total sealed events</span>
          </div>
        </div>

        {/* Checkpoint list */}
        <div style={{
          overflowY: 'auto',
          flex: 1,
          padding: '8px 0',
        }}>
          {auditCheckpoints.length === 0 ? (
            <div style={{ padding: '24px 18px', color: '#57606a', fontSize: 13, textAlign: 'center' }}>
              No checkpoints yet — the daemon writes one every N events.
            </div>
          ) : (
            auditCheckpoints.map((cp, i) => {
              const isBroken = !auditChainIntact && i === brokenAt;
              return (
                <div
                  key={cp.sequence}
                  style={{
                    display: 'flex',
                    alignItems: 'baseline',
                    gap: 10,
                    padding: '7px 18px',
                    borderBottom: i < auditCheckpoints.length - 1 ? '1px solid #21262d' : 'none',
                    background: isBroken ? 'rgba(248,81,73,0.06)' : 'transparent',
                  }}
                >
                  <span style={{ fontSize: 11, fontWeight: 600, color: '#57606a', minWidth: 32 }}>
                    #{cp.sequence}
                  </span>
                  <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#3fb950', flex: 1 }}>
                    hash: {cp.hash.slice(0, 8)}…
                  </span>
                  <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#57606a', flex: 1 }}>
                    prev: {cp.prevHash ? `${cp.prevHash.slice(0, 8)}…` : 'none'}
                  </span>
                  <span style={{ fontSize: 11, color: '#57606a', minWidth: 60, textAlign: 'right' }}>
                    {cp.eventCount} evt{cp.eventCount !== 1 ? 's' : ''}
                  </span>
                  <span style={{ fontSize: 10, color: '#57606a', minWidth: 72, textAlign: 'right' }}>
                    {formatRelativeTime(cp.timestamp)}
                  </span>
                  {isBroken && (
                    <span style={{ fontSize: 10, color: '#f85149', fontWeight: 600 }}>BREAK</span>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div style={{
          padding: '12px 18px',
          borderTop: '1px solid #30363d',
          display: 'flex',
          justifyContent: 'flex-end',
          flexShrink: 0,
        }}>
          <button
            onClick={handleExport}
            style={{
              fontSize: 12,
              fontWeight: 600,
              color: '#e6edf3',
              background: '#21262d',
              border: '1px solid #30363d',
              borderRadius: 5,
              padding: '6px 14px',
              cursor: 'pointer',
              fontFamily: 'inherit',
            }}
          >
            Export Audit Log
          </button>
        </div>
      </div>
    </div>
  );
}
