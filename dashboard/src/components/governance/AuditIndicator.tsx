import { useGovernanceStore } from '../../stores/governance-store';

export function AuditIndicator() {
  const auditChainIntact = useGovernanceStore((s) => s.auditChainIntact);
  const totalSealedEvents = useGovernanceStore((s) => s.totalSealedEvents);
  const auditCheckpoints = useGovernanceStore((s) => s.auditCheckpoints);
  const setAuditModalOpen = useGovernanceStore((s) => s.setAuditModalOpen);

  const noEvents = totalSealedEvents === 0 && auditCheckpoints.length === 0;

  let chipContent: React.ReactNode;
  let chipStyle: React.CSSProperties;

  if (noEvents) {
    chipContent = '— no events';
    chipStyle = {
      color: '#57606a',
      background: 'rgba(87,96,106,0.1)',
      border: '1px solid #30363d',
    };
  } else if (auditChainIntact) {
    chipContent = (
      <>
        <span style={{ color: '#3fb950', marginRight: 4 }}>✓</span>
        {totalSealedEvents} sealed
      </>
    );
    chipStyle = {
      color: '#3fb950',
      background: 'rgba(63,185,80,0.1)',
      border: '1px solid rgba(63,185,80,0.3)',
    };
  } else {
    chipContent = (
      <>
        <span style={{ marginRight: 4 }}>✗</span>
        CHAIN BROKEN
      </>
    );
    chipStyle = {
      color: '#f85149',
      background: 'rgba(248,81,73,0.1)',
      border: '1px solid rgba(248,81,73,0.4)',
    };
  }

  return (
    <button
      onClick={() => setAuditModalOpen(true)}
      aria-label="Open audit modal"
      style={{
        marginLeft: 'auto',
        display: 'flex',
        alignItems: 'center',
        fontSize: 11,
        fontWeight: 600,
        letterSpacing: '0.04em',
        padding: '2px 10px',
        borderRadius: 4,
        cursor: 'pointer',
        fontFamily: 'inherit',
        ...chipStyle,
      }}
    >
      {chipContent}
    </button>
  );
}

export function AuditAlarmBanner() {
  const auditChainIntact = useGovernanceStore((s) => s.auditChainIntact);
  const setAuditModalOpen = useGovernanceStore((s) => s.setAuditModalOpen);

  if (auditChainIntact) return null;

  return (
    <div
      role="alert"
      style={{
        background: 'rgba(248,81,73,0.08)',
        border: '1px solid rgba(248,81,73,0.4)',
        borderTop: 'none',
        padding: '8px 16px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 12,
        flexShrink: 0,
      }}
    >
      <span style={{ fontSize: 12, color: '#f85149' }}>
        <strong>Audit chain integrity failure.</strong>{' '}
        Events after the break cannot be verified.
      </span>
      <button
        onClick={() => setAuditModalOpen(true)}
        style={{
          fontSize: 11,
          fontWeight: 600,
          color: '#f85149',
          background: 'rgba(248,81,73,0.15)',
          border: '1px solid rgba(248,81,73,0.4)',
          borderRadius: 4,
          padding: '3px 10px',
          cursor: 'pointer',
          whiteSpace: 'nowrap',
          fontFamily: 'inherit',
        }}
      >
        Open Audit Details
      </button>
    </div>
  );
}
