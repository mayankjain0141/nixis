import { useThreatStore, type ThreatEvent, type ThreatSeverity } from '../../stores/threat-store';

const SEVERITY_COLORS: Record<ThreatSeverity, string> = {
  critical: '#cf222e',
  high: '#d29922',
  medium: '#e3b341',
  low: '#388bfd',
};

function formatTimestamp(ms: number): string {
  const d = new Date(ms);
  const hh = d.getHours().toString().padStart(2, '0');
  const mm = d.getMinutes().toString().padStart(2, '0');
  const ss = d.getSeconds().toString().padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
}

function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return text.slice(0, max - 1) + '…';
}

function ThreatItem({ threat, onAcknowledge }: { threat: ThreatEvent; onAcknowledge: (id: string) => void }) {
  const severityColor = SEVERITY_COLORS[threat.severity];
  const sessionShort = truncate(threat.sessionId, 12);

  return (
    <div style={{ ...itemStyles.row, opacity: threat.acknowledged ? 0.5 : 1 }}>
      <div style={itemStyles.top}>
        <span
          style={{ ...itemStyles.badge, backgroundColor: severityColor }}
          aria-label={`Severity: ${threat.severity}`}
        >
          {threat.severity}
        </span>
        <span style={itemStyles.tool} title={threat.tool}>{truncate(threat.tool, 20)}</span>
        <span style={itemStyles.timestamp}>{formatTimestamp(threat.timestamp)}</span>
      </div>
      <div style={itemStyles.bottom}>
        <span style={itemStyles.description} title={threat.description}>
          {truncate(threat.description, 60)}
        </span>
        <span style={itemStyles.session} title={threat.sessionId}>{sessionShort}</span>
        {!threat.acknowledged && (
          <button
            style={itemStyles.ackBtn}
            onClick={() => onAcknowledge(threat.id)}
            aria-label={`Acknowledge threat ${threat.id}`}
          >
            Ack
          </button>
        )}
      </div>
    </div>
  );
}

export function ThreatPanel() {
  const threats = useThreatStore((s) => s.threats);
  const unacknowledgedCount = useThreatStore((s) => s.unacknowledgedCount);
  const acknowledge = useThreatStore((s) => s.acknowledge);
  const acknowledgeAll = useThreatStore((s) => s.acknowledgeAll);

  return (
    <div style={styles.container} role="region" aria-label="Threat panel">
      <div style={styles.header}>
        <span style={styles.title}>Threats</span>
        {unacknowledgedCount > 0 && (
          <span
            style={styles.badge}
            aria-label={`${unacknowledgedCount} unacknowledged threats`}
            data-testid="unacknowledged-count"
          >
            {unacknowledgedCount}
          </span>
        )}
        {threats.length > 0 && (
          <button style={styles.clearBtn} onClick={acknowledgeAll} aria-label="Acknowledge all threats">
            Clear All
          </button>
        )}
      </div>

      {threats.length === 0 ? (
        <div style={styles.empty} role="status">
          No active threats
        </div>
      ) : (
        <div style={styles.list} role="list" aria-label="Active threats">
          {threats.map((threat) => (
            <div key={threat.id} role="listitem">
              <ThreatItem threat={threat} onAcknowledge={acknowledge} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column' as const,
    background: '#0d1117',
    borderTop: '1px solid #21262d',
    flex: '0 0 auto',
    maxHeight: '280px',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '8px 12px',
    background: '#161b22',
    borderBottom: '1px solid #21262d',
    flexShrink: 0,
  },
  title: {
    color: '#e6edf3',
    fontSize: '13px',
    fontWeight: 600,
    fontFamily: 'ui-monospace, Consolas, monospace',
  },
  badge: {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: '#cf222e',
    color: '#ffffff',
    fontSize: '10px',
    fontWeight: 700,
    fontFamily: 'ui-monospace, Consolas, monospace',
    borderRadius: '10px',
    padding: '1px 6px',
    minWidth: '18px',
  },
  clearBtn: {
    marginLeft: 'auto',
    background: '#21262d',
    border: '1px solid #30363d',
    borderRadius: '4px',
    color: '#8b949e',
    cursor: 'pointer',
    fontSize: '11px',
    padding: '2px 8px',
    fontFamily: 'ui-monospace, Consolas, monospace',
  },
  list: {
    overflowY: 'auto' as const,
    flex: 1,
  },
  empty: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '16px',
    color: '#57606a',
    fontSize: '12px',
    fontFamily: 'ui-monospace, Consolas, monospace',
  },
} as const;

const itemStyles = {
  row: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '4px',
    padding: '8px 12px',
    borderBottom: '1px solid #21262d',
    background: '#0d1117',
  },
  top: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  bottom: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  badge: {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: '4px',
    color: '#ffffff',
    fontSize: '10px',
    fontWeight: 600,
    fontFamily: 'ui-monospace, Consolas, monospace',
    padding: '1px 5px',
    flexShrink: 0,
    minWidth: '52px',
    textAlign: 'center' as const,
    letterSpacing: '0.03em',
  },
  tool: {
    color: '#e6edf3',
    fontSize: '12px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    flex: 1,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap' as const,
  },
  timestamp: {
    color: '#57606a',
    fontSize: '11px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    flexShrink: 0,
  },
  description: {
    color: '#8b949e',
    fontSize: '11px',
    fontFamily: 'ui-sans-serif, system-ui, sans-serif',
    flex: 1,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap' as const,
  },
  session: {
    color: '#30363d',
    fontSize: '10px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    flexShrink: 0,
  },
  ackBtn: {
    background: 'transparent',
    border: '1px solid #30363d',
    borderRadius: '3px',
    color: '#57606a',
    cursor: 'pointer',
    fontSize: '10px',
    padding: '1px 6px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    flexShrink: 0,
  },
} as const;
