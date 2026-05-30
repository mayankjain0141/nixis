import { useThreatStore } from '../../stores/threat-store';
import type { ThreatEvent, ThreatSeverity } from '../../stores/threat-store';
import { ThreatSparkline } from './ThreatSparkline';

const MAX_VISIBLE = 20;

const SEVERITY_COLOR: Record<ThreatSeverity, string> = {
  critical: '#cf222e',
  high: '#d29922',
  medium: '#e3b341',
  low: '#388bfd',
};

const SEVERITY_BG: Record<ThreatSeverity, string> = {
  critical: 'rgba(207,34,46,0.12)',
  high: 'rgba(210,153,34,0.12)',
  medium: 'rgba(227,179,65,0.10)',
  low: 'rgba(56,139,253,0.10)',
};

function formatRelative(ms: number): string {
  const delta = Math.max(0, Date.now() - ms);
  if (delta < 60_000) return `${Math.floor(delta / 1000)}s ago`;
  if (delta < 3600_000) return `${Math.floor(delta / 60_000)}m ago`;
  return `${Math.floor(delta / 3600_000)}h ago`;
}

interface CardProps {
  threat: ThreatEvent;
  onAcknowledge: (id: string) => void;
}

function ThreatCard({ threat, onAcknowledge }: CardProps) {
  function handleShowInDag() {
    window.dispatchEvent(
      new CustomEvent('aegis:highlight-event', {
        detail: { aegisSequence: threat.aegisSequence },
      }),
    );
    window.dispatchEvent(
      new CustomEvent('aegis:navigate', { detail: { panel: 'dag' } }),
    );
  }

  const severityLabel = threat.severity.toUpperCase();

  return (
    <div
      role="listitem"
      aria-label={`${severityLabel} threat: ${threat.humanDescription}`}
      style={{
        opacity: threat.acknowledged ? 0.5 : 1,
        borderRadius: 6,
        border: `1px solid ${SEVERITY_COLOR[threat.severity]}40`,
        background: SEVERITY_BG[threat.severity],
        padding: '12px 14px',
        marginBottom: 10,
        fontFamily: 'ui-sans-serif, system-ui, sans-serif',
      }}
    >
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <span
          style={{
            background: SEVERITY_COLOR[threat.severity],
            color: '#fff',
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: '0.08em',
            padding: '2px 7px',
            borderRadius: 4,
            fontFamily: 'ui-monospace, Consolas, monospace',
            flexShrink: 0,
          }}
          aria-label={`Severity: ${severityLabel}`}
        >
          {severityLabel}
        </span>
        <span
          style={{
            color: '#e6edf3',
            fontSize: 13,
            fontWeight: 600,
            flex: 1,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {threat.humanDescription}
        </span>
        <span
          style={{
            color: '#57606a',
            fontSize: 11,
            fontFamily: 'ui-monospace, Consolas, monospace',
            flexShrink: 0,
          }}
        >
          {formatRelative(threat.timestamp)}
        </span>
      </div>

      {/* Session row */}
      <div style={{ color: '#8b949e', fontSize: 12, marginBottom: 4 }}>
        Session:{' '}
        <span style={{ color: '#b1bac4' }}>{threat.relatedSessionName}</span>
      </div>

      {/* Impact row */}
      {threat.impact && (
        <div style={{ color: '#8b949e', fontSize: 12, marginBottom: 10 }}>
          Impact:{' '}
          <span style={{ color: '#b1bac4' }}>{threat.impact}</span>
        </div>
      )}

      {/* Action buttons */}
      <div style={{ display: 'flex', gap: 8 }}>
        {!threat.acknowledged && (
          <button
            onClick={() => onAcknowledge(threat.id)}
            aria-label={`Acknowledge threat ${threat.id}`}
            style={{
              background: '#21262d',
              border: '1px solid #30363d',
              borderRadius: 4,
              color: '#8b949e',
              cursor: 'pointer',
              fontSize: 11,
              padding: '3px 10px',
              fontFamily: 'ui-monospace, Consolas, monospace',
            }}
          >
            Acknowledge
          </button>
        )}
        <button
          onClick={handleShowInDag}
          aria-label="Show this event in the DAG"
          style={{
            background: 'transparent',
            border: '1px solid #30363d',
            borderRadius: 4,
            color: '#388bfd',
            cursor: 'pointer',
            fontSize: 11,
            padding: '3px 10px',
            fontFamily: 'ui-monospace, Consolas, monospace',
          }}
        >
          Show in DAG
        </button>
      </div>
    </div>
  );
}

export function ThreatFeed() {
  const threats = useThreatStore((s) => s.threats);
  const unacknowledgedCount = useThreatStore((s) => s.unacknowledgedCount);
  const acknowledge = useThreatStore((s) => s.acknowledge);

  const visible = threats.slice(0, MAX_VISIBLE);
  const overflow = threats.length - MAX_VISIBLE;

  return (
    <div
      role="region"
      aria-label="Security alerts feed"
      style={{
        display: 'flex',
        flexDirection: 'column',
        background: '#0d1117',
        height: '100%',
        overflow: 'hidden',
      }}
    >
      {/* Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          padding: '10px 14px',
          background: '#161b22',
          borderBottom: '1px solid #21262d',
          flexShrink: 0,
        }}
      >
        <span
          style={{
            color: '#e6edf3',
            fontSize: 13,
            fontWeight: 600,
            fontFamily: 'ui-monospace, Consolas, monospace',
            letterSpacing: '0.04em',
          }}
        >
          SECURITY ALERTS
        </span>
        {unacknowledgedCount > 0 && (
          <span
            style={{
              marginLeft: 'auto',
              color: '#cf222e',
              fontSize: 12,
              fontFamily: 'ui-monospace, Consolas, monospace',
              fontWeight: 600,
            }}
            aria-label={`${unacknowledgedCount} unread alerts`}
            data-testid="unread-count"
          >
            {unacknowledgedCount} unread
          </span>
        )}
      </div>

      {/* Sparkline — shown when >= 3 events */}
      {threats.length >= 3 && (
        <div style={{ padding: '8px 14px 0', flexShrink: 0 }}>
          <ThreatSparkline threats={threats} />
        </div>
      )}

      {/* Cards */}
      <div
        role="list"
        aria-label="Alert list"
        style={{ overflowY: 'auto', flex: 1, padding: '12px 14px 0' }}
      >
        {threats.length === 0 ? (
          <p
            role="status"
            style={{
              color: '#57606a',
              fontSize: 13,
              fontFamily: 'ui-sans-serif, system-ui, sans-serif',
              textAlign: 'center',
              marginTop: 24,
            }}
          >
            No security alerts. The system is monitoring for secrets, policy violations, and tool drift.
          </p>
        ) : (
          <>
            {visible.map((threat) => (
              <ThreatCard
                key={threat.id}
                threat={threat}
                onAcknowledge={acknowledge}
              />
            ))}
            {overflow > 0 && (
              <p
                style={{
                  color: '#57606a',
                  fontSize: 12,
                  fontFamily: 'ui-monospace, Consolas, monospace',
                  textAlign: 'center',
                  padding: '8px 0 16px',
                }}
              >
                Show {overflow} older alert{overflow !== 1 ? 's' : ''}
              </p>
            )}
            <p
              style={{
                color: '#30363d',
                fontSize: 11,
                fontFamily: 'ui-monospace, Consolas, monospace',
                textAlign: 'center',
                padding: '4px 0 16px',
              }}
            >
              -- No more alerts --
            </p>
          </>
        )}
      </div>
    </div>
  );
}
