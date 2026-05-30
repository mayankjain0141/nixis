import { useLatticeStore } from '../../stores/lattice-store';
import { useGovernanceStore } from '../../stores/governance-store';

const IFC_LEVELS = [
  { id: 'restricted',   label: 'RES', color: 'var(--deny)',         minConf: 49152 },
  { id: 'confidential', label: 'CON', color: 'var(--escalate)',     minConf: 24576 },
  { id: 'internal',     label: 'INT', color: 'var(--info-blue)',    minConf: 8192 },
  { id: 'unclassified', label: 'UNC', color: 'var(--allow)',        minConf: 0 },
];

function confToLevel(c: number) {
  return IFC_LEVELS.find(l => c >= l.minConf) ?? IFC_LEVELS[3];
}

const STATE_LABELS: Record<string, { label: string; color: string }> = {
  tainted_by_secret: { label: '! TAINTED BY SECRET', color: 'var(--deny)' },
  escalated:         { label: 'Escalated',           color: 'var(--escalate)' },
  ceiling_hit:       { label: 'Ceiling hit',         color: 'var(--audit-purple)' },
  fresh:             { label: 'Active',               color: 'var(--allow)' },
  declassified:      { label: 'Declassified',         color: 'var(--text-muted)' },
};

export function SessionCards() {
  const latticeNodes = useLatticeStore((s) => s.nodes);
  const sessionLabels = useGovernanceStore((s) => s.sessionLabels);
  const events = useGovernanceStore((s) => s.events);
  const filterSession = useGovernanceStore((s) => s.filterSession);

  type SessionEntry = {
    sessionId: string;
    confidentiality: number;
    state: string;
    lastEvent?: (typeof events)[0];
  };

  const sessionMap = new Map<string, SessionEntry>();

  // Populate from governance sessionLabels first
  for (const [id, sl] of sessionLabels) {
    sessionMap.set(id, {
      sessionId: id,
      confidentiality: sl.label.confidentiality,
      state: sl.state ?? 'fresh',
    });
  }

  // Lattice store takes priority (has escalation data)
  for (const [id, node] of latticeNodes) {
    sessionMap.set(id, {
      sessionId: id,
      confidentiality: node.label.confidentiality,
      state: node.state,
    });
  }

  // Attach last event per session
  for (const event of [...events].reverse()) {
    if (event.sessionId && sessionMap.has(event.sessionId)) {
      const s = sessionMap.get(event.sessionId)!;
      if (!s.lastEvent) s.lastEvent = event;
    }
  }

  const sessions = Array.from(sessionMap.values()).slice(0, 8);

  if (sessions.length === 0) {
    return (
      <div style={{ padding: 16, color: 'var(--text-muted)', fontSize: 12, textAlign: 'center' }}>
        No active sessions
      </div>
    );
  }

  return (
    <div style={{ padding: 8 }}>
      <div style={{
        padding: '4px 8px 6px',
        fontSize: 11, color: 'var(--text-secondary)', fontWeight: 600,
        textTransform: 'uppercase' as const, letterSpacing: '0.06em',
        display: 'flex', justifyContent: 'space-between',
      }}>
        <span>Sessions</span>
        <span style={{ background: 'var(--bg-overlay)', borderRadius: 10, padding: '0 6px' }}>
          {sessions.length}
        </span>
      </div>

      {sessions.map(s => {
        const level = confToLevel(s.confidentiality)!;
        const stateInfo = STATE_LABELS[s.state] ?? STATE_LABELS.fresh;
        const isTainted = s.state === 'tainted_by_secret';

        const isActive = filterSession === s.sessionId;

        return (
          <div
            key={s.sessionId}
            onClick={() => {
              const current = useGovernanceStore.getState().filterSession;
              useGovernanceStore.getState().setFilterSession(
                current === s.sessionId ? null : s.sessionId,
              );
            }}
            style={{
              marginBottom: 6, borderRadius: 6, overflow: 'hidden',
              border: `1px solid ${isTainted ? 'rgba(207,34,46,0.3)' : 'var(--border)'}`,
              background: isTainted ? 'rgba(207,34,46,0.04)' : 'var(--bg-surface)',
              cursor: 'pointer',
              borderLeft: isActive
                ? '2px solid #2da44e'
                : `1px solid ${isTainted ? 'rgba(207,34,46,0.3)' : 'var(--border)'}`,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 10px 4px' }}>
              <span style={{
                background: level.color, color: '#fff', borderRadius: 3,
                padding: '1px 6px', fontSize: 10, fontWeight: 700,
                fontFamily: 'monospace', flexShrink: 0,
              }}>
                {level.label}
              </span>
              <span style={{
                fontFamily: 'monospace', fontSize: 11, color: 'var(--text-primary)',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const,
              }}>
                {s.sessionId.slice(-12)}
              </span>
            </div>

            <div style={{ padding: '0 10px 4px', fontSize: 11, color: stateInfo.color, fontWeight: 500 }}>
              {stateInfo.label}
            </div>

            {s.lastEvent && (
              <div style={{
                padding: '0 10px 7px', fontSize: 11, color: 'var(--text-muted)',
                display: 'flex', alignItems: 'center', gap: 6,
              }}>
                <span style={{
                  width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                  background: (
                    s.lastEvent.verdict === 'deny' ? 'var(--deny)' :
                    s.lastEvent.verdict === 'allow' ? 'var(--allow)' :
                    s.lastEvent.verdict === 'require_approval' ? 'var(--escalate)' :
                    'var(--audit-purple)'
                  ),
                }} />
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const }}>
                  {s.lastEvent.verdict.toUpperCase()} {s.lastEvent.tool}
                </span>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
