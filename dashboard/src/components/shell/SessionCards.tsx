import { useGovernanceStore } from '../../stores/governance-store';
import { useLatticeStore } from '../../stores/lattice-store';

const DOT_COLORS: Record<string, string> = {
  tainted_by_secret: 'var(--deny)',
  escalated:         'var(--escalate)',
  ceiling_hit:       '#a855f7',
  fresh:             'var(--allow)',
  declassified:      'var(--text-muted)',
};

export function SessionCards() {
  const sessionDisplayNames = useGovernanceStore((s) => s.sessionDisplayNames);
  const sessionCounters = useGovernanceStore((s) => s.sessionCounters);
  const sessionLabels = useGovernanceStore((s) => s.sessionLabels);
  const filterSession = useGovernanceStore((s) => s.filterSession);
  const latticeNodes = useLatticeStore((s) => s.nodes);

  // Collect all known session IDs
  const allIds = new Set<string>();
  for (const [id] of sessionDisplayNames) allIds.add(id);
  for (const [id] of sessionCounters) allIds.add(id);
  for (const [id] of sessionLabels) allIds.add(id);
  for (const [id] of latticeNodes) allIds.add(id);

  if (allIds.size === 0) {
    return (
      <div style={{ padding: '8px 10px' }}>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>No sessions</p>
      </div>
    );
  }

  interface Row {
    sessionId: string;
    name: string;
    labelState: string;
    allows: number;
    denies: number;
  }

  const rows: Row[] = Array.from(allIds).map((id) => {
    const latticeNode = latticeNodes.get(id);
    const sessionLabel = sessionLabels.get(id);
    const counters = sessionCounters.get(id) ?? { allows: 0, denies: 0 };
    const name = sessionDisplayNames.get(id) ?? `…${id.slice(-8)}`;
    const labelState = latticeNode?.state ?? sessionLabel?.state ?? 'fresh';

    return {
      sessionId: id,
      name,
      labelState,
      allows: counters.allows,
      denies: counters.denies,
    };
  });

  function dotSymbol(state: string): string {
    if (state === 'tainted_by_secret') return '▓';
    return '●';
  }

  return (
    <div style={{ padding: '8px 6px' }}>
      {/* Header */}
      <div style={{
        padding: '2px 4px 6px',
        fontSize: 11, color: 'var(--text-secondary)', fontWeight: 600,
        textTransform: 'uppercase' as const, letterSpacing: '0.06em',
        display: 'flex', justifyContent: 'space-between',
      }}>
        <span>Agents</span>
        <span style={{ background: 'var(--bg-overlay)', borderRadius: 10, padding: '0 6px' }}>
          {rows.length}
        </span>
      </div>

      {/* Rows — scroll when more than 4 agents */}
      <div style={{ maxHeight: rows.length > 4 ? 128 : undefined, overflowY: rows.length > 4 ? 'auto' : undefined }}>
        {rows.map((row) => {
          const isSelected = filterSession === row.sessionId;
          const dotColor = DOT_COLORS[row.labelState] ?? DOT_COLORS.fresh;

          return (
            <div
              key={row.sessionId}
              onClick={() => {
                useGovernanceStore.getState().setFilterSession(
                  filterSession === row.sessionId ? null : row.sessionId,
                );
              }}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '4px 6px',
                borderRadius: 4,
                cursor: 'pointer',
                background: isSelected ? 'rgba(255,255,255,0.10)' : 'transparent',
                borderLeft: isSelected ? '2px solid var(--info-blue)' : '2px solid transparent',
                marginBottom: 1,
              }}
              onMouseEnter={(e) => {
                if (!isSelected) (e.currentTarget as HTMLDivElement).style.background = 'rgba(255,255,255,0.04)';
              }}
              onMouseLeave={(e) => {
                if (!isSelected) (e.currentTarget as HTMLDivElement).style.background = 'transparent';
              }}
            >
              <span style={{ color: dotColor, fontSize: 11, flexShrink: 0 }}>
                {dotSymbol(row.labelState)}
              </span>
              <span style={{
                fontSize: 12,
                color: 'var(--text-primary)',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const,
                flex: 1,
              }}>
                {row.name}
              </span>
              <span style={{ fontSize: 11, color: 'var(--text-secondary)', flexShrink: 0, fontFamily: 'monospace' }}>
                {row.allows}/{row.denies}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
