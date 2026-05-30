import { useGovernanceStore } from '../../stores/governance-store';
import { useLatticeStore } from '../../stores/lattice-store';
import { confidentialityToLevel } from '../../lib/label-display';

const IFC_COLOR: Record<string, string> = {
  Restricted:   'var(--deny)',
  Confidential: 'var(--escalate)',
  Internal:     'var(--info-blue)',
  Unclassified: 'var(--allow)',
};

const STATE_TEXT: Record<string, { text: string; color: string }> = {
  tainted_by_secret: { text: 'saw a secret',   color: 'var(--deny)' },
  escalated:         { text: 'escalated',       color: 'var(--escalate)' },
  ceiling_hit:       { text: 'ceiling hit',     color: '#a855f7' },
  fresh:             { text: 'active',          color: 'var(--allow)' },
  declassified:      { text: 'declassified',    color: 'var(--text-muted)' },
};

function formatTimeRemaining(expiresAt: number): string {
  const diffMs = expiresAt * 1000 - Date.now();
  if (diffMs <= 0) {
    const agoSec = Math.floor(-diffMs / 1000);
    if (agoSec < 60) return `expired ${agoSec}s ago`;
    return `expired ${Math.floor(agoSec / 60)}m ago`;
  }
  const remSec = Math.floor(diffMs / 1000);
  if (remSec < 60) return `active, ${remSec}s left`;
  return `active, ${Math.floor(remSec / 60)}m left`;
}

interface AgentRow {
  sessionId: string;
  name: string;
  isRoot: boolean;
  isExpired: boolean;
  confidentiality: number;
  labelState: string;
  allows: number;
  denies: number;
  expiresAt?: number;
}

export function AgentsPanel() {
  const delegationChains = useGovernanceStore((s) => s.delegationChains);
  const sessionDisplayNames = useGovernanceStore((s) => s.sessionDisplayNames);
  const sessionCounters = useGovernanceStore((s) => s.sessionCounters);
  const sessionLabels = useGovernanceStore((s) => s.sessionLabels);
  const filterSession = useGovernanceStore((s) => s.filterSession);
  const latticeNodes = useLatticeStore((s) => s.nodes);

  const now = Date.now();

  // Collect all known session IDs from various sources
  const allSessionIds = new Set<string>();
  for (const [id] of sessionDisplayNames) allSessionIds.add(id);
  for (const [id] of sessionCounters) allSessionIds.add(id);
  for (const [id] of sessionLabels) allSessionIds.add(id);
  for (const [id] of latticeNodes) allSessionIds.add(id);

  // Collect all delegatee IDs to find child agents
  const delegateeToHop = new Map<string, { expiresAt?: number; grantedLabel: { confidentiality: number; integrity: number; categories: number } }>();
  for (const hops of delegationChains.values()) {
    for (const hop of hops) {
      allSessionIds.add(hop.delegateeId);
      allSessionIds.add(hop.delegatorId);
      delegateeToHop.set(hop.delegateeId, { expiresAt: hop.expiresAt, grantedLabel: hop.grantedLabel });
    }
  }

  // Identify root sessions (not a delegatee of any delegation)
  const rootSessions: string[] = [];
  const childSessions: string[] = [];
  for (const id of allSessionIds) {
    if (delegateeToHop.has(id)) {
      childSessions.push(id);
    } else {
      rootSessions.push(id);
    }
  }

  if (allSessionIds.size === 0) {
    return (
      <div style={{ padding: '16px 12px' }}>
        <div style={{
          fontSize: 11, color: 'var(--text-secondary)', fontWeight: 600,
          textTransform: 'uppercase' as const, letterSpacing: '0.06em',
          marginBottom: 12,
        }}>
          Agents
        </div>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
          No agents active. Start a session to see agent activity here.
        </p>
      </div>
    );
  }

  function buildRow(id: string, isRoot: boolean): AgentRow {
    const hop = delegateeToHop.get(id);
    const latticeNode = latticeNodes.get(id);
    const sessionLabel = sessionLabels.get(id);
    const counters = sessionCounters.get(id) ?? { allows: 0, denies: 0 };
    const name = sessionDisplayNames.get(id) ?? (isRoot ? 'You (main)' : `…${id.slice(-8)}`);

    const confidentiality =
      latticeNode?.label.confidentiality ??
      sessionLabel?.label.confidentiality ??
      hop?.grantedLabel.confidentiality ??
      0;

    const labelState =
      latticeNode?.state ??
      sessionLabel?.state ??
      'fresh';

    const expiresAt = hop?.expiresAt;
    const isExpired = expiresAt !== undefined && expiresAt * 1000 < now;

    return {
      sessionId: id,
      name,
      isRoot,
      isExpired,
      confidentiality,
      labelState,
      allows: counters.allows,
      denies: counters.denies,
      expiresAt,
    };
  }

  // Build ordered list: roots first, then children. Cap at 8.
  const rows: AgentRow[] = [];
  for (const id of rootSessions) {
    if (rows.length >= 8) break;
    rows.push(buildRow(id, true));
  }
  for (const id of childSessions) {
    if (rows.length >= 8) break;
    rows.push(buildRow(id, false));
  }

  const activeCount = rows.filter((r) => !r.isExpired).length;

  function dotSymbol(row: AgentRow): string {
    if (row.isRoot) return '▓';
    if (row.isExpired) return '○';
    return '●';
  }

  function dotColor(row: AgentRow): string {
    if (row.isExpired) return 'var(--text-muted)';
    if (row.labelState === 'tainted_by_secret') return 'var(--deny)';
    return 'var(--allow)';
  }

  function statusText(row: AgentRow): string {
    if (row.isRoot) {
      const st = STATE_TEXT[row.labelState] ?? STATE_TEXT.fresh;
      return st.text;
    }
    if (row.expiresAt !== undefined) {
      return formatTimeRemaining(row.expiresAt);
    }
    return 'active';
  }

  function statusColor(row: AgentRow): string {
    if (row.isExpired) return 'var(--text-muted)';
    if (row.labelState === 'tainted_by_secret') return 'var(--deny)';
    if (row.labelState === 'escalated') return 'var(--escalate)';
    return 'var(--text-secondary)';
  }

  return (
    <div style={{ padding: '12px 8px' }}>
      {/* Header */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '4px 4px 10px',
        fontSize: 11, color: 'var(--text-secondary)', fontWeight: 600,
        textTransform: 'uppercase' as const, letterSpacing: '0.06em',
      }}>
        <span>Agents</span>
        <span style={{ background: 'var(--bg-overlay)', borderRadius: 10, padding: '0 6px', fontWeight: 600 }}>
          {activeCount} active
        </span>
      </div>

      {/* Rows */}
      {rows.map((row) => {
        const level = confidentialityToLevel(row.confidentiality);
        const levelColor = IFC_COLOR[level] ?? 'var(--text-muted)';
        const isFiltered = filterSession === row.sessionId;
        const indent = row.isRoot ? 0 : 16;

        return (
          <div
            key={row.sessionId}
            onClick={() => {
              useGovernanceStore.getState().setFilterSession(
                filterSession === row.sessionId ? null : row.sessionId,
              );
            }}
            style={{
              paddingLeft: indent,
              marginBottom: 2,
              borderRadius: 4,
              cursor: 'pointer',
              background: isFiltered ? 'rgba(88,166,255,0.08)' : 'transparent',
              borderLeft: isFiltered ? '2px solid var(--info-blue)' : '2px solid transparent',
            }}
            onMouseEnter={(e) => {
              if (!isFiltered) (e.currentTarget as HTMLDivElement).style.background = 'rgba(255,255,255,0.04)';
            }}
            onMouseLeave={(e) => {
              if (!isFiltered) (e.currentTarget as HTMLDivElement).style.background = 'transparent';
            }}
          >
            {/* Line 1: dot + name + status */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 6px 1px' }}>
              <span style={{ color: dotColor(row), fontSize: 12, flexShrink: 0 }}>
                {dotSymbol(row)}
              </span>
              <span style={{
                fontSize: 12, fontWeight: row.isRoot ? 600 : 400,
                color: row.isExpired ? 'var(--text-muted)' : 'var(--text-primary)',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const,
                flex: 1,
              }}>
                {row.name}
              </span>
              <span style={{ fontSize: 11, color: statusColor(row), flexShrink: 0 }}>
                {statusText(row)}
              </span>
            </div>

            {/* Line 2: security level + counters */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '0 6px 5px', paddingLeft: 24 }}>
              <span style={{ fontSize: 10, color: levelColor, fontWeight: 600 }}>
                {level}
              </span>
              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>•</span>
              <span style={{ fontSize: 10, color: 'var(--text-secondary)' }}>
                {row.allows} allow / {row.denies} deny
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
