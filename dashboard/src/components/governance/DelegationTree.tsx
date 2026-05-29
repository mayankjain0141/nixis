import { useGovernanceStore, type DelegationHop } from '../../stores/governance-store';
import { confidentialityToLevel } from '../../lib/label-display';

const IFC_COLOR: Record<string, string> = {
  Restricted:   'var(--deny)',
  Confidential: 'var(--escalate)',
  Internal:     'var(--info-blue)',
  Unclassified: 'var(--allow)',
};

function labelBadge(conf: number) {
  const level = confidentialityToLevel(conf);
  const color = IFC_COLOR[level] ?? 'var(--text-muted)';
  return { level, color };
}

function shortId(id: string) {
  // Show last 8 chars of session ID or the full thing if short
  return id.length > 12 ? `…${id.slice(-8)}` : id;
}

interface ChainEntry {
  sessionId: string;
  role: string;
  ceiling: { confidentiality: number; integrity: number; categories: number };
  granted: { confidentiality: number; integrity: number; categories: number };
  attenuated: boolean;
  expiresAt?: number;
}

function buildChainEntries(
  delegatorId: string,
  hops: DelegationHop[],
): ChainEntry[] {
  const entries: ChainEntry[] = [
    {
      sessionId: delegatorId,
      role: 'Delegator (origin)',
      ceiling: hops[0]?.grantedLabel ?? { confidentiality: 0, integrity: 0, categories: 0 },
      granted: hops[0]?.grantedLabel ?? { confidentiality: 0, integrity: 0, categories: 0 },
      attenuated: false,
    },
  ];
  hops.forEach((hop, i) => {
    const prevGranted = i === 0
      ? hops[0].grantedLabel
      : hops[i - 1].ceilingLabel;
    entries.push({
      sessionId: hop.delegateeId,
      role: i === hops.length - 1 ? 'Delegatee (active)' : `Relay hop ${i + 1}`,
      ceiling: hop.ceilingLabel,
      granted: hop.grantedLabel,
      attenuated: hop.ceilingLabel.confidentiality < prevGranted.confidentiality,
      expiresAt: hop.expiresAt,
    });
  });
  return entries;
}

export function DelegationTree() {
  const delegationChains = useGovernanceStore((s) => s.delegationChains);

  // Collect all chains (may be multiple sessions)
  const allChains: Array<{ delegatorId: string; hops: DelegationHop[] }> = [];
  for (const [sessionId, hops] of delegationChains.entries()) {
    if (hops.length > 0) {
      allChains.push({ delegatorId: hops[0].delegatorId, hops });
    }
  }

  if (allChains.length === 0) {
    return (
      <div style={{
        padding: 24, color: 'var(--text-muted)', fontSize: 13,
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8,
      }}>
        <div style={{ fontSize: 28, opacity: 0.3 }}>⇢</div>
        <div>No delegation chains active</div>
        <div style={{ fontSize: 11, textAlign: 'center', maxWidth: 240 }}>
          Delegation appears when an agent grants a sub-agent permission to act
          on its behalf with a reduced capability ceiling.
        </div>
      </div>
    );
  }

  return (
    <div style={{ padding: '8px 12px', overflow: 'auto' }}>
      {allChains.map(({ delegatorId, hops }, ci) => {
        const entries = buildChainEntries(delegatorId, hops);
        return (
          <div key={ci} style={{ marginBottom: 20 }}>
            {entries.map((entry, i) => {
              const { level, color } = labelBadge(entry.ceiling.confidentiality);
              const isLast = i === entries.length - 1;
              const expired = entry.expiresAt && entry.expiresAt < Date.now();
              return (
                <div key={entry.sessionId}>
                  {/* Node */}
                  <div style={{
                    display: 'flex', alignItems: 'flex-start', gap: 10,
                    padding: '8px 10px', borderRadius: 6,
                    background: i === 0 ? 'rgba(88,166,255,0.06)' : 'var(--bg-surface)',
                    border: `1px solid ${i === 0 ? 'rgba(88,166,255,0.2)' : 'var(--border)'}`,
                    opacity: expired ? 0.5 : 1,
                  }}>
                    {/* IFC badge */}
                    <div style={{
                      flexShrink: 0, marginTop: 2,
                      background: color, color: '#fff',
                      borderRadius: 3, padding: '1px 6px',
                      fontSize: 10, fontWeight: 700, fontFamily: 'monospace',
                      minWidth: 32, textAlign: 'center',
                    }}>
                      {level.slice(0, 3).toUpperCase()}
                    </div>

                    {/* Content */}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                        <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-primary)' }}>
                          {shortId(entry.sessionId)}
                        </span>
                        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                          {entry.role}
                        </span>
                        {expired && (
                          <span style={{ fontSize: 10, color: 'var(--deny)', fontWeight: 600 }}>EXPIRED</span>
                        )}
                      </div>
                      <div style={{ marginTop: 3, fontSize: 11, color: 'var(--text-secondary)' }}>
                        Ceiling:{' '}
                        <span style={{ color, fontWeight: 500 }}>{level}</span>
                        {entry.attenuated && (
                          <span style={{ marginLeft: 6, color: 'var(--deny)', fontSize: 10 }}>
                            ↓ attenuated from {confidentialityToLevel(entry.granted.confidentiality)}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Connector arrow */}
                  {!isLast && (
                    <div style={{
                      marginLeft: 22, paddingLeft: 10,
                      borderLeft: '2px dashed var(--border)',
                      height: 16, display: 'flex', alignItems: 'flex-end',
                    }}>
                      <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 6 }}>
                        delegates →
                      </span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        );
      })}

      {/* Legend */}
      <div style={{
        marginTop: 8, padding: '6px 8px', borderRadius: 4,
        background: 'var(--bg-overlay)', fontSize: 10, color: 'var(--text-muted)',
        lineHeight: 1.6,
      }}>
        <strong style={{ color: 'var(--text-secondary)' }}>What this shows:</strong> Each agent session
        can delegate to a sub-agent with a <em>lower</em> capability ceiling.
        "↓ attenuated" means the sub-agent received fewer permissions than the parent had.
        The sub-agent can never exceed its ceiling, even if the parent could.
      </div>
    </div>
  );
}
