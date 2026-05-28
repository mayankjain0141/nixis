// DEPRECATED: replaced by LatticeHasseDiagram. Remove after Wave 4 verification.
import { useLatticeStore, type LatticeNode } from '../../stores/lattice-store';
import type { LabelState } from '../../types/events';

const MAX_LABEL_VALUE = 65535;

const STATE_COLORS: Record<LabelState, string> = {
  fresh: '#2da44e',
  escalated: '#d29922',
  tainted_by_secret: '#cf222e',
  declassified: '#57606a',
};

function LabelBar({ value, color }: { value: number; color: string }) {
  const pct = Math.min(100, (value / MAX_LABEL_VALUE) * 100);
  return (
    <div style={rowStyles.barTrack} aria-hidden="true">
      <div style={{ ...rowStyles.barFill, width: `${pct}%`, backgroundColor: color }} />
    </div>
  );
}

function SessionRow({
  node,
  selected,
  onSelect,
}: {
  node: LatticeNode;
  selected: boolean;
  onSelect: (id: string) => void;
}) {
  const stateColor = STATE_COLORS[node.state];
  const shortId = node.sessionId.slice(0, 8);
  const categoriesHex = `0x${node.label.categories.toString(16).toUpperCase()}`;

  return (
    <div
      style={{
        ...rowStyles.row,
        background: selected ? '#161b22' : '#0d1117',
        outline: selected ? '1px solid #388bfd' : undefined,
      }}
      role="row"
      aria-selected={selected}
      onClick={() => onSelect(node.sessionId)}
      data-testid="session-row"
    >
      <span style={rowStyles.sessionId}>{shortId}</span>
      <span
        style={{ ...rowStyles.stateBadge, backgroundColor: stateColor }}
        data-state={node.state}
        data-testid="state-badge"
      >
        {node.state}
      </span>
      <div style={rowStyles.barsGroup}>
        <div style={rowStyles.barRow}>
          <span style={rowStyles.barLabel}>C</span>
          <LabelBar value={node.label.confidentiality} color="#388bfd" />
          <span style={rowStyles.barValue}>{node.label.confidentiality}</span>
        </div>
        <div style={rowStyles.barRow}>
          <span style={rowStyles.barLabel}>I</span>
          <LabelBar value={node.label.integrity} color="#a5d6ff" />
          <span style={rowStyles.barValue}>{node.label.integrity}</span>
        </div>
      </div>
      <span style={rowStyles.categories}>{categoriesHex}</span>
      <span style={rowStyles.escalations}>{node.escalationCount}</span>
    </div>
  );
}

export function LatticeView() {
  const nodes = useLatticeStore((s) => s.nodes);
  const selectSession = useLatticeStore((s) => s.selectSession);
  const selectedSessionId = useLatticeStore((s) => s.selectedSessionId);

  if (nodes.size === 0) {
    return <div style={styles.empty}>No active sessions</div>;
  }

  return (
    <div style={styles.container}>
      <div style={styles.columnHeader} role="row" aria-hidden="true">
        <span style={rowStyles.sessionId}>Session</span>
        <span style={rowStyles.stateBadgeHeader}>State</span>
        <span style={rowStyles.barsGroup}>C / I</span>
        <span style={rowStyles.categories}>Cat</span>
        <span style={rowStyles.escalations}>Esc</span>
      </div>
      <div style={styles.rows} role="grid" aria-label="IFC session labels">
        {Array.from(nodes.values()).map((node) => (
          <SessionRow
            key={node.sessionId}
            node={node}
            selected={selectedSessionId === node.sessionId}
            onSelect={selectSession}
          />
        ))}
      </div>
    </div>
  );
}

const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column' as const,
    overflow: 'hidden',
  },
  columnHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '4px 8px',
    background: '#161b22',
    borderBottom: '1px solid #21262d',
    flexShrink: 0,
  },
  rows: {
    overflowY: 'auto' as const,
    maxHeight: '180px',
  },
  empty: {
    color: '#30363d',
    fontSize: '11px',
    fontStyle: 'italic' as const,
    padding: '8px',
  },
} as const;

const rowStyles = {
  row: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '4px 8px',
    borderBottom: '1px solid #21262d',
    cursor: 'pointer',
    boxSizing: 'border-box' as const,
  },
  sessionId: {
    color: '#8b949e',
    fontSize: '11px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    flexShrink: 0,
    width: '64px',
  },
  stateBadge: {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: '4px',
    color: '#ffffff',
    fontSize: '9px',
    fontWeight: 600,
    fontFamily: 'ui-monospace, Consolas, monospace',
    padding: '1px 4px',
    flexShrink: 0,
    minWidth: '90px',
    textAlign: 'center' as const,
    letterSpacing: '0.03em',
  },
  stateBadgeHeader: {
    color: '#57606a',
    fontSize: '11px',
    flexShrink: 0,
    minWidth: '90px',
  },
  barsGroup: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '2px',
    flex: 1,
    minWidth: 0,
  },
  barRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '3px',
  },
  barLabel: {
    color: '#57606a',
    fontSize: '9px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    flexShrink: 0,
    width: '8px',
  },
  barTrack: {
    flex: 1,
    height: '4px',
    background: '#21262d',
    borderRadius: '2px',
    overflow: 'hidden',
    minWidth: 0,
  },
  barFill: {
    height: '100%',
    borderRadius: '2px',
    transition: 'width 0.15s ease',
  },
  barValue: {
    color: '#30363d',
    fontSize: '9px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    flexShrink: 0,
    width: '36px',
    textAlign: 'right' as const,
  },
  categories: {
    color: '#57606a',
    fontSize: '10px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    flexShrink: 0,
    width: '44px',
    textAlign: 'right' as const,
  },
  escalations: {
    color: '#57606a',
    fontSize: '10px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    flexShrink: 0,
    width: '24px',
    textAlign: 'right' as const,
  },
} as const;
