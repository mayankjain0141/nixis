import { useCallback, useEffect, useRef, useState } from 'react';
import { List, useListRef } from 'react-window';
import type { CSSProperties } from 'react';
import { useGovernanceStore, type GovernanceEvent } from '../../stores/governance-store';
import type { Verdict } from '../../types/events';

const ROW_HEIGHT = 36;
const VISIBLE_ROWS = 20;
const LIST_HEIGHT = ROW_HEIGHT * VISIBLE_ROWS;

const VERDICT_COLORS: Record<Verdict, string> = {
  deny: '#cf222e',
  allow: '#2da44e',
  require_approval: '#d29922',
  audit: '#57606a',
};

function formatTimestamp(timestampNs: number): string {
  const ms = Math.floor(timestampNs / 1_000_000);
  const d = new Date(ms);
  const hh = d.getHours().toString().padStart(2, '0');
  const mm = d.getMinutes().toString().padStart(2, '0');
  const ss = d.getSeconds().toString().padStart(2, '0');
  const ms3 = d.getMilliseconds().toString().padStart(3, '0');
  return `${hh}:${mm}:${ss}.${ms3}`;
}

function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return text.slice(0, max - 1) + '…';
}

interface RowProps {
  events: readonly GovernanceEvent[];
}

function EventRow({
  index,
  style,
  events,
}: {
  ariaAttributes: { 'aria-posinset': number; 'aria-setsize': number; role: 'listitem' };
  index: number;
  style: CSSProperties;
  events: readonly GovernanceEvent[];
}) {
  const event = events[index];
  if (!event) return null;

  const verdictColor = VERDICT_COLORS[event.verdict];
  const ts = formatTimestamp(event.timestamp);
  const reason = truncate(event.reason || '—', 80);

  return (
    <div style={{ ...style, ...rowStyles.row }} role="row">
      <span style={rowStyles.timestamp}>{ts}</span>
      <span style={rowStyles.tool} title={event.tool}>{event.tool}</span>
      <span
        style={{ ...rowStyles.badge, backgroundColor: verdictColor }}
        title={event.verdict}
      >
        {event.verdict}
      </span>
      <span style={rowStyles.reason} title={event.reason}>{reason}</span>
    </div>
  );
}

export function EventStream() {
  const events = useGovernanceStore((s) => s.events);
  const listRef = useListRef(null);
  const [paused, setPaused] = useState(false);
  const pausedRef = useRef(false);
  pausedRef.current = paused;

  const scrollToBottom = useCallback(() => {
    if (!pausedRef.current && listRef.current && events.length > 0) {
      listRef.current.scrollToRow({ index: events.length - 1, align: 'end' });
    }
  }, [events.length, listRef]);

  useEffect(() => {
    scrollToBottom();
  }, [scrollToBottom]);

  function handleRowsRendered({ stopIndex }: { startIndex: number; stopIndex: number }) {
    if (stopIndex >= events.length - 1 && pausedRef.current) {
      setPaused(false);
    }
  }

  function resumeScroll() {
    setPaused(false);
    if (listRef.current && events.length > 0) {
      listRef.current.scrollToRow({ index: events.length - 1, align: 'end' });
    }
  }

  const isEmpty = events.length === 0;

  return (
    <div style={styles.container} role="region" aria-label="Live event stream">
      <div style={styles.header}>
        <span style={styles.title}>Live Events</span>
        <span style={styles.count}>{events.length} / 1000</span>
        {paused && (
          <button
            style={styles.resumeBtn}
            onClick={resumeScroll}
            aria-label="Resume auto-scroll to newest events"
          >
            Resume scroll
          </button>
        )}
      </div>

      {isEmpty ? (
        <div style={styles.empty} role="status">
          No events yet
        </div>
      ) : (
        <div style={styles.tableWrapper}>
          <div style={styles.columnHeader} role="row" aria-hidden="true">
            <span style={rowStyles.timestamp}>Time</span>
            <span style={rowStyles.tool}>Tool</span>
            <span style={{ ...rowStyles.badge, backgroundColor: 'transparent', color: '#57606a', fontSize: '11px' }}>Verdict</span>
            <span style={rowStyles.reason}>Reason</span>
          </div>
          <List<RowProps>
            listRef={listRef}
            style={styles.list}
            rowHeight={ROW_HEIGHT}
            rowCount={events.length}
            rowComponent={EventRow}
            rowProps={{ events }}
            onRowsRendered={handleRowsRendered}
            defaultHeight={LIST_HEIGHT}
            role="grid"
            aria-label="Governance events"
            aria-rowcount={events.length}
          />
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
    border: '1px solid #21262d',
    borderRadius: '6px',
    overflow: 'hidden',
    flex: 1,
    minHeight: 0,
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
  count: {
    color: '#57606a',
    fontSize: '11px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    marginLeft: 'auto',
  },
  resumeBtn: {
    background: '#21262d',
    border: '1px solid #30363d',
    borderRadius: '4px',
    color: '#e6edf3',
    cursor: 'pointer',
    fontSize: '11px',
    padding: '2px 8px',
  },
  empty: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flex: 1,
    color: '#57606a',
    fontSize: '13px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    minHeight: '200px',
  },
  tableWrapper: {
    display: 'flex',
    flexDirection: 'column' as const,
    flex: 1,
    minHeight: 0,
  },
  columnHeader: {
    display: 'flex',
    alignItems: 'center',
    padding: '0 8px',
    gap: '8px',
    height: '28px',
    background: '#161b22',
    borderBottom: '1px solid #21262d',
    flexShrink: 0,
  },
  list: {
    overflowX: 'hidden' as const,
  },
} as const;

const rowStyles = {
  row: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '0 8px',
    borderBottom: '1px solid #21262d',
    boxSizing: 'border-box' as const,
    background: '#0d1117',
  },
  timestamp: {
    color: '#57606a',
    fontSize: '11px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    flexShrink: 0,
    width: '90px',
  },
  tool: {
    color: '#e6edf3',
    fontSize: '12px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    flexShrink: 0,
    width: '120px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap' as const,
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
    padding: '1px 6px',
    flexShrink: 0,
    minWidth: '80px',
    textAlign: 'center' as const,
    letterSpacing: '0.03em',
  },
  reason: {
    color: '#8b949e',
    fontSize: '11px',
    fontFamily: 'ui-sans-serif, system-ui, sans-serif',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap' as const,
    flex: 1,
  },
} as const;
