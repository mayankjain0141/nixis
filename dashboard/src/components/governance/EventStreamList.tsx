import { useEffect, useState, useCallback } from 'react';
import type { CSSProperties } from 'react';
import { List, useListRef } from 'react-window';
import type { RowComponentProps } from 'react-window';
import { useGovernanceStore, type GovernanceEvent } from '../../stores/governance-store';
import { useUIStore } from '../../stores/ui-store';

const VERDICT_STYLE: Record<string, { bg: string; color: string; label: string }> = {
  deny:             { bg: 'var(--deny)',         color: '#fff',     label: 'DENY' },
  allow:            { bg: 'var(--allow)',         color: '#fff',     label: 'ALLOW' },
  require_approval: { bg: 'var(--escalate)',      color: '#1a1a1a', label: 'APPR' },
  audit:            { bg: 'var(--audit-purple)',  color: '#fff',     label: 'AUDIT' },
  fail_open:        { bg: '#d29922',              color: '#1a1a1a', label: 'OPEN' },
};

function formatLatency(ns: number): string {
  if (ns >= 1_000_000) return `${(ns / 1_000_000).toFixed(1)}ms`;
  if (ns >= 1_000)     return `${(ns / 1_000).toFixed(0)}μs`;
  return `${ns}ns`;
}

function formatAgo(ts: number): string {
  const sec = Math.floor((Date.now() - ts / 1_000_000) / 1000);
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m`;
}

interface RowData {
  filtered: GovernanceEvent[];
  inspectorTarget: string | null;
  openInspector: (id: string) => void;
}

type EventRowProps = RowComponentProps<RowData>;

function EventRow({ ariaAttributes, index, style, filtered, inspectorTarget, openInspector }: EventRowProps) {
  const event = filtered[index];
  if (!event) return null;

  const verdictStyle = VERDICT_STYLE[event.verdict] ?? { bg: '#6e7681', color: '#fff', label: event.verdict.toUpperCase() };
  const isSelected = event.id === inspectorTarget;
  const requestArgs = event.requestArgs;
  const hasArgs = Boolean(requestArgs);

  return (
    <div {...ariaAttributes} style={style}>
      <div
        data-verdict={event.verdict}
        onClick={() => openInspector(event.id)}
        style={{
          display: 'flex',
          alignItems: 'center',
          minHeight: hasArgs ? 52 : 36,
          borderBottom: '1px solid #21262d',
          borderLeft: isSelected ? '2px solid var(--info-blue, #58a6ff)' : '2px solid transparent',
          background: isSelected ? '#1f2937' : undefined,
          padding: '0 8px',
          gap: 8,
          cursor: 'pointer',
          boxSizing: 'border-box',
        }}
        onMouseEnter={(e) => {
          if (!isSelected) (e.currentTarget as HTMLDivElement).style.background = '#161b22';
        }}
        onMouseLeave={(e) => {
          if (!isSelected) (e.currentTarget as HTMLDivElement).style.background = '';
        }}
      >
        {/* Verdict badge */}
        <div
          onClick={(e) => {
            e.stopPropagation();
            useGovernanceStore.getState().setFilterVerdict(event.verdict);
          }}
          style={{
            width: 52,
            flexShrink: 0,
            background: verdictStyle.bg,
            color: verdictStyle.color,
            borderRadius: 4,
            fontSize: 10,
            fontWeight: 700,
            textAlign: 'center',
            padding: '2px 0',
            letterSpacing: '0.04em',
            alignSelf: 'center',
            cursor: 'pointer',
          }}
        >
          {verdictStyle.label}
        </div>

        {/* Tool + command stacked */}
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2 }}>
          <div style={{
            fontFamily: 'monospace', fontSize: 12, color: '#e6edf3',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            {event.tool}
          </div>
          {hasArgs && (
            <div style={{
              fontFamily: 'monospace', fontSize: 11,
              color: event.verdict === 'deny' ? 'var(--deny, #cf222e)' : '#8b949e',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
              {requestArgs}
            </div>
          )}
        </div>

        {/* Session (last 8 chars) */}
        <div style={{
          width: 72,
          flexShrink: 0,
          fontFamily: 'monospace',
          fontSize: 11,
          color: '#8b949e',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          alignSelf: 'center',
        }}>
          {event.sessionId.slice(-8)}
        </div>

        {/* Policy */}
        <div style={{
          width: 120,
          flexShrink: 0,
          fontSize: 11,
          color: '#8b949e',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          alignSelf: 'center',
        }}>
          {(event.policyId ?? '').replace(/^aegis\/|^gatekeeper\/|^falco\/|^kyverno\/|^agentwall\/|^sigma\/|^catalog\//, '')}
        </div>

        {/* Latency */}
        <div style={{
          width: 60,
          flexShrink: 0,
          fontSize: 11,
          color: '#8b949e',
          textAlign: 'right',
        }}>
          {formatLatency(event.latencyNs)}
        </div>

        {/* Time */}
        <div style={{
          width: 48,
          flexShrink: 0,
          fontSize: 11,
          color: '#8b949e',
          textAlign: 'right',
        }}>
          {formatAgo(event.timestamp)}
        </div>
      </div>
    </div>
  );
}

export function EventStreamList() {
  const events = useGovernanceStore((s) => s.events);
  const filterVerdict = useGovernanceStore((s) => s.filterVerdict);
  const filterSession = useGovernanceStore((s) => s.filterSession);
  const filterPolicy = useGovernanceStore((s) => s.filterPolicy);
  const inspectorTarget = useUIStore((s) => s.inspectorTarget);
  const openInspector = useUIStore((s) => s.openInspector);
  const isPaused = useUIStore((s) => s.isPaused);
  const togglePause = useUIStore((s) => s.togglePause);

  const listRef = useListRef(null);
  const isUserScrolledRef = { current: false };
  const [showNewBadge, setShowNewBadge] = useState(false);

  let filtered = filterVerdict ? events.filter(e => e.verdict === filterVerdict) : [...events];
  if (filterSession) filtered = filtered.filter(e => e.sessionId === filterSession);
  if (filterPolicy) filtered = filtered.filter(e => e.policyId === filterPolicy);

  const getRowHeight = (index: number, _rowProps: RowData): number =>
    (filtered[index]?.requestArgs ? 52 : 36);

  useEffect(() => {
    if (isPaused) {
      setShowNewBadge(true);
      return;
    }
    if (!isUserScrolledRef.current) {
      listRef.current?.scrollToRow({ index: filtered.length - 1, align: 'end' });
      setShowNewBadge(false);
    } else {
      setShowNewBadge(true);
    }
  }, [filtered.length, isPaused]);

  const scrollToBottom = useCallback(() => {
    isUserScrolledRef.current = false;
    setShowNewBadge(false);
    listRef.current?.scrollToRow({ index: filtered.length - 1, align: 'end' });
  }, [filtered.length]);

  useEffect(() => {
    function handleScrollToBottom() {
      isUserScrolledRef.current = false;
      setShowNewBadge(false);
      listRef.current?.scrollToRow({ index: filtered.length - 1, align: 'end' });
    }
    window.addEventListener('aegis:scroll-to-bottom', handleScrollToBottom);
    return () => window.removeEventListener('aegis:scroll-to-bottom', handleScrollToBottom);
  }, [filtered.length]);

  if (filtered.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#8b949e', fontSize: 13 }}>
        Waiting for events…
      </div>
    );
  }

  const rowData: RowData = { filtered, inspectorTarget, openInspector };

  const listStyle: CSSProperties = { flex: 1, background: '#0d1117' };

  return (
    <div aria-label="Live event stream" style={{ position: 'relative', height: '100%', display: 'flex', flexDirection: 'column' }}>
      {filterVerdict && (
        <div style={{
          padding: '4px 12px', background: 'rgba(88,166,255,0.1)',
          borderBottom: '1px solid rgba(88,166,255,0.2)',
          fontSize: 11, color: 'var(--info-blue)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span>Filtering: {filterVerdict.toUpperCase()} — {filtered.length} events</span>
          <button
            onClick={() => useGovernanceStore.getState().setFilterVerdict(null)}
            style={{ background: 'none', border: 'none', color: 'var(--info-blue)', cursor: 'pointer', fontSize: 11 }}
          >
            ✕ clear
          </button>
        </div>
      )}
      {filterSession && (
        <div style={{
          padding: '4px 12px', background: 'rgba(88,166,255,0.1)',
          borderBottom: '1px solid rgba(88,166,255,0.2)',
          fontSize: 11, color: 'var(--info-blue)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span>Session: …{filterSession.slice(-8)} — {filtered.length} events</span>
          <button
            onClick={() => useGovernanceStore.getState().setFilterSession(null)}
            style={{ background: 'none', border: 'none', color: 'var(--info-blue)', cursor: 'pointer', fontSize: 11 }}
          >
            ✕ clear
          </button>
        </div>
      )}
      {filterPolicy && (
        <div style={{
          padding: '4px 12px', background: 'rgba(88,166,255,0.1)',
          borderBottom: '1px solid rgba(88,166,255,0.2)',
          fontSize: 11, color: 'var(--info-blue)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span>Policy: {filterPolicy.replace(/^aegis\/|^gatekeeper\/|^falco\/|^kyverno\/|^agentwall\/|^sigma\/|^catalog\//, '')} — {filtered.length} events</span>
          <button
            onClick={() => useGovernanceStore.getState().setFilterPolicy(null)}
            style={{ background: 'none', border: 'none', color: 'var(--info-blue)', cursor: 'pointer', fontSize: 11 }}
          >
            ✕ clear
          </button>
        </div>
      )}
      {isPaused && (
        <div style={{
          padding: '4px 12px',
          background: 'rgba(210,153,34,0.12)',
          borderBottom: '1px solid rgba(210,153,34,0.3)',
          fontSize: 11,
          color: 'var(--escalate, #d29922)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <span>&#9208; Paused — new events buffering</span>
          <button
            onClick={() => togglePause()}
            style={{ background: 'none', border: 'none', color: 'var(--escalate, #d29922)', cursor: 'pointer', fontSize: 11, fontWeight: 600 }}
          >
            &#9654; Resume
          </button>
        </div>
      )}
      <List
        listRef={listRef}
        rowComponent={EventRow}
        rowCount={filtered.length}
        rowHeight={getRowHeight}
        rowProps={rowData}
        overscanCount={5}
        style={listStyle}
        onRowsRendered={(visibleRows) => {
          const atBottom = visibleRows.stopIndex >= filtered.length - 2;
          if (atBottom) {
            isUserScrolledRef.current = false;
            setShowNewBadge(false);
          } else {
            isUserScrolledRef.current = true;
          }
        }}
      />

      {showNewBadge && (
        <div
          onClick={scrollToBottom}
          style={{
            position: 'absolute',
            bottom: 8,
            left: '50%',
            transform: 'translateX(-50%)',
            background: '#58a6ff',
            color: '#0d1117',
            borderRadius: 12,
            padding: '4px 12px',
            fontSize: 12,
            cursor: 'pointer',
            fontWeight: 600,
            animation: 'pulse 1.5s ease-in-out infinite',
            userSelect: 'none',
          }}
        >
          ↓ New events
        </div>
      )}
    </div>
  );
}
