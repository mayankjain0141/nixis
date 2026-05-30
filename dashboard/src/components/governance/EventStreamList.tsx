import { useEffect, useRef, useState, useCallback } from 'react';
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

function EventRow({ event, isSelected, openInspector }: {
  event: GovernanceEvent;
  isSelected: boolean;
  openInspector: (id: string) => void;
}) {
  const verdictStyle = VERDICT_STYLE[event.verdict] ?? { bg: '#6e7681', color: '#fff', label: event.verdict.toUpperCase() };
  const requestArgs = event.requestArgs;
  const hasArgs = Boolean(requestArgs);

  return (
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
        flexShrink: 0,
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
      <div style={{ width: 72, flexShrink: 0, fontFamily: 'monospace', fontSize: 11, color: '#8b949e', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', alignSelf: 'center' }}>
        {event.sessionId.slice(-8)}
      </div>

      {/* Policy */}
      <div style={{ width: 120, flexShrink: 0, fontSize: 11, color: '#8b949e', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', alignSelf: 'center' }}>
        {(event.policyId ?? '').replace(/^nixis\/|^gatekeeper\/|^falco\/|^kyverno\/|^agentwall\/|^sigma\/|^catalog\//, '')}
      </div>

      {/* Latency */}
      <div style={{ width: 60, flexShrink: 0, fontSize: 11, color: '#8b949e', textAlign: 'right' }}>
        {formatLatency(event.latencyNs)}
      </div>

      {/* Time */}
      <div style={{ width: 48, flexShrink: 0, fontSize: 11, color: '#8b949e', textAlign: 'right' }}>
        {formatAgo(event.timestamp)}
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

  const scrollRef = useRef<HTMLDivElement>(null);
  const isUserScrolledRef = useRef(false);
  const [showNewBadge, setShowNewBadge] = useState(false);

  let filtered = filterVerdict ? events.filter(e => e.verdict === filterVerdict) : [...events];
  if (filterSession) filtered = filtered.filter(e => e.sessionId === filterSession);
  if (filterPolicy) filtered = filtered.filter(e => e.policyId === filterPolicy);

  const scrollToBottom = useCallback(() => {
    isUserScrolledRef.current = false;
    setShowNewBadge(false);
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, []);

  // Auto-scroll to bottom when new events arrive (unless user scrolled up or paused)
  useEffect(() => {
    if (isPaused) { setShowNewBadge(true); return; }
    if (!isUserScrolledRef.current) {
      scrollToBottom();
    } else {
      setShowNewBadge(true);
    }
  }, [filtered.length, isPaused, scrollToBottom]);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    function onScroll() {
      if (!el) return;
      const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
      if (atBottom) {
        isUserScrolledRef.current = false;
        setShowNewBadge(false);
      } else {
        isUserScrolledRef.current = true;
      }
    }
    el.addEventListener('scroll', onScroll, { passive: true });
    return () => el.removeEventListener('scroll', onScroll);
  }, []);

  useEffect(() => {
    function handleScrollToBottom() { scrollToBottom(); }
    window.addEventListener('nixis:scroll-to-bottom', handleScrollToBottom);
    return () => window.removeEventListener('nixis:scroll-to-bottom', handleScrollToBottom);
  }, [scrollToBottom]);

  if (filtered.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#8b949e', fontSize: 13 }}>
        Waiting for events…
      </div>
    );
  }

  return (
    <div aria-label="Live event stream" style={{ position: 'relative', height: '100%', display: 'flex', flexDirection: 'column' }}>
      {filterVerdict && (
        <div style={{ padding: '4px 12px', background: 'rgba(88,166,255,0.1)', borderBottom: '1px solid rgba(88,166,255,0.2)', fontSize: 11, color: 'var(--info-blue)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span>Filtering: {filterVerdict.toUpperCase()} — {filtered.length} events</span>
          <button onClick={() => useGovernanceStore.getState().setFilterVerdict(null)} style={{ background: 'none', border: 'none', color: 'var(--info-blue)', cursor: 'pointer', fontSize: 11 }}>✕ clear</button>
        </div>
      )}
      {filterSession && (
        <div style={{ padding: '4px 12px', background: 'rgba(88,166,255,0.1)', borderBottom: '1px solid rgba(88,166,255,0.2)', fontSize: 11, color: 'var(--info-blue)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span>Session: …{filterSession.slice(-8)} — {filtered.length} events</span>
          <button onClick={() => useGovernanceStore.getState().setFilterSession(null)} style={{ background: 'none', border: 'none', color: 'var(--info-blue)', cursor: 'pointer', fontSize: 11 }}>✕ clear</button>
        </div>
      )}
      {filterPolicy && (
        <div style={{ padding: '4px 12px', background: 'rgba(88,166,255,0.1)', borderBottom: '1px solid rgba(88,166,255,0.2)', fontSize: 11, color: 'var(--info-blue)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span>Policy: {filterPolicy.replace(/^nixis\/|^gatekeeper\/|^falco\/|^kyverno\/|^agentwall\/|^sigma\/|^catalog\//, '')} — {filtered.length} events</span>
          <button onClick={() => useGovernanceStore.getState().setFilterPolicy(null)} style={{ background: 'none', border: 'none', color: 'var(--info-blue)', cursor: 'pointer', fontSize: 11 }}>✕ clear</button>
        </div>
      )}
      {isPaused && (
        <div style={{ padding: '4px 12px', background: 'rgba(210,153,34,0.12)', borderBottom: '1px solid rgba(210,153,34,0.3)', fontSize: 11, color: 'var(--escalate, #d29922)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span>⏸ Paused — new events buffering</span>
          <button onClick={() => togglePause()} style={{ background: 'none', border: 'none', color: 'var(--escalate, #d29922)', cursor: 'pointer', fontSize: 11, fontWeight: 600 }}>▶ Resume</button>
        </div>
      )}

      <div
        ref={scrollRef}
        style={{ flex: 1, overflowY: 'auto', background: '#0d1117', display: 'flex', flexDirection: 'column' }}
      >
        {filtered.map((event) => (
          <EventRow
            key={event.id}
            event={event}
            isSelected={event.id === inspectorTarget}
            openInspector={openInspector}
          />
        ))}
      </div>

      {showNewBadge && (
        <div
          onClick={scrollToBottom}
          style={{ position: 'absolute', bottom: 8, left: '50%', transform: 'translateX(-50%)', background: '#58a6ff', color: '#0d1117', borderRadius: 12, padding: '4px 12px', fontSize: 12, cursor: 'pointer', fontWeight: 600, userSelect: 'none' }}
        >
          ↓ New events
        </div>
      )}
    </div>
  );
}
