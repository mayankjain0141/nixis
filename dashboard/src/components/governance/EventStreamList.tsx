import { useRef, useEffect, useState, useCallback } from 'react';
import { useGovernanceStore } from '../../stores/governance-store';
import { useUIStore } from '../../stores/ui-store';

const MAX_VISIBLE = 25;

const VERDICT_STYLE: Record<string, { bg: string; color: string; label: string }> = {
  deny:             { bg: 'var(--deny)',         color: '#fff',     label: 'DENY' },
  allow:            { bg: 'var(--allow)',         color: '#fff',     label: 'ALLOW' },
  require_approval: { bg: 'var(--escalate)',      color: '#1a1a1a', label: 'APPR' },
  audit:            { bg: 'var(--audit-purple)',  color: '#fff',     label: 'AUDIT' },
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

export function EventStreamList() {
  const events = useGovernanceStore((s) => s.events);
  const filterVerdict = useGovernanceStore((s) => s.filterVerdict);
  const inspectorTarget = useUIStore((s) => s.inspectorTarget);
  const openInspector = useUIStore((s) => s.openInspector);

  const containerRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const isUserScrolled = useRef(false);
  const [showNewBadge, setShowNewBadge] = useState(false);

  const filtered = filterVerdict ? events.filter(e => e.verdict === filterVerdict) : events;
  const visible = filtered.slice(-MAX_VISIBLE);

  const handleScroll = useCallback(() => {
    const el = containerRef.current;
    if (!el) return;
    const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 20;
    if (atBottom) {
      isUserScrolled.current = false;
      setShowNewBadge(false);
    } else {
      isUserScrolled.current = true;
    }
  }, []);

  useEffect(() => {
    if (!isUserScrolled.current) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
      setShowNewBadge(false);
    } else {
      setShowNewBadge(true);
    }
  }, [events]);

  const scrollToBottom = useCallback(() => {
    isUserScrolled.current = false;
    setShowNewBadge(false);
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  if (visible.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#8b949e', fontSize: 13 }}>
        Waiting for events…
      </div>
    );
  }

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
      <div
        ref={containerRef}
        onScroll={handleScroll}
        style={{
          flex: 1,
          overflowY: 'auto',
          background: '#0d1117',
        }}
      >
        {visible.map((event) => {
          const verdictStyle = VERDICT_STYLE[event.verdict] ?? { bg: '#6e7681', color: '#fff', label: event.verdict.toUpperCase() };
          const isSelected = event.id === inspectorTarget;

          const requestArgs = event.requestArgs;
          const hasArgs = Boolean(requestArgs);

          return (
            <div
              key={event.id}
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
              <div style={{
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
              }}>
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
          );
        })}
        <div ref={bottomRef} />
      </div>

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
