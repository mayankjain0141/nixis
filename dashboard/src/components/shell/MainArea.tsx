import { useState, useRef, useEffect, useCallback } from 'react';
import { EventStreamList } from '../governance/EventStreamList';
import { GovernanceDAG } from '../governance/dag/GovernanceDAG';
import { AuditIndicator, AuditAlarmBanner } from '../governance/AuditIndicator';
import { AuditModal } from '../governance/AuditModal';
import { ThreatFeed } from '../governance/ThreatFeed';
import { AgentsPanel } from '../governance/AgentsPanel';
import { LatticeHasseDiagram } from '../governance/LatticeHasseDiagram';
import { useThreatStore } from '../../stores/threat-store';

export type MainTab = 'dag' | 'agents' | 'threats' | 'lattice';

const TAB_LABELS: Record<MainTab, string> = {
  dag: 'DAG',
  agents: 'Agents',
  threats: 'Threats',
  lattice: 'IFC Lattice',
};

// Shared ref so App.tsx's navigate handler can switch tabs without prop-drilling
export const activeTabRef = { current: 'dag' as MainTab, setTab: (_t: MainTab) => {} };

const MIN_STREAM_PX = 80;
const DEFAULT_STREAM_PCT = 50;

export function MainArea() {
  const [activeTab, setActiveTab] = useState<MainTab>('dag');
  activeTabRef.current = activeTab;
  activeTabRef.setTab = setActiveTab;

  const unacknowledgedCount = useThreatStore((s) => s.unacknowledgedCount);

  // Resizable stream divider
  const containerRef = useRef<HTMLDivElement>(null);
  const [streamPct, setStreamPct] = useState(DEFAULT_STREAM_PCT);
  const [collapsed, setCollapsed] = useState(false);
  const prevPctRef = useRef(DEFAULT_STREAM_PCT);
  const dragging = useRef(false);

  const onDragStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    dragging.current = true;
    const onMove = (mv: MouseEvent) => {
      if (!dragging.current || !containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const pct = ((mv.clientY - rect.top) / rect.height) * 100;
      const clamped = Math.max((MIN_STREAM_PX / rect.height) * 100, Math.min(85, pct));
      setStreamPct(clamped);
      prevPctRef.current = clamped;
      if (collapsed) setCollapsed(false);
    };
    const onUp = () => {
      dragging.current = false;
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  }, [collapsed]);

  const toggleCollapse = () => {
    if (collapsed) {
      setStreamPct(prevPctRef.current);
      setCollapsed(false);
    } else {
      prevPctRef.current = streamPct;
      setStreamPct(0);
      setCollapsed(true);
    }
  };

  // Keyboard shortcut: Cmd+Shift+S to toggle stream
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 'S') {
        e.preventDefault();
        toggleCollapse();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  });

  return (
    <div ref={containerRef} style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Event stream — resizable */}
      <div style={{
        flex: collapsed ? '0 0 0px' : `0 0 ${streamPct}%`,
        overflow: 'hidden',
        borderBottom: collapsed ? 'none' : '1px solid var(--border)',
        transition: dragging.current ? 'none' : 'flex 0.15s ease',
      }}>
        {!collapsed && <EventStreamList />}
      </div>

      {/* Drag handle + collapse toggle */}
      <div
        style={{
          height: 10, flexShrink: 0, cursor: 'row-resize',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'var(--bg-surface)',
          borderBottom: '1px solid var(--border)',
          position: 'relative',
        }}
        onMouseDown={onDragStart}
      >
        <div style={{ width: 32, height: 3, borderRadius: 2, background: 'var(--border)' }} />
        <button
          onClick={toggleCollapse}
          title={collapsed ? 'Expand stream (⌘⇧S)' : 'Collapse stream (⌘⇧S)'}
          style={{
            position: 'absolute', right: 8,
            background: 'none', border: 'none', cursor: 'pointer',
            fontSize: 10, color: 'var(--text-secondary)', padding: '0 4px',
            lineHeight: 1,
          }}
        >
          {collapsed ? '▼ stream' : '▲'}
        </button>
      </div>

      {/* Tab bar — Playground moved to end */}
      <div style={{
        display: 'flex', alignItems: 'center',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-surface)',
        padding: '0 12px', height: 36, flexShrink: 0,
      }}>
        {(['dag', 'agents', 'threats', 'lattice'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              padding: '0 14px', height: '100%', border: 'none', cursor: 'pointer',
              background: 'transparent', fontSize: 12, fontWeight: 500,
              color: activeTab === tab ? 'var(--text-primary)' : 'var(--text-secondary)',
              borderBottom: activeTab === tab ? '2px solid var(--info-blue)' : '2px solid transparent',
              textTransform: 'uppercase' as const, letterSpacing: '0.06em',
            }}
          >
            {tab === 'threats'
              ? <>
                  {TAB_LABELS[tab]}
                  {unacknowledgedCount > 0 && (
                    <span style={{ marginLeft: 4, color: 'var(--deny)' }}>
                      ●{unacknowledgedCount}
                    </span>
                  )}
                </>
              : TAB_LABELS[tab]
            }
          </button>
        ))}
        <AuditIndicator />
      </div>
      <AuditAlarmBanner />
      <AuditModal />

      {/* Tab content */}
      <div style={{ flex: 1, overflow: 'auto', padding: 12 }}>
        {activeTab === 'dag'        && <GovernanceDAG />}
        {activeTab === 'agents'     && <AgentsPanel />}
        {activeTab === 'threats'    && (
          <div style={{ padding: 16 }}>
            <ThreatFeed />
          </div>
        )}
        {activeTab === 'lattice'    && (
          <div style={{ display: 'flex', padding: 16 }}>
            <LatticeHasseDiagram />
          </div>
        )}
      </div>
    </div>
  );
}
