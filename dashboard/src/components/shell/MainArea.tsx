import { useState } from 'react';
import { EventStreamList } from '../governance/EventStreamList';
import { GovernanceDAG } from '../governance/dag/GovernanceDAG';
import { AuditIndicator, AuditAlarmBanner } from '../governance/AuditIndicator';
import { AuditModal } from '../governance/AuditModal';
import { PolicyPlayground } from './PolicyPlayground';
import { ThreatFeed } from '../governance/ThreatFeed';
import { AgentsPanel } from '../governance/AgentsPanel';
import { LatticeHasseDiagram } from '../governance/LatticeHasseDiagram';
import { useThreatStore } from '../../stores/threat-store';

export type MainTab = 'dag' | 'playground' | 'agents' | 'threats' | 'lattice';

const TAB_LABELS: Record<MainTab, string> = {
  dag: 'DAG',
  playground: 'Playground',
  agents: 'Agents',
  threats: 'Threats',
  lattice: 'IFC Lattice',
};

// Shared ref so App.tsx's navigate handler can switch tabs without prop-drilling
export const activeTabRef = { current: 'dag' as MainTab, setTab: (_t: MainTab) => {} };

export function MainArea() {
  const [activeTab, setActiveTab] = useState<MainTab>('dag');
  activeTabRef.current = activeTab;
  activeTabRef.setTab = setActiveTab;

  const unacknowledgedCount = useThreatStore((s) => s.unacknowledgedCount);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Event stream: takes 50% of height */}
      <div style={{ flex: '0 0 50%', overflow: 'hidden', borderBottom: '1px solid var(--border)' }}>
        <EventStreamList />
      </div>

      {/* Tab bar */}
      <div style={{
        display: 'flex', alignItems: 'center',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-surface)',
        padding: '0 12px', height: 36, flexShrink: 0,
      }}>
        {(['dag', 'playground', 'agents', 'threats', 'lattice'] as const).map(tab => (
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
        {activeTab === 'playground' && <PolicyPlayground />}
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
