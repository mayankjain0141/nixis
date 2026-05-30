import { useState } from 'react';
import { EventStreamList } from '../governance/EventStreamList';
import { GovernanceDAG } from '../governance/dag/GovernanceDAG';
import { DelegationTree } from '../governance/DelegationTree';
import { AuditHashChain } from '../governance/AuditHashChain';
import { PolicyPlayground } from './PolicyPlayground';
import { LatticeHasseDiagram } from '../governance/LatticeHasseDiagram';

export type MainTab = 'dag' | 'playground' | 'audit' | 'delegation' | 'lattice';

// Shared ref so App.tsx's navigate handler can switch tabs without prop-drilling
export const activeTabRef = { current: 'dag' as MainTab, setTab: (_t: MainTab) => {} };

export function MainArea() {
  const [activeTab, setActiveTab] = useState<MainTab>('dag');
  activeTabRef.current = activeTab;
  activeTabRef.setTab = setActiveTab;

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
        {(['dag', 'playground', 'audit', 'delegation', 'lattice'] as const).map(tab => (
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
            {tab === 'dag' ? 'DAG' : tab === 'playground' ? 'Playground' : tab === 'audit' ? 'Audit Chain' : tab === 'delegation' ? 'Delegation' : 'IFC Lattice'}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ flex: 1, overflow: 'auto', padding: 12 }}>
        {activeTab === 'dag'        && <GovernanceDAG />}
        {activeTab === 'playground' && <PolicyPlayground />}
        {activeTab === 'audit'      && <AuditHashChain />}
        {activeTab === 'delegation' && <DelegationTree />}
        {activeTab === 'lattice'    && (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 16 }}>
            <LatticeHasseDiagram />
          </div>
        )}
      </div>
    </div>
  );
}
