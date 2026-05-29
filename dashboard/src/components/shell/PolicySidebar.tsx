import React, { useMemo } from 'react';
import { usePolicyStore } from '../../stores/policy-store';
import { useLatticeStore } from '../../stores/lattice-store';
import { useGovernanceStore } from '../../stores/governance-store';
import { confidentialityToLevel } from '../../lib/label-display';
import type { LabelState } from '../../types/events';

const MAX_SESSIONS_DISPLAY = 10;

function ifcBadge(confidentiality: number): { label: string; color: string } {
  const level = confidentialityToLevel(confidentiality);
  switch (level) {
    case 'Restricted':    return { label: 'RES', color: '#cf222e' };
    case 'Confidential':  return { label: 'CON', color: '#d29922' };
    case 'Internal':      return { label: 'INT', color: '#58a6ff' };
    default:              return { label: 'UNC', color: '#2da44e' };
  }
}

function labelStateDotColor(state: LabelState): string {
  switch (state) {
    case 'escalated':         return '#d29922';
    case 'tainted_by_secret': return '#cf222e';
    default:                  return '#2da44e';
  }
}

interface SessionRow {
  sessionId: string;
  confidentiality: number;
  state: LabelState;
}

export function PolicySidebar(): React.ReactElement {
  const policies = usePolicyStore((s) => s.policies);
  const selectedPolicyId = usePolicyStore((s) => s.selectedPolicyId);
  const selectPolicy = usePolicyStore((s) => s.selectPolicy);

  const latticeNodes = useLatticeStore((s) => s.nodes);
  const sessionLabels = useGovernanceStore((s) => s.sessionLabels);

  const selectedPolicy = useMemo(
    () => policies.find((p) => p.id === selectedPolicyId) ?? null,
    [policies, selectedPolicyId],
  );

  const sessions: SessionRow[] = useMemo(() => {
    const merged = new Map<string, SessionRow>();

    for (const [id, entry] of sessionLabels) {
      merged.set(id, {
        sessionId: id,
        confidentiality: entry.label.confidentiality,
        state: entry.state,
      });
    }

    for (const [id, node] of latticeNodes) {
      merged.set(id, {
        sessionId: id,
        confidentiality: node.label.confidentiality,
        state: node.state,
      });
    }

    return Array.from(merged.values());
  }, [latticeNodes, sessionLabels]);

  const visibleSessions = sessions.slice(0, MAX_SESSIONS_DISPLAY);
  const overflowCount = sessions.length - visibleSessions.length;

  function shortSessionId(id: string): string {
    return id.length > 12 ? id.slice(0, 8) + '…' : id;
  }

  function stripPrefix(name: string): string {
    return name.startsWith('aegis/') ? name.slice(6) : name;
  }

  return (
    <div style={{ background: '#0d1117', overflowY: 'auto', height: '100%' }}>
      {/* POLICIES section */}
      <div
        style={{
          padding: '10px 12px 6px',
          fontSize: '11px',
          fontWeight: 600,
          color: '#8b949e',
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <span>Policies</span>
        <span
          style={{
            background: '#21262d',
            color: '#8b949e',
            borderRadius: '10px',
            padding: '1px 7px',
            fontSize: '11px',
          }}
        >
          {policies.length}
        </span>
      </div>

      {policies.map((policy) => {
        const isSelected = policy.id === selectedPolicyId;
        return (
          <div key={policy.id}>
            <div
              onClick={() => selectPolicy(isSelected ? null : policy.id)}
              style={{
                padding: '7px 12px',
                cursor: 'pointer',
                fontSize: '13px',
                color: '#e6edf3',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                background: isSelected ? '#1f2937' : 'transparent',
                borderLeft: isSelected ? '2px solid #58a6ff' : '2px solid transparent',
              }}
            >
              <span
                style={{
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  background: policy.enabled ? '#2da44e' : '#484f58',
                  flexShrink: 0,
                }}
              />
              <span>{stripPrefix(policy.name)}</span>
            </div>

            {isSelected && (
              <div
                style={{
                  margin: '0 12px 8px',
                  border: '1px solid #30363d',
                  borderRadius: '4px',
                  padding: '8px',
                  fontSize: '12px',
                  color: '#e6edf3',
                }}
              >
                {selectedPolicy?.layer === 'cel' ? (
                  <>
                    <div style={{ marginBottom: '6px', color: '#8b949e', fontSize: '11px' }}>
                      CEL Expression
                    </div>
                    <div
                      style={{
                        background: '#0d1117',
                        border: '1px solid #30363d',
                        borderRadius: '4px',
                        padding: '8px',
                        fontFamily: 'monospace',
                        fontSize: '11px',
                        color: '#79c0ff',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                        maxHeight: '80px',
                        overflowY: 'auto',
                      }}
                    >
                      {`tool == "${stripPrefix(policy.name)}" &&\nrequest.args != null`}
                    </div>
                  </>
                ) : (
                  <div style={{ color: '#8b949e', fontSize: '11px' }}>
                    No CEL expression for this layer.
                  </div>
                )}
                <div
                  style={{
                    marginTop: '8px',
                    fontSize: '11px',
                    color: '#8b949e',
                    display: 'flex',
                    gap: '12px',
                  }}
                >
                  <span>
                    Layer: <span style={{ color: '#e6edf3' }}>{policy.layer}</span>
                  </span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    Status:
                    <span
                      style={{
                        width: '6px',
                        height: '6px',
                        borderRadius: '50%',
                        background: policy.enabled ? '#2da44e' : '#484f58',
                        display: 'inline-block',
                      }}
                    />
                    <span style={{ color: '#e6edf3' }}>
                      {policy.enabled ? 'active' : 'disabled'}
                    </span>
                  </span>
                </div>
              </div>
            )}
          </div>
        );
      })}

      {policies.length === 0 && (
        <div style={{ padding: '7px 12px', fontSize: '12px', color: '#484f58' }}>
          No policies loaded.
        </div>
      )}

      {selectedPolicyId === null && policies.length > 0 && (
        <div style={{ padding: '6px 12px 4px', fontSize: '11px', color: '#484f58' }}>
          Select a policy to view details
        </div>
      )}

      <div style={{ borderTop: '1px solid #21262d', margin: '4px 0' }} />

      {/* SESSIONS section */}
      <div
        style={{
          padding: '10px 12px 6px',
          fontSize: '11px',
          fontWeight: 600,
          color: '#8b949e',
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <span>Sessions</span>
        <span
          style={{
            background: '#21262d',
            color: '#8b949e',
            borderRadius: '10px',
            padding: '1px 7px',
            fontSize: '11px',
          }}
        >
          {sessions.length}
        </span>
      </div>

      {visibleSessions.map((session) => {
        const badge = ifcBadge(session.confidentiality);
        const dotColor = labelStateDotColor(session.state);
        return (
          <div
            key={session.sessionId}
            style={{
              padding: '7px 12px',
              fontSize: '13px',
              color: '#e6edf3',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
            }}
          >
            <span
              style={{
                background: badge.color,
                color: '#ffffff',
                borderRadius: '10px',
                padding: '1px 6px',
                fontSize: '10px',
                fontWeight: 600,
                flexShrink: 0,
              }}
            >
              {badge.label}
            </span>
            <span style={{ fontFamily: 'monospace', fontSize: '12px', color: '#8b949e' }}>
              {shortSessionId(session.sessionId)}
            </span>
            <span style={{ color: '#484f58', fontSize: '12px' }}>—</span>
            <span
              style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                background: dotColor,
                flexShrink: 0,
              }}
            />
            <span style={{ fontSize: '11px', color: '#8b949e' }}>{session.state}</span>
          </div>
        );
      })}

      {overflowCount > 0 && (
        <div style={{ padding: '4px 12px 8px', fontSize: '11px', color: '#484f58' }}>
          and {overflowCount} more…
        </div>
      )}

      {sessions.length === 0 && (
        <div style={{ padding: '7px 12px', fontSize: '12px', color: '#484f58' }}>
          No active sessions.
        </div>
      )}
    </div>
  );
}
