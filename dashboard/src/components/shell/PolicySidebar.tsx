import React, { useMemo, useState } from 'react';
import { usePolicyStore } from '../../stores/policy-store';

const SECTION_HEADER: React.CSSProperties = {
  padding: '10px 12px 6px',
  fontSize: '11px',
  fontWeight: 600,
  color: '#8b949e',
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
};

const COUNT_BADGE: React.CSSProperties = {
  background: '#21262d',
  color: '#8b949e',
  borderRadius: '10px',
  padding: '1px 7px',
  fontSize: '11px',
};

function stripPrefix(name: string): string {
  return name.startsWith('aegis/') ? name.slice(6) : name;
}

export function PolicySidebar(): React.ReactElement {
  const policies = usePolicyStore((s) => s.policies);
  const selectedPolicyId = usePolicyStore((s) => s.selectedPolicyId);
  const selectPolicy = usePolicyStore((s) => s.selectPolicy);
  const bundleStatus = usePolicyStore((s) => s.bundleStatus);

  const [filter, setFilter] = useState('');

  const selectedPolicy = useMemo(
    () => policies.find((p) => p.id === selectedPolicyId) ?? null,
    [policies, selectedPolicyId],
  );

  const visiblePolicies = useMemo(() => {
    if (!filter.trim()) return policies;
    const q = filter.toLowerCase();
    return policies.filter(p =>
      p.id.toLowerCase().includes(q) ||
      p.name.toLowerCase().includes(q) ||
      (p.celExpression ?? '').toLowerCase().includes(q),
    );
  }, [policies, filter]);

  return (
    <div style={{ background: '#0d1117', overflowY: 'auto', height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* POLICIES section */}
      <div style={SECTION_HEADER}>
        <span>Policies</span>
        <span style={COUNT_BADGE}>{filter ? `${visiblePolicies.length}/${policies.length}` : policies.length}</span>
      </div>

      <div style={{ padding: '0 12px 6px' }}>
        <input
          type="text"
          value={filter}
          onChange={e => setFilter(e.target.value)}
          placeholder="Filter policies…"
          style={{
            width: '100%', background: '#161b22', border: '1px solid #30363d',
            borderRadius: 4, padding: '4px 8px', color: '#e6edf3',
            fontSize: '12px', outline: 'none', boxSizing: 'border-box',
          }}
        />
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        {visiblePolicies.map((policy) => {
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

              {isSelected && selectedPolicy && (
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
                  {selectedPolicy.celExpression != null ? (
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
                        {selectedPolicy.celExpression}
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
                      Layer: <span style={{ color: '#e6edf3' }}>{selectedPolicy.layer}</span>
                    </span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                      Status:
                      <span
                        style={{
                          width: '6px',
                          height: '6px',
                          borderRadius: '50%',
                          background: selectedPolicy.enabled ? '#2da44e' : '#484f58',
                          display: 'inline-block',
                        }}
                      />
                      <span style={{ color: '#e6edf3' }}>
                        {selectedPolicy.enabled ? 'active' : 'disabled'}
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

        {filter && visiblePolicies.length === 0 && policies.length > 0 && (
          <div style={{ padding: '7px 12px', fontSize: '12px', color: '#484f58' }}>
            No policies match.
          </div>
        )}

        {selectedPolicyId === null && policies.length > 0 && !filter && (
          <div style={{ padding: '6px 12px 4px', fontSize: '11px', color: '#484f58' }}>
            Select a policy to view details
          </div>
        )}
      </div>

      {/* BUNDLE section — pinned to bottom */}
      <div>
        <div style={{ borderTop: '1px solid #21262d', margin: '4px 0' }} />
        <div style={SECTION_HEADER}>
          <span>Bundle</span>
          {bundleStatus && (
            <span style={COUNT_BADGE}>v{bundleStatus.version}</span>
          )}
        </div>

        {bundleStatus ? (
          <div
            style={{
              padding: '6px 12px 10px',
              fontSize: '11px',
              color: '#8b949e',
              display: 'flex',
              flexDirection: 'column',
              gap: '4px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Loaded</span>
              <span style={{ color: '#e6edf3' }}>{policies.length}</span>
            </div>
            {bundleStatus.policyCount > policies.length && (
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>On disk</span>
                <span style={{ color: '#8b949e' }}>{bundleStatus.policyCount}</span>
              </div>
            )}
            {bundleStatus.adapterCount > 0 && (
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Adapters</span>
                <span style={{ color: '#e6edf3' }}>{bundleStatus.adapterCount}</span>
              </div>
            )}
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Signature</span>
              <span style={{ color: bundleStatus.signatureVerified ? '#2da44e' : '#8b949e', fontWeight: 500 }}>
                {bundleStatus.signatureVerified ? '✓ verified' : 'unsigned'}
              </span>
            </div>
            {bundleStatus.hash && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>Hash</span>
                <span
                  style={{ color: '#e6edf3', fontFamily: 'monospace', fontSize: '10px' }}
                  title={bundleStatus.hash}
                >
                  {bundleStatus.hash.replace('sha256:', '').slice(0, 8)}…
                </span>
              </div>
            )}
          </div>
        ) : (
          <div style={{ padding: '6px 12px 10px', fontSize: '11px', color: '#484f58' }}>
            No bundle active.
          </div>
        )}
      </div>
    </div>
  );
}
