import React, { useMemo, useState } from 'react';
import { usePolicyStore } from '../../stores/policy-store';
import { useGovernanceStore } from '../../stores/governance-store';

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

type PolicySource = 'falco' | 'kyverno' | 'catalog' | 'nixis' | 'other';

function getPolicySource(id: string): PolicySource {
  if (id.startsWith('nixis/')) return 'nixis';
  if (id.startsWith('falco-')) return 'falco';
  if (id.startsWith('kyverno-')) return 'kyverno';
  if (id.startsWith('catalog-')) return 'catalog';
  return 'other';
}

function deduplicateSegments(text: string): string {
  const words = text.split(' ');
  const half = Math.floor(words.length / 2);
  if (half > 0) {
    const firstHalf = words.slice(0, half).join(' ');
    const secondHalf = words.slice(half).join(' ');
    if (firstHalf === secondHalf) return firstHalf;
  }
  return text;
}

function formatPolicyName(id: string): string {
  const source = getPolicySource(id);
  if (source === 'nixis') {
    return id.slice('nixis/'.length);
  }
  if (source === 'falco') {
    const stripped = id.slice('falco-'.length);
    return stripped.replace(/-/g, ' ').trim();
  }
  if (source === 'catalog') {
    const stripped = id.slice('catalog-auto-'.length);
    // `---` in the id represents ` --` (space + double-dash CLI flag)
    const withFlags = stripped.replace(/---/g, ' --');
    return withFlags.replace(/-/g, ' ').trim();
  }
  if (source === 'kyverno') {
    const stripped = id.slice('kyverno-'.length);
    const expanded = stripped.replace(/-/g, ' ').trim();
    return deduplicateSegments(expanded);
  }
  return id.replace(/[-/]/g, ' ').trim();
}

const SOURCE_BADGE_STYLES: Record<PolicySource, { bg: string; color: string; label: string }> = {
  falco:   { bg: '#0969da', color: '#cae8ff', label: 'F' },
  kyverno: { bg: '#953800', color: '#ffddb0', label: 'K' },
  catalog: { bg: '#1b6633', color: '#aff5b4', label: 'C' },
  nixis:   { bg: '#5a3e9c', color: '#e2ccff', label: 'A' },
  other:   { bg: '#30363d', color: '#8b949e', label: '?' },
};

function SourceBadge({ source }: { source: PolicySource }): React.ReactElement {
  const { bg, color, label } = SOURCE_BADGE_STYLES[source];
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: 14,
        height: 14,
        borderRadius: 3,
        background: bg,
        color,
        fontSize: 9,
        fontWeight: 700,
        flexShrink: 0,
        lineHeight: 1,
      }}
    >
      {label}
    </span>
  );
}

const SOURCE_ORDER: PolicySource[] = ['nixis', 'falco', 'kyverno', 'catalog', 'other'];

const SOURCE_DISPLAY_NAME: Record<PolicySource, string> = {
  nixis:   'Nixis',
  falco:   'Falco',
  kyverno: 'Kyverno',
  catalog: 'Catalog',
  other:   'Other',
};

interface PolicyItem {
  id: string;
  name: string;
  enabled: boolean;
  celExpression?: string | null;
  layer?: string;
}

function GroupDivider({ label, count }: { label: string; count: number }): React.ReactElement {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        padding: '8px 12px 4px',
        gap: 6,
      }}
    >
      <span style={{ flex: 1, height: 1, background: '#21262d' }} />
      <span
        style={{
          fontSize: 10,
          color: '#484f58',
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          whiteSpace: 'nowrap',
        }}
      >
        {label} ({count})
      </span>
      <span style={{ flex: 1, height: 1, background: '#21262d' }} />
    </div>
  );
}

function PolicyRow({
  policy,
  isSelected,
  selectedPolicy,
  onSelect,
  matchCount,
  filterPolicy,
  setFilterPolicy,
}: {
  policy: PolicyItem;
  isSelected: boolean;
  selectedPolicy: PolicyItem | null;
  onSelect: () => void;
  matchCount: number;
  filterPolicy: string | null;
  setFilterPolicy: (id: string | null) => void;
}): React.ReactElement {
  const source = getPolicySource(policy.id);
  const displayName = formatPolicyName(policy.id);
  const isFiltering = filterPolicy === policy.id;

  return (
    <div key={policy.id}>
      <div
        onClick={() => {
          const newId = isSelected ? null : policy.id;
          onSelect();
          setFilterPolicy(newId);
        }}
        style={{
          padding: '7px 12px',
          cursor: 'pointer',
          fontSize: '13px',
          color: '#e6edf3',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          background: isSelected ? '#1f2937' : 'transparent',
          borderLeft: isFiltering
            ? '2px solid #2da44e'
            : isSelected ? '2px solid #58a6ff' : '2px solid transparent',
        }}
      >
        <SourceBadge source={source} />
        <span
          style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            background: policy.enabled ? '#2da44e' : '#484f58',
            flexShrink: 0,
          }}
        />
        <span style={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
          {displayName}
        </span>
        {matchCount > 0 && (
          <span style={{
            background: '#21262d',
            borderRadius: 10,
            padding: '0 5px',
            fontSize: 10,
            color: 'var(--text-secondary)',
            marginLeft: 4,
            flexShrink: 0,
          }}>
            {matchCount}
          </span>
        )}
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
}

export function PolicySidebar(): React.ReactElement {
  const policies = usePolicyStore((s) => s.policies);
  const selectedPolicyId = usePolicyStore((s) => s.selectedPolicyId);
  const selectPolicy = usePolicyStore((s) => s.selectPolicy);
  const bundleStatus = usePolicyStore((s) => s.bundleStatus);

  const events = useGovernanceStore((s) => s.events);
  const filterPolicy = useGovernanceStore((s) => s.filterPolicy);
  const setFilterPolicy = useGovernanceStore((s) => s.setFilterPolicy);

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

  const groupedPolicies = useMemo(() => {
    const groups: Partial<Record<PolicySource, PolicyItem[]>> = {};
    for (const policy of visiblePolicies) {
      const src = getPolicySource(policy.id);
      if (!groups[src]) groups[src] = [];
      groups[src]!.push(policy);
    }
    return groups;
  }, [visiblePolicies]);

  const policyCounts = useMemo(() => {
    const m: Record<string, number> = {};
    for (const e of events) {
      if (e.policyId) m[e.policyId] = (m[e.policyId] ?? 0) + 1;
    }
    return m;
  }, [events]);

  const isFiltering = filter.trim().length > 0;

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
        {isFiltering ? (
          // Flat results with badges when filtering
          <>
            {visiblePolicies.map((policy) => {
              const isSelected = policy.id === selectedPolicyId;
              return (
                <PolicyRow
                  key={policy.id}
                  policy={policy}
                  isSelected={isSelected}
                  selectedPolicy={selectedPolicy}
                  onSelect={() => selectPolicy(isSelected ? null : policy.id)}
                  matchCount={policyCounts[policy.id] ?? 0}
                  filterPolicy={filterPolicy}
                  setFilterPolicy={setFilterPolicy}
                />
              );
            })}
            {visiblePolicies.length === 0 && policies.length > 0 && (
              <div style={{ padding: '7px 12px', fontSize: '12px', color: '#484f58' }}>
                No policies match.
              </div>
            )}
          </>
        ) : (
          // Grouped results when not filtering
          <>
            {SOURCE_ORDER.map((src) => {
              const group = groupedPolicies[src];
              if (!group || group.length === 0) return null;
              return (
                <React.Fragment key={src}>
                  <GroupDivider label={SOURCE_DISPLAY_NAME[src]} count={group.length} />
                  {group.map((policy) => {
                    const isSelected = policy.id === selectedPolicyId;
                    return (
                      <PolicyRow
                        key={policy.id}
                        policy={policy}
                        isSelected={isSelected}
                        selectedPolicy={selectedPolicy}
                        onSelect={() => selectPolicy(isSelected ? null : policy.id)}
                        matchCount={policyCounts[policy.id] ?? 0}
                        filterPolicy={filterPolicy}
                        setFilterPolicy={setFilterPolicy}
                      />
                    );
                  })}
                </React.Fragment>
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
          </>
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
