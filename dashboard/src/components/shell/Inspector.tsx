import { useState } from 'react';
import { useUIStore } from '../../stores/ui-store';
import { useGovernanceStore } from '../../stores/governance-store';
import { usePolicyStore } from '../../stores/policy-store';
import { confidentialityToLevel } from '../../lib/label-display';

function KeyRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
      <span style={{ fontSize: 12, color: 'var(--text-secondary)', flexShrink: 0, marginRight: 12 }}>
        {label}
      </span>
      <span style={{
        fontSize: 12, color: 'var(--text-primary)',
        fontFamily: mono ? 'monospace' : 'inherit',
        textAlign: 'right', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const,
      }}>
        {value}
      </span>
    </div>
  );
}

function CollapsibleSection({ title, children }: { title: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ borderBottom: '1px solid var(--border)' }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '8px 16px', background: 'transparent', border: 'none', cursor: 'pointer',
          color: 'var(--text-secondary)', fontSize: 11,
          textTransform: 'uppercase' as const, letterSpacing: '0.06em',
        }}
      >
        {title} <span>{open ? '▴' : '▾'}</span>
      </button>
      {open && <div style={{ padding: '0 16px 12px' }}>{children}</div>}
    </div>
  );
}

const VERDICT_COLORS: Record<string, string> = {
  deny:             'var(--deny)',
  allow:            'var(--allow)',
  require_approval: 'var(--escalate)',
  audit:            'var(--audit-purple)',
};

const VERDICT_LABELS: Record<string, string> = {
  deny:             'DENY',
  allow:            'ALLOW',
  require_approval: 'REQUIRE APPROVAL',
  audit:            'AUDIT',
};

export function Inspector() {
  const inspectorTarget = useUIStore((s) => s.inspectorTarget);
  const isPaused = useUIStore((s) => s.isPaused);
  const togglePause = useUIStore((s) => s.togglePause);
  const events = useGovernanceStore((s) => s.events);
  const policies = usePolicyStore((s) => s.policies);

  const event = inspectorTarget
    ? events.find(e => e.id === inspectorTarget) ?? null
    : null;

  if (!event) {
    return (
      <div style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
        height: '100%', color: 'var(--text-secondary)', gap: 8, padding: 20, textAlign: 'center',
      }}>
        <div style={{ fontSize: 28, opacity: 0.3 }}>&#8857;</div>
        <div style={{ fontSize: 12 }}>Click an event to inspect</div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Select any row in the event stream</div>
      </div>
    );
  }

  const policy = policies.find(p => p.id === event.policyId);
  const verdictColor = VERDICT_COLORS[event.verdict] ?? 'var(--text-secondary)';
  const verdictLabel = VERDICT_LABELS[event.verdict] ?? event.verdict.toUpperCase();

  const latencyFormatted = event.latencyNs >= 1_000_000
    ? `${(event.latencyNs / 1_000_000).toFixed(2)}ms`
    : event.latencyNs >= 1_000
    ? `${(event.latencyNs / 1_000).toFixed(0)}us`
    : `${event.latencyNs}ns`;

  const celExpr = event.celExpression ?? policy?.celExpression;
  const ext = event as typeof event & { requestedLabel?: { confidentiality: number; integrity: number; categories: number } };

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', fontSize: 13 }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '8px 12px', borderBottom: '1px solid var(--border)',
        background: 'var(--bg-surface)', flexShrink: 0,
      }}>
        <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
          #{event.aegisSequence}
        </span>
        <button
          onClick={togglePause}
          style={{
            background: 'transparent', border: '1px solid var(--border)', borderRadius: 4,
            color: isPaused ? 'var(--info-blue)' : 'var(--text-secondary)',
            padding: '2px 8px', cursor: 'pointer', fontSize: 11,
          }}
        >
          {isPaused ? 'Resume' : 'Pause'}
        </button>
      </div>

      <div style={{ flex: 1, overflow: 'auto', padding: '0 0 12px' }}>
        {/* Verdict — primary signal */}
        <div style={{
          padding: '20px 16px 16px',
          borderBottom: event.verdict === 'deny' ? '3px solid var(--deny)' : '1px solid var(--border)',
          background: event.verdict === 'deny' ? 'rgba(207,34,46,0.06)' : 'transparent',
        }}>
          <div
            data-verdict={event.verdict}
            style={{
              fontSize: 32, fontWeight: 800, letterSpacing: '-0.02em',
              color: verdictColor, marginBottom: 10, lineHeight: 1,
            }}
          >
            {verdictLabel}
          </div>
          {event.reason && (
            <div style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.5 }}>
              {event.reason}
            </div>
          )}
        </div>

        {/* Key facts */}
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
          <KeyRow label="Tool"    value={event.tool} mono />
          <KeyRow label="Policy"  value={policy?.name ?? event.policyId ?? '—'} />
          <KeyRow label="Layer"   value={event.enforcingLayer} />
          <KeyRow label="Session" value={event.sessionId?.slice(-8) ?? '—'} mono />
        </div>

        {/* CEL Expression */}
        {celExpr && (
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
            <div style={{
              fontSize: 11, color: 'var(--text-secondary)', marginBottom: 6,
              textTransform: 'uppercase' as const, letterSpacing: '0.06em',
            }}>
              CEL Expression
            </div>
            <pre style={{
              background: 'var(--bg-base)', border: '1px solid var(--border)',
              borderRadius: 4, padding: '8px 10px', margin: 0,
              fontFamily: 'monospace', fontSize: 11, color: '#79c0ff',
              whiteSpace: 'pre-wrap' as const, wordBreak: 'break-all' as const,
              maxHeight: 90, overflow: 'auto', lineHeight: 1.6,
            }}>
              {celExpr}
            </pre>
          </div>
        )}

        {/* Timing */}
        <div style={{
          padding: '10px 16px', borderBottom: '1px solid var(--border)',
          display: 'flex', gap: 20,
        }}>
          <div>
            <div style={{
              fontSize: 10, color: 'var(--text-secondary)',
              textTransform: 'uppercase' as const, letterSpacing: '0.06em',
            }}>
              Latency
            </div>
            <div style={{
              fontVariantNumeric: 'tabular-nums', fontWeight: 600,
              color: event.latencyNs > 2_000_000 ? 'var(--escalate)' : 'var(--text-primary)',
            }}>
              {latencyFormatted}
            </div>
          </div>
          <div>
            <div style={{
              fontSize: 10, color: 'var(--text-secondary)',
              textTransform: 'uppercase' as const, letterSpacing: '0.06em',
            }}>
              Sequence
            </div>
            <div style={{ fontVariantNumeric: 'tabular-nums' }}>
              #{event.aegisSequence}
            </div>
          </div>
        </div>

        {/* Security Label — collapsible */}
        <CollapsibleSection title="Security Label">
          <KeyRow label="Confidentiality" value={confidentialityToLevel(event.label?.confidentiality ?? 0)} />
          <KeyRow label="Integrity"       value={confidentialityToLevel(event.label?.integrity ?? 0)} />
          <KeyRow label="State"           value={event.labelState ?? 'fresh'} />
        </CollapsibleSection>

        {/* IFC Reasoning — collapsible, only when requestedLabel is present */}
        {ext.requestedLabel && (
          <CollapsibleSection title="IFC Reasoning">
            {(() => {
              const subj = event.label;
              const obj = ext.requestedLabel!;
              const cOk = subj.confidentiality >= obj.confidentiality;
              const iOk = subj.integrity >= obj.integrity;
              const kOk = (subj.categories & obj.categories) === obj.categories;
              const dominates = cOk && iOk && kOk;
              return (
                <div style={{ fontFamily: 'monospace', fontSize: 11, lineHeight: 2 }}>
                  <div>C: {subj.confidentiality} &ge; {obj.confidentiality} {cOk ? '✓' : '✗'}</div>
                  <div>I: {subj.integrity} &ge; {obj.integrity} {iOk ? '✓' : '✗'}</div>
                  <div>K: {subj.categories} &supe; {obj.categories} {kOk ? '✓' : '✗'}</div>
                  <div style={{
                    fontWeight: 700,
                    color: dominates ? 'var(--allow)' : 'var(--deny)',
                    marginTop: 4,
                  }}>
                    Dominates(): {dominates ? 'YES' : 'NO'}
                  </div>
                </div>
              );
            })()}
          </CollapsibleSection>
        )}
      </div>
    </div>
  );
}
