import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { useUIStore } from '../../stores/ui-store';
import { useGovernanceStore, type GovernanceEvent, type DelegationHop } from '../../stores/governance-store';
import { SecurityLabelBadge } from '../SecurityLabelBadge';
import {
  confidentialityToLevel,
  categoriesToStrings,
  formatSecurityLabel,
} from '../../lib/label-display';

export interface InspectorProps {
  className?: string;
}

interface Section {
  id: string;
  title: string;
  render: (event: GovernanceEvent) => React.ReactElement | null;
}

function formatLatency(ns: number): string {
  if (ns < 1_000_000) return `${ns.toLocaleString()} ns`;
  return `${(ns / 1_000_000).toFixed(2)} ms`;
}

function labelStateColor(state: string): string {
  switch (state) {
    case 'fresh': return '#2da44e';
    case 'escalated': return '#d29922';
    case 'tainted_by_secret': return '#cf222e';
    case 'declassified': return '#57606a';
    default: return '#8b949e';
  }
}

function SectionRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div style={sectionStyles.row}>
      <span style={sectionStyles.label}>{label}</span>
      <span style={sectionStyles.value}>{value}</span>
    </div>
  );
}

const SECTIONS: Section[] = [
  {
    id: 'why-denied',
    title: 'Why Denied',
    render(event) {
      if (event.verdict !== 'deny') return null;
      const ext = event as GovernanceEvent & Record<string, unknown>;
      return (
        <div
          style={{
            ...sectionStyles.body,
            borderLeft: '3px solid var(--deny, #cf222e)',
            paddingLeft: 12,
            marginLeft: -4,
          }}
          data-verdict="deny"
        >
          <SectionRow label="Reason" value={event.reason ?? '(no reason provided)'} />
          {typeof ext.celExpression === 'string' && (
            <SectionRow label="CEL Expression" value={ext.celExpression} />
          )}
          <SectionRow
            label="Classification"
            value={event.label ? formatSecurityLabel(event.label) : '—'}
          />
        </div>
      );
    },
  },
  {
    id: 'classification',
    title: 'Classification',
    render(event) {
      return (
        <div style={sectionStyles.body}>
          <SectionRow label="Tool" value={event.tool} />
          <SectionRow label="Enforcing Layer" value={event.enforcingLayer} />
          <SectionRow label="Risk Level" value={
            <span style={{ color: event.verdict === 'deny' ? '#cf222e' : event.verdict === 'allow' ? '#2da44e' : '#d29922' }}>
              {event.verdict}
            </span>
          } />
          <SectionRow label="Reason" value={event.reason || '—'} />
        </div>
      );
    },
  },
  {
    id: 'security-labels',
    title: 'Security Labels',
    render(event) {
      const cats = categoriesToStrings(event.label.categories);
      return (
        <div style={sectionStyles.body}>
          <SectionRow label="Confidentiality" value={
            <span>{confidentialityToLevel(event.label.confidentiality)} ({event.label.confidentiality})</span>
          } />
          <SectionRow label="Integrity" value={
            <span>{confidentialityToLevel(event.label.integrity)} ({event.label.integrity})</span>
          } />
          <SectionRow label="Categories" value={cats.length > 0 ? cats.join(', ') : '—'} />
          <div style={{ marginTop: '8px' }}>
            <SecurityLabelBadge label={event.label} variant="expanded" />
          </div>
        </div>
      );
    },
  },
  {
    id: 'delegation-chain',
    title: 'Delegation Chain',
    render(event) {
      const hops: DelegationHop[] =
        useGovernanceStore.getState().delegationChains.get(event.sessionId) ?? [];

      if (hops.length === 0) {
        return (
          <div style={sectionStyles.body}>
            <div style={sectionStyles.emptyState}>No delegation in this session</div>
          </div>
        );
      }

      return (
        <div style={sectionStyles.body}>
          {hops.map((hop, i) => (
            <div key={i} style={{ marginBottom: 8 }}>
              <span style={{ fontFamily: 'monospace', fontSize: 11 }}>
                Hop {hop.hopIndex}: {hop.delegatorId} → {hop.delegateeId}
              </span>
              <div style={{ fontSize: 10, color: '#666', marginTop: 2 }}>
                Granted: {formatSecurityLabel(hop.grantedLabel)}
                {' | '}
                Ceiling: {formatSecurityLabel(hop.ceilingLabel)}
              </div>
            </div>
          ))}
        </div>
      );
    },
  },
  {
    id: 'policy-evaluation',
    title: 'Policy Evaluation',
    render(event) {
      const ext = event as GovernanceEvent & Record<string, unknown>;
      const cel = typeof ext.celExpression === 'string'
        ? ext.celExpression
        : typeof ext.cel_expression === 'string'
          ? ext.cel_expression
          : '(not available)';
      return (
        <div style={sectionStyles.body}>
          <SectionRow label="Policy ID" value={event.policyId || '—'} />
          <SectionRow label="Enforcing Layer" value={event.enforcingLayer || '—'} />
          <SectionRow label="CEL Expression" value={cel} />
        </div>
      );
    },
  },
  {
    id: 'ifc-reasoning',
    title: 'IFC Reasoning',
    render(event) {
      const stateColor = labelStateColor(event.labelState);
      const ext = event as GovernanceEvent & Record<string, unknown>;
      const subj = event.label;
      const obj = ext.requestedLabel as typeof subj | undefined;

      let dominatesEl: React.ReactElement;
      if (!subj || !obj) {
        dominatesEl = <SectionRow label="Dominates()" value="(no requested label)" />;
      } else {
        const cOk = subj.confidentiality >= obj.confidentiality;
        const iOk = subj.integrity >= obj.integrity;
        const kOk = (subj.categories & obj.categories) === obj.categories;
        const result = cOk && iOk && kOk;
        dominatesEl = (
          <div style={sectionStyles.body}>
            <div style={{ fontFamily: 'monospace', fontSize: 11, marginBottom: 4 }}>
              C: {subj.confidentiality} ≥ {obj.confidentiality} {cOk ? '✓' : '✗'}<br />
              I: {subj.integrity} ≥ {obj.integrity} {iOk ? '✓' : '✗'}<br />
              K: {subj.categories} ⊇ {obj.categories} {kOk ? '✓' : '✗'}
            </div>
            <div style={{ fontWeight: 600, color: result ? '#2da44e' : '#cf222e' }}>
              Dominates(): {result ? 'YES' : 'NO'}
            </div>
          </div>
        );
      }

      return (
        <div style={sectionStyles.body}>
          {dominatesEl}
          <SectionRow label="Label State" value={
            <span style={{ color: stateColor }}>{event.labelState}</span>
          } />
        </div>
      );
    },
  },
  {
    id: 'capability-ceiling',
    title: 'Capability Ceiling',
    render(event) {
      const ext = event as GovernanceEvent & Record<string, unknown>;
      const ceiling = ext.capabilityCeiling as Parameters<typeof formatSecurityLabel>[0] | undefined;
      const requested = ext.requestedLabel as Parameters<typeof formatSecurityLabel>[0] | undefined;
      return (
        <div style={sectionStyles.body}>
          <SectionRow
            label="Session Ceiling"
            value={ceiling ? formatSecurityLabel(ceiling) : 'Not applicable for this event type'}
          />
          <SectionRow
            label="Requested Label"
            value={requested ? formatSecurityLabel(requested) : 'Not applicable for this event type'}
          />
        </div>
      );
    },
  },
  {
    id: 'audit-annotations',
    title: 'Audit Annotations',
    render(event) {
      return (
        <div style={sectionStyles.body}>
          <SectionRow label="Session ID" value={event.sessionId} />
          <SectionRow label="Sequence" value={String(event.aegisSequence)} />
        </div>
      );
    },
  },
  {
    id: 'latency-breakdown',
    title: 'Latency Breakdown',
    render(event) {
      return (
        <div style={sectionStyles.body}>
          <SectionRow label="Total Latency" value={formatLatency(event.latencyNs)} />
          <SectionRow label="Enforcing Layer" value={event.enforcingLayer} />
        </div>
      );
    },
  },
];

function AccordionSection({
  section,
  event,
  isOpen,
  onToggle,
  isDenySection,
}: {
  section: Section;
  event: GovernanceEvent;
  isOpen: boolean;
  onToggle: () => void;
  isDenySection: boolean;
}) {
  const content = section.render(event);
  if (content === null) return null;

  return (
    <div style={accordionStyles.section}>
      <button
        style={accordionStyles.trigger}
        onClick={onToggle}
        aria-expanded={isOpen}
        aria-controls={`inspector-section-${section.id}`}
        data-verdict={isDenySection ? 'deny' : undefined}
      >
        <span
          style={{
            ...accordionStyles.title,
            color: isDenySection ? '#cf222e' : '#8b949e',
          }}
        >
          {section.title}
        </span>
        <span style={{ ...accordionStyles.chevron, transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)' }}>
          ▾
        </span>
      </button>
      {isOpen && (
        <div id={`inspector-section-${section.id}`} style={accordionStyles.content}>
          {content}
        </div>
      )}
    </div>
  );
}

const MAX_PAUSE_BUFFER = 500;

export function Inspector({ className }: InspectorProps): React.ReactElement | null {
  const open = useUIStore((s) => s.inspectorOpen);
  const liveTarget = useUIStore((s) => s.inspectorTarget);
  const isPaused = useUIStore((s) => s.isPaused);
  const togglePause = useUIStore((s) => s.togglePause);
  const events = useGovernanceStore((s) => s.events);

  const [frozenTarget, setFrozenTarget] = useState(liveTarget);
  const pauseBuffer = useRef<string[]>([]);

  useEffect(() => {
    if (!isPaused) {
      pauseBuffer.current = [];
      setFrozenTarget(liveTarget);
    }
  }, [isPaused, liveTarget]);

  useEffect(() => {
    if (isPaused && liveTarget !== frozenTarget) {
      if (pauseBuffer.current.length < MAX_PAUSE_BUFFER && liveTarget !== null) {
        pauseBuffer.current.push(liveTarget);
      }
    } else if (!isPaused) {
      setFrozenTarget(liveTarget);
    }
  }, [liveTarget, isPaused, frozenTarget]);

  const displayTarget = isPaused ? frozenTarget : liveTarget;

  const event = displayTarget
    ? events.find((e) => e.id === displayTarget) ?? null
    : null;

  const [openSections, setOpenSections] = useState<Set<string>>(
    new Set(['classification'])
  );

  function toggleSection(id: string) {
    setOpenSections((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  if (!open) return null;

  return (
    <motion.aside
      initial={{ x: 280, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ duration: 0.25, ease: 'easeOut' }}
      style={{
        ...containerStyles.root,
        userSelect: 'text',
      }}
      className={className}
      role="complementary"
      aria-label="Inspector panel"
    >
      <div style={containerStyles.header}>
        <span style={containerStyles.title}>Inspector</span>
        {event && (
          <span style={containerStyles.eventId} title={event.id}>
            {event.tool}
          </span>
        )}
        <button
          style={containerStyles.pauseButton}
          onClick={togglePause}
          aria-pressed={isPaused}
          aria-label={isPaused ? 'Resume inspector' : 'Pause inspector'}
        >
          {isPaused ? 'Resume' : 'Pause'}
        </button>
      </div>

      {!event ? (
        <div style={containerStyles.empty} role="status">
          Select an event to inspect
        </div>
      ) : (
        <div style={containerStyles.sections}>
          {SECTIONS.map((section) => (
            <AccordionSection
              key={section.id}
              section={section}
              event={event}
              isOpen={openSections.has(section.id)}
              onToggle={() => toggleSection(section.id)}
              isDenySection={section.id === 'why-denied' && event.verdict === 'deny'}
            />
          ))}
        </div>
      )}
    </motion.aside>
  );
}

const containerStyles = {
  root: {
    display: 'flex',
    flexDirection: 'column' as const,
    background: '#0d1117',
    height: '100%',
    overflow: 'hidden',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '8px 12px',
    background: '#161b22',
    borderBottom: '1px solid #21262d',
    flexShrink: 0,
  },
  title: {
    color: '#e6edf3',
    fontSize: '13px',
    fontWeight: 600,
    fontFamily: 'ui-monospace, Consolas, monospace',
  },
  eventId: {
    color: '#57606a',
    fontSize: '11px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    marginLeft: 'auto',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap' as const,
    maxWidth: '140px',
  },
  pauseButton: {
    marginLeft: '8px',
    padding: '2px 8px',
    fontSize: '11px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    background: '#21262d',
    color: '#8b949e',
    border: '1px solid #30363d',
    borderRadius: '4px',
    cursor: 'pointer',
    flexShrink: 0,
  },
  empty: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flex: 1,
    color: '#57606a',
    fontSize: '13px',
    fontFamily: 'ui-monospace, Consolas, monospace',
  },
  sections: {
    flex: 1,
    overflowY: 'auto' as const,
  },
} as const;

const accordionStyles = {
  section: {
    borderBottom: '1px solid #21262d',
  },
  trigger: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    width: '100%',
    padding: '8px 12px',
    background: 'transparent',
    border: 'none',
    cursor: 'pointer',
    color: '#8b949e',
    textAlign: 'left' as const,
  },
  title: {
    fontSize: '12px',
    fontWeight: 600,
    fontFamily: 'ui-monospace, Consolas, monospace',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.05em',
  },
  chevron: {
    color: '#57606a',
    fontSize: '12px',
    transition: 'transform 0.15s',
    flexShrink: 0,
  },
  content: {
    padding: '0 12px 12px',
  },
} as const;

const sectionStyles = {
  body: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '6px',
  },
  row: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '8px',
    minHeight: '20px',
  },
  label: {
    color: '#57606a',
    fontSize: '11px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    flexShrink: 0,
    width: '110px',
  },
  value: {
    color: '#e6edf3',
    fontSize: '11px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    wordBreak: 'break-all' as const,
    flex: 1,
  },
  emptyState: {
    color: '#30363d',
    fontSize: '11px',
    fontStyle: 'italic' as const,
    fontFamily: 'ui-monospace, Consolas, monospace',
  },
} as const;
