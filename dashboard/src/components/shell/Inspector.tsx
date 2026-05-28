import { useState } from 'react';
import { useUIStore } from '../../stores/ui-store';
import { useGovernanceStore, type GovernanceEvent } from '../../stores/governance-store';
import { SecurityLabelBadge } from '../SecurityLabelBadge';
import { confidentialityToLevel, categoriesToStrings } from '../../lib/label-display';

export interface InspectorProps {
  className?: string;
}

interface Section {
  id: string;
  title: string;
  render: (event: GovernanceEvent) => React.ReactElement;
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
    id: 'classification',
    title: 'Classification',
    render(event) {
      return (
        <div style={sectionStyles.body}>
          <SectionRow label="Tool" value={event.tool} />
          <SectionRow label="Adapter Family" value={event.enforcingLayer} />
          <SectionRow label="Risk Level" value={
            <span style={{ color: event.verdict === 'deny' ? '#cf222e' : event.verdict === 'allow' ? '#2da44e' : '#d29922' }}>
              {event.verdict}
            </span>
          } />
          <SectionRow label="Effects" value={event.reason || '—'} />
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
    render(_event) {
      return (
        <div style={sectionStyles.body}>
          <div style={sectionStyles.placeholder}>No delegation chain refs in MVP-1</div>
        </div>
      );
    },
  },
  {
    id: 'policy-evaluation',
    title: 'Policy Evaluation',
    render(event) {
      return (
        <div style={sectionStyles.body}>
          <SectionRow label="Policy ID" value={event.policyId || '—'} />
          <SectionRow label="Enforcing Layer" value={event.enforcingLayer || '—'} />
          <SectionRow label="CEL Expression" value="—" />
        </div>
      );
    },
  },
  {
    id: 'ifc-reasoning',
    title: 'IFC Reasoning',
    render(event) {
      const stateColor = labelStateColor(event.labelState);
      return (
        <div style={sectionStyles.body}>
          <SectionRow label="Dominates()" value="—" />
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
    render(_event) {
      return (
        <div style={sectionStyles.body}>
          <SectionRow label="Session Ceiling" value="N/A" />
          <SectionRow label="Requested Label" value="N/A" />
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
}: {
  section: Section;
  event: GovernanceEvent;
  isOpen: boolean;
  onToggle: () => void;
}) {
  return (
    <div style={accordionStyles.section}>
      <button
        style={accordionStyles.trigger}
        onClick={onToggle}
        aria-expanded={isOpen}
        aria-controls={`inspector-section-${section.id}`}
      >
        <span style={accordionStyles.title}>{section.title}</span>
        <span style={{ ...accordionStyles.chevron, transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)' }}>
          ▾
        </span>
      </button>
      {isOpen && (
        <div id={`inspector-section-${section.id}`} style={accordionStyles.content}>
          {section.render(event)}
        </div>
      )}
    </div>
  );
}

export function Inspector({ className }: InspectorProps): React.ReactElement {
  const inspectorTarget = useUIStore((s) => s.inspectorTarget);
  const events = useGovernanceStore((s) => s.events);

  const event = inspectorTarget
    ? events.find((e) => e.id === inspectorTarget) ?? null
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

  return (
    <div
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
            />
          ))}
        </div>
      )}
    </div>
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
    color: '#8b949e',
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
  placeholder: {
    color: '#30363d',
    fontSize: '11px',
    fontStyle: 'italic' as const,
    fontFamily: 'ui-monospace, Consolas, monospace',
  },
} as const;
