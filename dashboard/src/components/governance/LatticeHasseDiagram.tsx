import { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import { useLatticeStore } from '../../stores/lattice-store';
import { useGovernanceStore } from '../../stores/governance-store';
import { confidentialityToLevel } from '../../lib/label-display';

// The G_OFFSET must match the translate() applied to the D3 group below.
const G_OFFSET = { x: 10, y: 30 };

const LATTICE_LEVELS = [
  { id: 'unclassified', label: 'Unclassified', y: 270, x: 160 },
  { id: 'internal',     label: 'Internal',     y: 180, x: 160 },
  { id: 'confidential', label: 'Confidential', y: 90,  x: 160 },
  { id: 'restricted',   label: 'Restricted',   y: 0,   x: 160 },
] as const;

const LATTICE_EDGES = [
  { source: 'restricted',   target: 'confidential' },
  { source: 'confidential', target: 'internal' },
  { source: 'internal',     target: 'unclassified' },
] as const;

function confidentialityToNodeId(c: number): string {
  if (c >= 49152) return 'restricted';
  if (c >= 24576) return 'confidential';
  if (c >= 8192)  return 'internal';
  return 'unclassified';
}

const LEVEL_COLORS: Record<string, string> = {
  restricted:   '#cf222e',
  confidential: '#d29922',
  internal:     '#58a6ff',
  unclassified: '#2da44e',
};

export function LatticeHasseDiagram() {
  const staticRef = useRef<SVGSVGElement>(null);

  // Primary: lattice store (escalation events)
  const latticeNodes = useLatticeStore((s) => s.nodes);
  // Fallback: governance store session labels (policy.evaluated events)
  const sessionLabels = useGovernanceStore((s) => s.sessionLabels);

  // Draw static Hasse layer once on mount
  useEffect(() => {
    const svg = d3.select(staticRef.current);
    svg.selectAll('*').remove();

    svg.append('defs').append('marker')
      .attr('id', 'hasse-arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 22).attr('refY', 0)
      .attr('markerWidth', 6).attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#30363d');

    const g = svg.append('g')
      .attr('transform', `translate(${G_OFFSET.x}, ${G_OFFSET.y})`);

    // Edges
    LATTICE_EDGES.forEach(({ source, target }) => {
      const src = LATTICE_LEVELS.find(l => l.id === source)!;
      const tgt = LATTICE_LEVELS.find(l => l.id === target)!;
      g.append('line')
        .attr('x1', src.x).attr('y1', src.y)
        .attr('x2', tgt.x).attr('y2', tgt.y)
        .attr('stroke', '#30363d').attr('stroke-width', 1.5)
        .attr('marker-end', 'url(#hasse-arrow)');
    });

    // Nodes: circle + label to the right
    LATTICE_LEVELS.forEach(level => {
      const node = g.append('g').attr('transform', `translate(${level.x}, ${level.y})`);
      node.append('circle')
        .attr('r', 16)
        .attr('fill', '#1e2a3a')
        .attr('stroke', LEVEL_COLORS[level.id])
        .attr('stroke-width', 2);
      // Level abbreviation inside circle
      node.append('text')
        .attr('text-anchor', 'middle').attr('dy', '0.35em')
        .attr('font-size', 9).attr('fill', LEVEL_COLORS[level.id])
        .attr('font-weight', '600')
        .text(level.label.slice(0, 3).toUpperCase());
      // Full label to the right
      node.append('text')
        .attr('x', 22).attr('dy', '0.35em')
        .attr('font-size', 11).attr('fill', '#e6edf3')
        .text(level.label);
    });
  }, []);

  // Build session list: prefer lattice store, fall back to governance sessionLabels
  const latticeArr = Array.from(latticeNodes.values());

  // Also pull from sessionLabels for sessions not yet in lattice store
  const sessionArr = Array.from(sessionLabels instanceof Map
    ? sessionLabels.values()
    : Object.values(sessionLabels as Record<string, unknown>)
  ) as Array<{ sessionId: string; label: { confidentiality: number; integrity: number; categories: number }; state: string }>;

  // Merge: lattice store takes priority
  const latticeIds = new Set(latticeArr.map(n => n.sessionId));
  const extraSessions = sessionArr.filter(s => !latticeIds.has(s.sessionId));

  const allSessions = [
    ...latticeArr.map(n => ({ sessionId: n.sessionId, confidentiality: n.label.confidentiality, state: n.state })),
    ...extraSessions.map(s => ({ sessionId: s.sessionId, confidentiality: s.label?.confidentiality ?? 0, state: s.state ?? 'fresh' })),
  ];

  // Group sessions by lattice level
  const byLevel: Record<string, typeof allSessions> = {};
  for (const s of allSessions) {
    const nodeId = confidentialityToNodeId(s.confidentiality);
    if (!byLevel[nodeId]) byLevel[nodeId] = [];
    byLevel[nodeId].push(s);
  }

  const DOT_STATE_COLORS: Record<string, string> = {
    escalated:         '#d29922',
    tainted_by_secret: '#cf222e',
    fresh:             '#2da44e',
    ceiling_hit:       '#8250df',
  };

  return (
    <div style={{ position: 'relative', width: 380, height: 360 }} aria-label="IFC Lattice Hasse Diagram">
      {/* Layer 1: static Hasse structure */}
      <svg
        ref={staticRef}
        className="hasse-static"
        width={380} height={360}
        style={{ position: 'absolute', top: 0, left: 0 }}
        aria-hidden="true"
      />

      {/* Layer 2: session overlay — dots aligned to static circles */}
      <svg
        className="hasse-overlay"
        width={380} height={360}
        style={{ position: 'absolute', top: 0, left: 0, pointerEvents: 'none' }}
        aria-label="Session high-water marks"
      >
        {LATTICE_LEVELS.map(level => {
          const sessions = byLevel[level.id] ?? [];
          return sessions.map((s, i) => {
            // Align with static layer: account for G_OFFSET + node position
            const cx = G_OFFSET.x + level.x + 30 + (i % 5) * 14;
            const cy = G_OFFSET.y + level.y;
            const color = DOT_STATE_COLORS[s.state] ?? '#2da44e';
            return (
              <g
                key={s.sessionId}
                transform={`translate(${cx}, ${cy})`}
                data-label-state={s.state}
                className="session-dot"
              >
                <circle r={7} fill={color} opacity={0.9} />
                <title>{s.sessionId.slice(0, 8)} — {s.state}</title>
              </g>
            );
          });
        })}
      </svg>

      {/* Empty state */}
      {allSessions.length === 0 && (
        <div style={{
          position: 'absolute', bottom: 8, left: 0, right: 0,
          textAlign: 'center', color: '#8b949e', fontSize: 11,
        }}>
          No active sessions
        </div>
      )}

      {/* Session count badge */}
      {allSessions.length > 0 && (
        <div style={{
          position: 'absolute', bottom: 6, right: 8,
          fontSize: 10, color: '#8b949e',
        }}>
          {allSessions.length} session{allSessions.length !== 1 ? 's' : ''}
        </div>
      )}

      {/* Screen-reader list */}
      <ul aria-label="IFC Lattice sessions" style={{ position: 'absolute', left: -9999 }}>
        {allSessions.map(s => (
          <li key={s.sessionId}>
            Session {s.sessionId}: {confidentialityToLevel(s.confidentiality)} ({s.state})
          </li>
        ))}
      </ul>
    </div>
  );
}
