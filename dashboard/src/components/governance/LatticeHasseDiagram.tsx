import { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import { useLatticeStore } from '../../stores/lattice-store';
import { confidentialityToLevel } from '../../lib/label-display';

const LATTICE_LEVELS = [
  { id: 'unclassified', label: 'Unclassified', y: 300, x: 200 },
  { id: 'internal', label: 'Internal', y: 200, x: 200 },
  { id: 'confidential', label: 'Confidential', y: 100, x: 200 },
  { id: 'restricted', label: 'Restricted', y: 0, x: 200 },
] as const;

const LATTICE_EDGES = [
  { source: 'restricted', target: 'confidential' },
  { source: 'confidential', target: 'internal' },
  { source: 'internal', target: 'unclassified' },
] as const;

function confidentialityToNodeId(c: number): string {
  if (c >= 49152) return 'restricted';
  if (c >= 24576) return 'confidential';
  if (c >= 8192) return 'internal';
  return 'unclassified';
}

export function LatticeHasseDiagram() {
  const staticRef = useRef<SVGSVGElement>(null);
  const nodes = useLatticeStore((s) => s.nodes);

  // Draw static layer once on mount — never redraws
  useEffect(() => {
    const svg = d3.select(staticRef.current);
    svg.selectAll('*').remove();

    svg.append('defs').append('marker')
      .attr('id', 'hasse-arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 10)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#30363d');

    const g = svg.append('g').attr('transform', 'translate(10, 10)');

    LATTICE_EDGES.forEach(({ source, target }) => {
      const src = LATTICE_LEVELS.find(l => l.id === source)!;
      const tgt = LATTICE_LEVELS.find(l => l.id === target)!;
      g.append('line')
        .attr('x1', src.x).attr('y1', src.y)
        .attr('x2', tgt.x).attr('y2', tgt.y)
        .attr('stroke', '#30363d')
        .attr('stroke-width', 2)
        .attr('marker-end', 'url(#hasse-arrow)');
    });

    LATTICE_LEVELS.forEach(level => {
      const node = g.append('g').attr('transform', `translate(${level.x}, ${level.y})`);
      node.append('circle')
        .attr('r', 20)
        .attr('fill', '#1e2a3a')
        .attr('stroke', '#58a6ff')
        .attr('stroke-width', 1.5);
      node.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', '0.35em')
        .attr('font-size', 10)
        .attr('fill', '#e6edf3')
        .text(level.label);
    });
  }, []);

  const sessions = Array.from(nodes.values());

  const sessionDots = sessions.map((session) => {
    const nodeId = confidentialityToNodeId(session.label.confidentiality);
    const levelNode = LATTICE_LEVELS.find(l => l.id === nodeId)!;
    return { session, levelNode };
  });

  return (
    <div style={{ position: 'relative', width: 420, height: 360 }} aria-label="IFC Lattice Hasse Diagram">
      {/* Layer 1: static Hasse structure — never changes */}
      <svg
        ref={staticRef}
        className="hasse-static"
        width={420}
        height={360}
        style={{ position: 'absolute', top: 0, left: 0 }}
        aria-hidden="true"
      />

      {/* Layer 2: session high-water marks — updates with sessions */}
      <svg
        className="hasse-overlay"
        width={420}
        height={360}
        style={{ position: 'absolute', top: 0, left: 0, pointerEvents: 'none' }}
        aria-label="Session high-water marks"
      >
        {sessionDots.map(({ session, levelNode }, i) => (
          <g
            key={session.sessionId}
            transform={`translate(${levelNode.x + 25 + (i % 4) * 12}, ${levelNode.y + 10})`}
            data-label-state={session.state}
            className="session-dot"
          >
            <circle
              r={5}
              fill={
                session.state === 'escalated'
                  ? '#d29922'
                  : session.state === 'tainted_by_secret'
                  ? '#cf222e'
                  : '#2da44e'
              }
              opacity={0.85}
            />
          </g>
        ))}
      </svg>

      {/* Screen-reader accessible list */}
      <ul aria-label="IFC Lattice sessions" style={{ position: 'absolute', left: -9999 }}>
        {sessions.map((session) => (
          <li key={session.sessionId}>
            Session {session.sessionId}: {confidentialityToLevel(session.label.confidentiality)}
          </li>
        ))}
      </ul>
    </div>
  );
}
