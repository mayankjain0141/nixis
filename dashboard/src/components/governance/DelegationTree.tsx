import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import { useGovernanceStore, type DelegationHop } from '../../stores/governance-store';

const SVG_WIDTH = 380;
const SVG_HEIGHT = 300;
const NODE_HEIGHT = 50;
const NODE_X = 100;
const APPROX_CHAR_WIDTH = 6.5;

export function DelegationTree() {
  const svgRef = useRef<SVGSVGElement>(null);
  const delegationChains = useGovernanceStore((s) => s.delegationChains);

  useEffect(() => {
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    let hops: DelegationHop[] = [];
    for (const chain of delegationChains.values()) {
      if (chain.length > 0) {
        hops = chain;
        break;
      }
    }

    if (hops.length === 0) {
      svg
        .append('text')
        .attr('x', 10)
        .attr('y', 20)
        .attr('fill', '#8b949e')
        .attr('font-size', 12)
        .text('No delegation chains active');
      return;
    }

    const g = svg.append('g').attr('transform', 'translate(20, 20)');

    const nodeData = [
      { label: hops[0].delegatorId, y: 0, attenuated: false },
      ...hops.map((hop, i) => ({
        label: hop.delegateeId,
        y: (i + 1) * NODE_HEIGHT,
        attenuated:
          hop.ceilingLabel.confidentiality < hop.grantedLabel.confidentiality,
      })),
    ];

    for (let i = 0; i < nodeData.length - 1; i++) {
      g.append('line')
        .attr('x1', NODE_X)
        .attr('y1', nodeData[i].y + 12)
        .attr('x2', NODE_X)
        .attr('y2', nodeData[i + 1].y)
        .attr('stroke', '#30363d')
        .attr('stroke-width', 1.5);
    }

    nodeData.forEach((node) => {
      const row = g.append('g').attr('transform', `translate(0, ${node.y})`);

      row
        .append('circle')
        .attr('cx', NODE_X)
        .attr('cy', 8)
        .attr('r', 8)
        .attr('fill', '#1e2a3a')
        .attr('stroke', '#58a6ff');

      row
        .append('text')
        .attr('x', 116)
        .attr('y', 12)
        .attr('font-size', 11)
        .attr('fill', '#e6edf3')
        .text(node.label);

      if (node.attenuated) {
        const approxWidth = node.label.length * APPROX_CHAR_WIDTH;
        row
          .append('line')
          .attr('x1', 116)
          .attr('y1', 8)
          .attr('x2', 116 + approxWidth)
          .attr('y2', 8)
          .attr('stroke', '#cf222e')
          .attr('stroke-width', 1.5);
      }
    });
  }, [delegationChains]);

  return (
    <div aria-label="Delegation chain tree">
      <svg
        ref={svgRef}
        width={SVG_WIDTH}
        height={SVG_HEIGHT}
        style={{ background: '#0d1117' }}
      />
    </div>
  );
}
