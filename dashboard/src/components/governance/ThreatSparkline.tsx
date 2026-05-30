import { useState } from 'react';
import type { ThreatEvent, ThreatSeverity } from '../../stores/threat-store';

const HEIGHT = 24;
const WIDTH = 400;
const WINDOW_MS = 5 * 60 * 1000;
const DOT_RADIUS = 4;
const DOT_HOVER_RADIUS = 6;

const SEVERITY_Y: Record<ThreatSeverity, number> = {
  critical: 4,
  high: 10,
  medium: 16,
  low: 20,
};

const SEVERITY_COLOR: Record<ThreatSeverity, string> = {
  critical: '#cf222e',
  high: '#d29922',
  medium: '#e3b341',
  low: '#388bfd',
};

interface Props {
  threats: ThreatEvent[];
}

export function ThreatSparkline({ threats }: Props) {
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  if (threats.length < 3) return null;

  const now = Date.now();
  const windowStart = now - WINDOW_MS;

  const visible = threats.filter((t) => t.timestamp >= windowStart);

  return (
    <svg
      width="100%"
      height={HEIGHT}
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      preserveAspectRatio="none"
      aria-label="Threat frequency sparkline"
      style={{ display: 'block', overflow: 'visible' }}
    >
      {visible.map((threat) => {
        const x = ((threat.timestamp - windowStart) / WINDOW_MS) * WIDTH;
        const y = SEVERITY_Y[threat.severity];
        const isHovered = hoveredId === threat.id;
        const r = isHovered ? DOT_HOVER_RADIUS : DOT_RADIUS;
        return (
          <circle
            key={threat.id}
            cx={x}
            cy={y}
            r={r}
            fill={SEVERITY_COLOR[threat.severity]}
            opacity={threat.acknowledged ? 0.4 : 1}
            onMouseEnter={() => setHoveredId(threat.id)}
            onMouseLeave={() => setHoveredId(null)}
            style={{ transition: 'r 0.1s', cursor: 'default' }}
          />
        );
      })}
    </svg>
  );
}
