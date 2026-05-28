import React, { useRef, useEffect } from 'react';
import { useThreatStore, type ThreatEvent } from '../../stores/threat-store';

const CANVAS_HEIGHT = 160;
const CANVAS_WIDTH = 500;
const TIMELINE_WINDOW_MS = 5 * 60 * 1000;

const SEVERITY_Y: Record<string, number> = {
  critical: 20,
  high: 60,
  medium: 100,
  low: 130,
};

const TYPE_COLORS: Record<string, string> = {
  'secret.found': '#cf222e',
  'label.tainted': '#d29922',
  'system.error': '#8b949e',
};

function plotThreats(
  ctx: CanvasRenderingContext2D,
  threats: ThreatEvent[],
): void {
  const now = Date.now();
  const windowStart = now - TIMELINE_WINDOW_MS;

  ctx.clearRect(0, 0, CANVAS_WIDTH, CANVAS_HEIGHT);
  ctx.fillStyle = '#0d1117';
  ctx.fillRect(0, 0, CANVAS_WIDTH, CANVAS_HEIGHT);

  ctx.strokeStyle = '#30363d';
  ctx.beginPath();
  ctx.moveTo(0, CANVAS_HEIGHT - 20);
  ctx.lineTo(CANVAS_WIDTH, CANVAS_HEIGHT - 20);
  ctx.stroke();

  for (const threat of threats) {
    if (threat.timestamp < windowStart) continue;
    const x = ((threat.timestamp - windowStart) / TIMELINE_WINDOW_MS) * CANVAS_WIDTH;
    const y = SEVERITY_Y[threat.severity] ?? 130;
    ctx.fillStyle = TYPE_COLORS[threat.type] ?? '#8b949e';
    ctx.beginPath();
    ctx.arc(x, y, 5, 0, Math.PI * 2);
    ctx.fill();
  }
}

export function ThreatTimeline() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rafRef = useRef<number>(0);
  // Mutable ref keeps the rAF loop reading the latest threats without restarting.
  const threatsRef = useRef<ThreatEvent[]>([]);
  const threats = useThreatStore((s) => s.threats);

  // Sync latest threats into the ref every render.
  threatsRef.current = threats;

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d') ?? null;

    function draw() {
      if (ctx) plotThreats(ctx, threatsRef.current);
      rafRef.current = requestAnimationFrame(draw);
    }

    rafRef.current = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(rafRef.current);
    };
  }, []);

  return (
    <div style={{ position: 'relative' }} aria-label="Threat timeline">
      <canvas
        ref={canvasRef}
        width={CANVAS_WIDTH}
        height={CANVAS_HEIGHT}
        style={{ display: 'block', background: '#0d1117' }}
      />
      <table
        aria-label="Threat events"
        style={{ position: 'absolute', left: -9999, top: 0 }}
      >
        <tbody>
          {threats.map((t) => (
            <tr key={t.id}>
              <td>{t.type}</td>
              <td>{t.severity}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
