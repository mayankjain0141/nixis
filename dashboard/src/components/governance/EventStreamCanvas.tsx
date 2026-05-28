import React, { useRef, useEffect, useCallback } from 'react';
import { useGovernanceStore } from '../../stores/governance-store';
import { useUIStore } from '../../stores/ui-store';
import type { GovernanceEvent } from '../../stores/governance-store';

const ROW_HEIGHT = 22;
const MAX_BUFFER = 500;

const VERDICT_COLORS: Record<string, string> = {
  deny: '#cf222e',
  allow: '#2da44e',
  require_approval: '#d29922',
  audit: '#8250df',
};

export function EventStreamCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rafRef = useRef<number>(0);
  const eventsRef = useRef<GovernanceEvent[]>([]);

  const events = useGovernanceStore((s) => s.events);
  const isPaused = useUIStore((s) => s.isPaused);
  const openInspector = useUIStore((s) => s.openInspector);

  // Keep eventsRef current when not paused
  useEffect(() => {
    if (!isPaused) {
      eventsRef.current = events.slice(-MAX_BUFFER);
    }
  }, [events, isPaused]);

  // Click handler: map Y position to event row
  const handleClick = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const y = e.clientY - rect.top;
      const visibleCount = Math.floor(canvas.height / ROW_HEIGHT);
      const displayEvents = eventsRef.current.slice(-visibleCount);
      const rowIndex = Math.floor(y / ROW_HEIGHT);
      const event = displayEvents[rowIndex];
      if (!event) return;
      openInspector(event.id);
    },
    [openInspector],
  );

  // rAF render loop — owns its own animation frame, does not go through React reconciliation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    function draw() {
      const w = canvas!.width;
      const h = canvas!.height;
      ctx!.clearRect(0, 0, w, h);

      const visibleCount = Math.floor(h / ROW_HEIGHT);
      const displayEvents = eventsRef.current.slice(-visibleCount);

      displayEvents.forEach((event, i) => {
        const y = i * ROW_HEIGHT;

        // Verdict color swatch
        ctx!.fillStyle = VERDICT_COLORS[event.verdict] ?? '#666';
        ctx!.fillRect(4, y + 4, 8, ROW_HEIGHT - 8);

        // Tool name
        ctx!.fillStyle = '#e6edf3';
        ctx!.font = '11px monospace';
        ctx!.fillText(event.tool, 18, y + ROW_HEIGHT / 2 + 4);

        // Verdict label — deny uses red (DenyColorGuard: never green)
        ctx!.fillStyle = VERDICT_COLORS[event.verdict] ?? '#666';
        ctx!.fillText(event.verdict, 160, y + ROW_HEIGHT / 2 + 4);

        // Latency
        const latMs =
          event.latencyNs > 1_000_000
            ? `${(event.latencyNs / 1_000_000).toFixed(1)}ms`
            : `${(event.latencyNs / 1000).toFixed(0)}μs`;
        ctx!.fillStyle = '#8b949e';
        ctx!.fillText(latMs, 260, y + ROW_HEIGHT / 2 + 4);

        // Row separator
        ctx!.fillStyle = '#21262d';
        ctx!.fillRect(0, y + ROW_HEIGHT - 1, w, 1);
      });

      rafRef.current = requestAnimationFrame(draw);
    }

    rafRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(rafRef.current);
  }, []);

  const topSeq =
    eventsRef.current[eventsRef.current.length - 1]?.aegisSequence ?? 0;
  const lastEvent = eventsRef.current[eventsRef.current.length - 1];

  return (
    <div style={{ position: 'relative' }}>
      <canvas
        ref={canvasRef}
        width={500}
        height={400}
        onClick={handleClick}
        data-sequence={topSeq}
        style={{ display: 'block', cursor: 'pointer', background: '#0d1117' }}
        aria-label="Live governance event stream"
      />
      {/* Accessibility: announce latest event to screen readers */}
      <div
        aria-live="polite"
        aria-atomic="false"
        style={{
          position: 'absolute',
          left: -9999,
          width: 1,
          height: 1,
          overflow: 'hidden',
        }}
      >
        {lastEvent
          ? `${lastEvent.tool}: ${lastEvent.verdict}`
          : 'No events'}
      </div>
    </div>
  );
}
