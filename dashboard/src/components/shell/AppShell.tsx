import React from 'react';

interface AppShellProps {
  header: React.ReactNode;
  metricsBar: React.ReactNode;
  sidebar: React.ReactNode;
  main: React.ReactNode;
  inspector: React.ReactNode;
}

export function AppShell({ header, metricsBar, sidebar, main, inspector }: AppShellProps) {
  return (
    <div style={{
      display: 'grid',
      gridTemplateRows: '44px 36px 1fr',
      gridTemplateColumns: '260px 1fr 320px',
      gridTemplateAreas: `
        "header  header   header"
        "metrics metrics  metrics"
        "sidebar main     inspector"
      `,
      height: '100vh',
      width: '100vw',
      overflow: 'hidden',
      background: 'var(--bg-base)',
    }}>
      <div style={{ gridArea: 'header',    borderBottom: '1px solid var(--border)', background: 'var(--bg-surface)' }}>
        {header}
      </div>
      <div style={{ gridArea: 'metrics',   borderBottom: '1px solid var(--border)', background: 'var(--bg-base)' }}>
        {metricsBar}
      </div>
      <div style={{ gridArea: 'sidebar',   borderRight: '1px solid var(--border)', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {sidebar}
      </div>
      <div style={{ gridArea: 'main',      overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {main}
      </div>
      <div style={{ gridArea: 'inspector', borderLeft: '1px solid var(--border)', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {inspector}
      </div>
    </div>
  );
}

interface AppHeaderProps {
  connectionState: string;
  onStartDemo: () => void;
  onOpenPalette: () => void;
}

export function AppHeader({ connectionState, onStartDemo, onOpenPalette }: AppHeaderProps) {
  const CONNECTION_COLORS: Record<string, string> = {
    CONNECTED: '#2da44e', MOCK: '#8250df', CONNECTING: '#d29922',
    DISCONNECTED: '#cf222e', RECONNECTING: '#d29922', IDLE: '#484f58', FAILED: '#cf222e',
  };
  const color = CONNECTION_COLORS[connectionState] ?? '#484f58';

  return (
    <div style={{ display: 'flex', alignItems: 'center', height: '100%', padding: '0 16px', gap: 12 }}>
      <span style={{ fontWeight: 700, fontSize: 15, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
        AEGIS
      </span>
      <span style={{ color: 'var(--border)', fontSize: 16 }}>|</span>

      <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color }}>
        <span style={{ width: 7, height: 7, borderRadius: '50%', background: color, display: 'inline-block' }} />
        {connectionState}
      </span>

      <div style={{ flex: 1 }} />

      <button
        onClick={onStartDemo}
        style={{
          display: 'flex', alignItems: 'center', gap: 7,
          padding: '6px 16px', borderRadius: 6,
          background: 'var(--info-blue)', border: 'none',
          color: '#fff', cursor: 'pointer', fontSize: 12,
          fontWeight: 600, letterSpacing: '0.01em',
          boxShadow: '0 0 0 0 rgba(88,166,255,0.4)',
          animation: 'demo-pulse 2.5s ease-in-out infinite',
          transition: 'transform 0.1s, box-shadow 0.1s',
        }}
        onMouseEnter={e => {
          e.currentTarget.style.transform = 'scale(1.04)';
          e.currentTarget.style.animation = 'none';
          e.currentTarget.style.boxShadow = '0 0 0 3px rgba(88,166,255,0.35)';
        }}
        onMouseLeave={e => {
          e.currentTarget.style.transform = 'scale(1)';
          e.currentTarget.style.animation = 'demo-pulse 2.5s ease-in-out infinite';
          e.currentTarget.style.boxShadow = '0 0 0 0 rgba(88,166,255,0.4)';
        }}
        onMouseDown={e => (e.currentTarget.style.transform = 'scale(0.97)')}
        onMouseUp={e => (e.currentTarget.style.transform = 'scale(1.04)')}
      >
        <span style={{ fontSize: 11 }}>▶</span> Start Demo
      </button>

      <button
        onClick={onOpenPalette}
        style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '5px 12px', borderRadius: 6,
          background: 'transparent', border: '1px solid var(--border)',
          color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 12,
        }}
        onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-overlay)')}
        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
      >
        ⌘K  <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>Commands</span>
      </button>
    </div>
  );
}

interface MetricProps {
  eventsPerSec: number;
  denyRate: number;
  p99LatencyMs: number;
  bufferPct: number;
  coalescedCount: number;
}

export function AppMetricsBar({ eventsPerSec, denyRate, p99LatencyMs, bufferPct, coalescedCount }: MetricProps) {
  const denyColor = denyRate > 10 ? 'var(--deny)' : denyRate > 5 ? 'var(--escalate)' : 'var(--text-secondary)';
  return (
    <div style={{
      display: 'flex', alignItems: 'center', height: '100%',
      padding: '0 16px', gap: 20,
      fontSize: 11, color: 'var(--text-secondary)',
    }}>
      <Metric label="EVENTS/S"   value={eventsPerSec.toFixed(1)} />
      <Metric label="DENY"       value={`${denyRate.toFixed(1)}%`} valueColor={denyColor} />
      <Metric label="P99"        value={`${p99LatencyMs.toFixed(2)}ms`} />
      <Metric label="BUFFER"     value={`${bufferPct.toFixed(0)}%`} />
      {coalescedCount > 0 && (
        <Metric label="COALESCED" value={`${coalescedCount}`} valueColor="var(--text-muted)" />
      )}
    </div>
  );
}

function Metric({ label, value, valueColor }: { label: string; value: string; valueColor?: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
      <span style={{ textTransform: 'uppercase', letterSpacing: '0.06em', fontSize: 10 }}>{label}</span>
      <span style={{ color: valueColor ?? 'var(--text-primary)', fontVariantNumeric: 'tabular-nums', fontWeight: 500 }}>
        {value}
      </span>
    </div>
  );
}
