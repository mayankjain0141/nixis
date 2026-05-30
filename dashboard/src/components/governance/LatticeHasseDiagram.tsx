import { useState, useRef, useCallback, useEffect } from 'react';
import { useLatticeStore } from '../../stores/lattice-store';
import { useGovernanceStore } from '../../stores/governance-store';
import { confidentialityToLevel } from '../../lib/label-display';

const LATTICE_LEVELS = [
  {
    id: 'restricted',
    label: 'Restricted',
    y: 50,
    color: '#cf222e',
    description: 'Secrets, PII, credentials — highest sensitivity',
  },
  {
    id: 'confidential',
    label: 'Confidential',
    y: 130,
    color: '#d29922',
    description: 'Financial data, health records, legal docs',
  },
  {
    id: 'internal',
    label: 'Internal',
    y: 210,
    color: '#58a6ff',
    description: 'Non-public APIs, internal tooling, config',
  },
  {
    id: 'unclassified',
    label: 'Unclassified',
    y: 290,
    color: '#2da44e',
    description: 'Public data, no sensitivity constraints',
  },
] as const;

const LATTICE_EDGES = [
  { source: 'restricted', target: 'confidential' },
  { source: 'confidential', target: 'internal' },
  { source: 'internal', target: 'unclassified' },
] as const;

const NODE_X = 100;
const SVG_WIDTH = 480;
const SVG_HEIGHT = 340;

function confidentialityToNodeId(c: number): string {
  if (c >= 49152) return 'restricted';
  if (c >= 24576) return 'confidential';
  if (c >= 8192) return 'internal';
  return 'unclassified';
}

const STATE_COLORS: Record<string, string> = {
  escalated: '#d29922',
  tainted_by_secret: '#cf222e',
  tainted: '#cf222e',
  fresh: '#2da44e',
  ceiling_hit: '#8250df',
  declassified: '#58a6ff',
};

function stateLabel(state: string): string {
  switch (state) {
    case 'escalated': return 'escalated';
    case 'tainted_by_secret':
    case 'tainted': return 'tainted';
    case 'ceiling_hit': return 'ceiling hit';
    case 'declassified': return 'declassified';
    default: return 'fresh';
  }
}

interface SessionEntry {
  sessionId: string;
  confidentiality: number;
  state: string;
  escalationCount: number;
}

export function LatticeHasseDiagram() {
  const [selectedLevel, setSelectedLevel] = useState<string | null>(null);
  const [showHelp, setShowHelp] = useState(false);
  const previousCountsRef = useRef<Map<string, number>>(new Map());
  const animatingBadgesRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const animatingCirclesRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const [pulseBadges, setPulseBadges] = useState<Set<string>>(new Set());
  const [flashCircles, setFlashCircles] = useState<Set<string>>(new Set());

  const latticeNodes = useLatticeStore((s) => s.nodes);
  const sessionLabels = useGovernanceStore((s) => s.sessionLabels);

  const latticeArr = Array.from(latticeNodes.values());

  const sessionArr = Array.from(
    sessionLabels instanceof Map
      ? sessionLabels.values()
      : Object.values(sessionLabels as Record<string, unknown>),
  ) as Array<{
    sessionId: string;
    label: { confidentiality: number; integrity: number; categories: number };
    state: string;
  }>;

  const latticeIds = new Set(latticeArr.map((n) => n.sessionId));
  const extraSessions = sessionArr.filter((s) => !latticeIds.has(s.sessionId));

  const allSessions: SessionEntry[] = [
    ...latticeArr.map((n) => ({
      sessionId: n.sessionId,
      confidentiality: n.label.confidentiality,
      state: n.state,
      escalationCount: n.escalationCount,
    })),
    ...extraSessions.map((s) => ({
      sessionId: s.sessionId,
      confidentiality: s.label?.confidentiality ?? 0,
      state: s.state ?? 'fresh',
      escalationCount: 0,
    })),
  ];

  const byLevel: Record<string, SessionEntry[]> = {};
  for (const s of allSessions) {
    const nodeId = confidentialityToNodeId(s.confidentiality);
    if (!byLevel[nodeId]) byLevel[nodeId] = [];
    byLevel[nodeId].push(s);
  }

  const triggerBadgePulse = useCallback((levelId: string) => {
    const existing = animatingBadgesRef.current.get(levelId);
    if (existing) clearTimeout(existing);
    setPulseBadges((prev) => new Set([...prev, levelId]));
    const t = setTimeout(() => {
      setPulseBadges((prev) => {
        const next = new Set(prev);
        next.delete(levelId);
        return next;
      });
      animatingBadgesRef.current.delete(levelId);
    }, 350);
    animatingBadgesRef.current.set(levelId, t);
  }, []);

  const triggerCircleFlash = useCallback((levelId: string) => {
    const existing = animatingCirclesRef.current.get(levelId);
    if (existing) clearTimeout(existing);
    setFlashCircles((prev) => new Set([...prev, levelId]));
    const t = setTimeout(() => {
      setFlashCircles((prev) => {
        const next = new Set(prev);
        next.delete(levelId);
        return next;
      });
      animatingCirclesRef.current.delete(levelId);
    }, 550);
    animatingCirclesRef.current.set(levelId, t);
  }, []);

  useEffect(() => {
    const prev = previousCountsRef.current;
    for (const level of LATTICE_LEVELS) {
      const currentCount = (byLevel[level.id] ?? []).length;
      const prevCount = prev.get(level.id) ?? 0;
      if (currentCount > prevCount) {
        triggerBadgePulse(level.id);
      } else if (currentCount < prevCount) {
        // sessions left this level — they escalated to another
        const gainingLevel = LATTICE_LEVELS.find(
          (l) => (byLevel[l.id] ?? []).length > (prev.get(l.id) ?? 0),
        );
        if (gainingLevel) triggerCircleFlash(gainingLevel.id);
      }
    }
    const next = new Map<string, number>();
    for (const level of LATTICE_LEVELS) {
      next.set(level.id, (byLevel[level.id] ?? []).length);
    }
    previousCountsRef.current = next;
  });

  useEffect(() => {
    const badges = animatingBadgesRef.current;
    const circles = animatingCirclesRef.current;
    return () => {
      for (const t of badges.values()) clearTimeout(t);
      for (const t of circles.values()) clearTimeout(t);
    };
  }, []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setSelectedLevel(null);
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, []);

  const isEmpty = allSessions.length === 0;

  const handleNodeClick = useCallback(
    (levelId: string) => {
      setSelectedLevel((prev) => (prev === levelId ? null : levelId));
    },
    [],
  );

  const handleNodeKeyDown = useCallback(
    (e: React.KeyboardEvent, levelId: string) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        handleNodeClick(levelId);
      }
    },
    [handleNodeClick],
  );

  const handleSessionRowClick = useCallback((sessionId: string) => {
    useGovernanceStore.getState().setFilterSession(sessionId);
  }, []);

  const nodeY = (levelId: string) =>
    LATTICE_LEVELS.find((l) => l.id === levelId)?.y ?? 0;

  const BADGE_X = NODE_X + 100;

  return (
    <div style={{ width: '100%', minHeight: 400, display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '8px 12px 4px', borderBottom: '1px solid #30363d',
      }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: '#e6edf3' }}>
            Data Classification Lattice
          </div>
          <div style={{ fontSize: 11, color: '#8b949e', marginTop: 1 }}>
            Active sessions grouped by sensitivity ceiling
          </div>
        </div>
        <button
          onClick={() => setShowHelp((h) => !h)}
          aria-pressed={showHelp}
          aria-label="Toggle level descriptions"
          style={{
            background: showHelp ? '#21262d' : 'transparent',
            border: '1px solid #30363d', borderRadius: 4,
            color: '#8b949e', cursor: 'pointer', fontSize: 11,
            padding: '2px 7px',
          }}
        >
          ?
        </button>
      </div>

      {/* Body */}
      <div style={{ position: 'relative', flex: 1 }}>
        <svg
          className="hasse-static"
          width="100%"
          height={SVG_HEIGHT}
          viewBox={`0 0 ${SVG_WIDTH} ${SVG_HEIGHT}`}
          preserveAspectRatio="xMidYMid meet"
          aria-hidden="true"
          style={{ opacity: isEmpty ? 0.3 : 1, display: 'block' }}
        >
          <defs>
            {/* Arrow markers for edges */}
            <marker
              id="hasse-arrow"
              viewBox="0 -5 10 10"
              refX={22} refY={0}
              markerWidth={6} markerHeight={6}
              orient="auto"
            >
              <path d="M0,-5L10,0L0,5" fill="#30363d" />
            </marker>
            {/* Axis arrow markers */}
            <marker
              id="axis-arrow-up"
              viewBox="0 -5 10 10"
              refX={5} refY={0}
              markerWidth={5} markerHeight={5}
              orient="auto"
            >
              <path d="M0,-5L10,0L0,5" fill="#484f58" />
            </marker>
            <marker
              id="axis-arrow-down"
              viewBox="0 -5 10 10"
              refX={5} refY={0}
              markerWidth={5} markerHeight={5}
              orient="270"
            >
              <path d="M0,-5L10,0L0,5" fill="#484f58" />
            </marker>
          </defs>

          {/* Left axis annotation */}
          <line
            x1={20} y1={30}
            x2={20} y2={310}
            stroke="#484f58"
            strokeWidth={1}
            markerStart="url(#axis-arrow-up)"
            markerEnd="url(#axis-arrow-down)"
          />
          <text x={28} y={38} fontSize={8} fill="#484f58" textAnchor="start">
            Higher security
          </text>
          <text x={28} y={318} fontSize={8} fill="#484f58" textAnchor="start">
            Lower security
          </text>

          {/* Edges */}
          {LATTICE_EDGES.map(({ source, target }) => {
            const srcY = nodeY(source);
            const tgtY = nodeY(target);
            const isTop = source === 'restricted';
            return (
              <g key={`${source}-${target}`}>
                <line
                  x1={NODE_X} y1={srcY}
                  x2={NODE_X} y2={tgtY}
                  stroke="#30363d" strokeWidth={1.5}
                  markerEnd="url(#hasse-arrow)"
                />
                {isTop && (
                  <text
                    x={NODE_X + 8}
                    y={(srcY + tgtY) / 2 + 4}
                    fontSize={9}
                    fill="#484f58"
                    opacity={0.5}
                  >
                    flows to
                  </text>
                )}
              </g>
            );
          })}

          {/* Nodes */}
          {LATTICE_LEVELS.map((level) => {
            const sessions = byLevel[level.id] ?? [];
            const count = sessions.length;
            const nonFresh = sessions.filter((s) => s.state !== 'fresh');
            const stateSummary = Object.entries(
              nonFresh.reduce<Record<string, number>>((acc, s) => {
                const key = stateLabel(s.state);
                acc[key] = (acc[key] ?? 0) + 1;
                return acc;
              }, {}),
            )
              .map(([k, v]) => `${v} ${k}`)
              .join(' · ');

            const isFlashing = flashCircles.has(level.id);

            return (
              <g
                key={level.id}
                transform={`translate(${NODE_X}, ${level.y})`}
                role="button"
                tabIndex={0}
                aria-label={`${level.label}: ${count} session${count !== 1 ? 's' : ''}`}
                onClick={() => handleNodeClick(level.id)}
                onKeyDown={(e) => handleNodeKeyDown(e, level.id)}
                style={{ cursor: 'pointer', outline: 'none' }}
              >
                <title>{`${level.label}: ${level.description}`}</title>

                {/* Flash overlay circle for escalation animation */}
                {isFlashing && (
                  <circle
                    r={20}
                    fill={level.color}
                    className="escalation-flash"
                    style={{ pointerEvents: 'none' }}
                  />
                )}

                <circle
                  r={16}
                  fill="#1e2a3a"
                  stroke={level.color}
                  strokeWidth={selectedLevel === level.id ? 3 : 2}
                />
                <text
                  textAnchor="middle"
                  dy="0.35em"
                  fontSize={9}
                  fill={level.color}
                  fontWeight="600"
                  style={{ pointerEvents: 'none' }}
                >
                  {level.label.slice(0, 3).toUpperCase()}
                </text>

                {/* Level name */}
                <text
                  x={22}
                  dy="0.35em"
                  fontSize={11}
                  fill="#e6edf3"
                  style={{ pointerEvents: 'none' }}
                >
                  {level.label}
                </text>

                {/* State breakdown */}
                {stateSummary && (
                  <text
                    x={22}
                    y={14}
                    fontSize={9}
                    fill="#8b949e"
                    style={{ pointerEvents: 'none' }}
                  >
                    {stateSummary}
                  </text>
                )}

                {/* Help tooltip */}
                {showHelp && (
                  <text
                    x={22}
                    y={-16}
                    fontSize={9}
                    fill="#8b949e"
                    style={{ pointerEvents: 'none' }}
                  >
                    {level.description}
                  </text>
                )}

                {/* Count badge */}
                {count > 0 && (
                  <g
                    className={`count-badge${pulseBadges.has(level.id) ? ' count-badge-pulse' : ''}`}
                    transform={`translate(${BADGE_X - NODE_X}, 0)`}
                    data-label-state={sessions[0]?.state}
                    style={{ pointerEvents: 'none' }}
                  >
                    <rect
                      x={-14}
                      y={-9}
                      width={28}
                      height={18}
                      rx={9}
                      fill="#21262d"
                      stroke={level.color}
                      strokeWidth={1}
                    />
                    <text
                      textAnchor="middle"
                      dy="0.35em"
                      fontSize={10}
                      fill={level.color}
                      fontWeight="600"
                    >
                      {count}
                    </text>
                  </g>
                )}
              </g>
            );
          })}
        </svg>

        {/* Empty state overlay */}
        {isEmpty && (
          <div
            className="hasse-overlay"
            style={{
              position: 'absolute',
              top: 0, left: 0, right: 0, bottom: 0,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              pointerEvents: 'none',
            }}
          >
            <div style={{
              color: '#8b949e', fontSize: 12, textAlign: 'center',
              padding: '12px 20px', background: '#161b22',
              border: '1px solid #30363d', borderRadius: 6,
            }}>
              Lattice is idle — sessions will appear as events flow in
            </div>
          </div>
        )}

        {/* Detail panel */}
        {selectedLevel !== null && (() => {
          const level = LATTICE_LEVELS.find((l) => l.id === selectedLevel);
          const sessions = byLevel[selectedLevel] ?? [];
          if (!level) return null;
          return (
            <div
              style={{
                margin: '8px 12px',
                border: '1px solid #30363d',
                borderRadius: 6,
                background: '#161b22',
                overflow: 'hidden',
              }}
              role="listbox"
              aria-label={`${level.label} sessions`}
            >
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '6px 10px', borderBottom: '1px solid #30363d',
              }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: level.color }}>
                  {level.label} ({sessions.length} session{sessions.length !== 1 ? 's' : ''})
                </span>
                <button
                  onClick={() => setSelectedLevel(null)}
                  aria-label="Close detail panel"
                  style={{
                    background: 'transparent', border: 'none',
                    color: '#8b949e', cursor: 'pointer', fontSize: 13, lineHeight: 1,
                  }}
                >
                  ×
                </button>
              </div>
              <div style={{ maxHeight: 120, overflowY: 'auto' }}>
                {sessions.slice(0, 5).map((s) => (
                  <div
                    key={s.sessionId}
                    role="option"
                    aria-selected={false}
                    onClick={() => handleSessionRowClick(s.sessionId)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 8,
                      padding: '5px 10px', cursor: 'pointer', fontSize: 11,
                      borderBottom: '1px solid #21262d',
                    }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLDivElement).style.background = '#21262d';
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLDivElement).style.background = 'transparent';
                    }}
                  >
                    <span style={{ color: '#e6edf3', fontFamily: 'monospace' }}>
                      {s.sessionId.slice(0, 8)}
                    </span>
                    <span style={{
                      width: 8, height: 8, borderRadius: '50%',
                      background: STATE_COLORS[s.state] ?? '#2da44e',
                      flexShrink: 0,
                    }} />
                    <span style={{ color: '#8b949e' }}>{stateLabel(s.state)}</span>
                    <span style={{ marginLeft: 'auto', color: '#484f58' }}>
                      {s.escalationCount} escalation{s.escalationCount !== 1 ? 's' : ''}
                    </span>
                  </div>
                ))}
                {sessions.length > 5 && (
                  <div style={{ padding: '4px 10px', fontSize: 10, color: '#484f58' }}>
                    +{sessions.length - 5} more
                  </div>
                )}
                {sessions.length === 0 && (
                  <div style={{ padding: '8px 10px', fontSize: 11, color: '#8b949e' }}>
                    No sessions at this level
                  </div>
                )}
              </div>
            </div>
          );
        })()}
      </div>

      {/* Footer legend */}
      {!isEmpty && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 16,
          padding: '4px 12px', height: 28, borderTop: '1px solid #30363d',
          fontSize: 10, color: '#8b949e', flexShrink: 0,
        }}>
          {[
            { label: 'fresh', color: '#2da44e' },
            { label: 'escalated', color: '#d29922' },
            { label: 'tainted', color: '#cf222e' },
            { label: 'declassified', color: '#58a6ff' },
          ].map(({ label, color }) => (
            <span key={label} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block' }} />
              {label}
            </span>
          ))}
          <span style={{ marginLeft: 'auto', color: '#484f58' }}>↓ flows down</span>
        </div>
      )}

      {/* Screen-reader list */}
      <ul aria-label="IFC Lattice sessions" style={{ position: 'absolute', left: -9999 }}>
        {allSessions.map((s) => (
          <li key={s.sessionId}>
            Session {s.sessionId}: {confidentialityToLevel(s.confidentiality)} ({s.state})
          </li>
        ))}
      </ul>
    </div>
  );
}
