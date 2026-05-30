import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useUIStore } from '../../stores/ui-store';
import { useGovernanceStore } from '../../stores/governance-store';
import { useStreamStore } from '../../stores/stream-store';

interface Command {
  id: string;
  category: 'navigation' | 'search' | 'action' | 'filter' | 'time-travel' | 'debug';
  label: string;
  keywords: string[];
  execute: (params?: unknown) => Promise<void>;
}

function fuzzyMatch(query: string, target: string, keywords: string[]): boolean {
  if (query === '') return true;
  const q = query.toLowerCase();
  const t = target.toLowerCase();
  const kw = keywords.join(' ').toLowerCase();
  if (t.includes(q) || kw.includes(q)) return true;
  // character subsequence match
  let qi = 0;
  for (let i = 0; i < t.length && qi < q.length; i++) {
    if (t[i] === q[qi]) qi++;
  }
  return qi === q.length;
}

function buildStaticCommands(
  setFilterVerdict: (verdict: string | null) => void,
  connectionState: string,
  startMock: () => void,
  stopMock: () => void,
  setCommandPaletteOpen: (open: boolean) => void,
  close: () => void,
): Command[] {
  return [
    {
      id: 'filter-deny',
      label: 'Filter: Show denials only',
      category: 'filter',
      keywords: ['deny', 'block', 'filter', 'show', 'denial'],
      execute: async () => { setFilterVerdict('deny'); close(); },
    },
    {
      id: 'filter-allow',
      label: 'Filter: Show allow events only',
      category: 'filter',
      keywords: ['allow', 'pass', 'permit', 'filter', 'show'],
      execute: async () => { setFilterVerdict('allow'); close(); },
    },
    {
      id: 'filter-require_approval',
      label: 'Filter: Show require_approval only',
      category: 'filter',
      keywords: ['approval', 'require', 'hitl'],
      execute: async () => { setFilterVerdict('require_approval'); close(); },
    },
    {
      id: 'filter-audit',
      label: 'Filter: Show audit events only',
      category: 'filter',
      keywords: ['audit', 'checkpoint'],
      execute: async () => { setFilterVerdict('audit'); close(); },
    },
    {
      id: 'filter-clear',
      label: 'Filter: Clear all filters',
      category: 'filter',
      keywords: ['clear', 'reset', 'all', 'filter', 'remove', 'show all'],
      execute: async () => { setFilterVerdict(null); close(); },
    },
    {
      id: 'panel-stream',
      label: 'Go to: Event Stream',
      category: 'navigation',
      keywords: ['go', 'navigate', 'event', 'stream', 'panel', 'jump'],
      execute: async () => {
        window.dispatchEvent(new CustomEvent('aegis:navigate', { detail: { panel: 'events' } }));
        setCommandPaletteOpen(false);
      },
    },
    {
      id: 'panel-inspector',
      label: 'Go to: Inspector',
      category: 'navigation',
      keywords: ['go', 'navigate', 'inspector', 'panel', 'jump', 'detail'],
      execute: async () => {
        window.dispatchEvent(new CustomEvent('aegis:navigate', { detail: { panel: 'inspector' } }));
        setCommandPaletteOpen(false);
      },
    },
    {
      id: 'panel-lattice',
      label: 'Go to: IFC Lattice',
      category: 'navigation',
      keywords: ['lattice', 'ifc', 'label'],
      execute: async () => {
        window.dispatchEvent(new CustomEvent('aegis:navigate', { detail: { panel: 'lattice' } }));
        close();
      },
    },
    {
      id: 'panel-metrics',
      label: 'Go to: Metrics',
      category: 'navigation',
      keywords: ['metrics', 'stats', 'throughput'],
      execute: async () => {
        window.dispatchEvent(new CustomEvent('aegis:navigate', { detail: { panel: 'metrics' } }));
        close();
      },
    },
    {
      id: 'panel-threats',
      label: 'Go to: Threats',
      category: 'navigation',
      keywords: ['threats', 'secrets', 'drift'],
      execute: async () => {
        window.dispatchEvent(new CustomEvent('aegis:navigate', { detail: { panel: 'threats' } }));
        close();
      },
    },
    {
      id: 'nav-agents',
      label: 'Go to: Agents',
      category: 'navigation',
      keywords: ['agents', 'sessions', 'delegation'],
      execute: async () => {
        window.dispatchEvent(new CustomEvent('aegis:navigate', { detail: { panel: 'agents' } }));
        close();
      },
    },
    {
      id: 'tt-live',
      label: 'Time travel: Return to live',
      category: 'time-travel',
      keywords: ['live', 'latest', 'now', 'resume'],
      execute: async () => {
        const ui = useUIStore.getState() as { isPaused?: boolean; togglePause?: () => void };
        if (ui.isPaused) ui.togglePause?.();
        window.dispatchEvent(new CustomEvent('aegis:scroll-to-bottom'));
        close();
      },
    },
    {
      id: 'tt-pause',
      label: 'Time travel: Pause stream here',
      category: 'time-travel',
      keywords: ['pause', 'freeze', 'stop'],
      execute: async () => {
        (useUIStore.getState() as { togglePause?: () => void }).togglePause?.();
        close();
      },
    },
    {
      id: 'connect',
      label: connectionState === 'MOCK'
        ? 'Connection: Switch to daemon mode'
        : 'Connection: Reconnect to daemon',
      category: 'action',
      keywords: ['connect', 'reconnect', 'daemon', 'websocket', 'ws'],
      execute: async () => {
        if (connectionState === 'MOCK') {
          useStreamStore.getState().setRequestMockMode(false);
        }
        window.dispatchEvent(new CustomEvent('aegis:reconnect'));
        close();
      },
    },
    {
      id: 'mock-start',
      label: 'Demo: Start mock event stream',
      category: 'debug',
      keywords: ['demo', 'mock', 'start', 'simulate', 'test', 'fake'],
      execute: async () => { startMock(); },
    },
    {
      id: 'mock-stop',
      label: 'Demo: Stop mock event stream',
      category: 'debug',
      keywords: ['demo', 'mock', 'stop', 'halt', 'end', 'fake'],
      execute: async () => { stopMock(); },
    },
  ];
}

// CommandPaletteContent is remounted (via key) each time the palette opens,
// giving fresh state without any setState-in-effect workarounds.
function CommandPaletteContent({
  onClose,
}: {
  onClose: () => void;
}): React.ReactElement {
  const setCommandPaletteOpen = useUIStore((s) => s.setCommandPaletteOpen);
  const connectionState = useStreamStore((s) => s.connectionState);
  const setFilterVerdict = useGovernanceStore((s) => s.setFilterVerdict);

  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // Focus on mount — this is a real DOM side-effect, effect is correct here.
  useEffect(() => {
    requestAnimationFrame(() => {
      inputRef.current?.focus();
    });
  }, []);

  const close = useCallback(() => {
    onClose();
  }, [onClose]);

  const staticCommands = useMemo(
    () => buildStaticCommands(
      setFilterVerdict,
      connectionState,
      () => {
        useStreamStore.getState().setRequestMockMode(true);
        close();
      },
      () => {
        useStreamStore.getState().setRequestMockMode(false);
        useGovernanceStore.getState().clear();
        close();
      },
      setCommandPaletteOpen,
      close,
    ),
    [setFilterVerdict, connectionState, close, setCommandPaletteOpen],
  );

  const allCommands = useMemo(() => {
    if (query.length <= 2) return staticCommands;
    const eventCommands: Command[] = useGovernanceStore.getState().events
      .filter((e) => fuzzyMatch(query, e.tool, [e.sessionId, e.policyId ?? '']))
      .slice(0, 5)
      .map((e) => ({
        id: `event-${e.id}`,
        label: `${e.tool} — ${e.verdict}`,
        category: 'search' as const,
        keywords: [e.tool, e.sessionId],
        execute: async () => {
          useUIStore.getState().openInspector(e.id);
          close();
        },
      }));
    return [...staticCommands, ...eventCommands];
  }, [query, staticCommands, close]);

  const { groupedByCategory, flatFiltered } = useMemo(() => {
    const filtered = allCommands.filter((c) => fuzzyMatch(query, c.label, c.keywords));
    const grouped = filtered.reduce<Map<string, Command[]>>((acc, cmd) => {
      const group = acc.get(cmd.category) ?? [];
      group.push(cmd);
      acc.set(cmd.category, group);
      return acc;
    }, new Map());
    return { groupedByCategory: grouped, flatFiltered: Array.from(grouped.values()).flat() };
  }, [allCommands, query]);

  const executeCmd = useCallback(
    async (cmd: Command) => {
      await cmd.execute();
      close();
    },
    [close],
  );

  const handleQueryChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setQuery(e.target.value);
    setSelectedIndex(0);
  }, []);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        close();
        return;
      }
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex((i) => Math.min(i + 1, flatFiltered.length - 1));
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex((i) => Math.max(i - 1, 0));
        return;
      }
      if (e.key === 'Enter') {
        e.preventDefault();
        const cmd = flatFiltered[selectedIndex];
        if (cmd) void executeCmd(cmd);
        return;
      }
    },
    [close, executeCmd, flatFiltered, selectedIndex],
  );

  let flatIndex = 0;

  return (
    <div
      style={styles.backdrop}
      onClick={close}
    >
      <div
        role="dialog"
        aria-label="Command palette"
        aria-modal="true"
        style={styles.modal}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        <input
          ref={inputRef}
          type="text"
          placeholder="Type a command..."
          value={query}
          onChange={handleQueryChange}
          style={styles.input}
          aria-label="Search commands"
          aria-autocomplete="list"
          aria-controls="command-palette-results"
          aria-activedescendant={
            flatFiltered[selectedIndex] ? `cmd-${flatFiltered[selectedIndex].id}` : undefined
          }
        />
        <div
          id="command-palette-results"
          role="listbox"
          aria-label="Commands"
          style={styles.results}
        >
          {flatFiltered.length === 0 && (
            <div style={styles.empty}>No commands match</div>
          )}
          {Array.from(groupedByCategory.entries()).map(([category, cmds]) => (
            <div key={category} role="group" aria-label={category}>
              <div style={styles.categoryLabel}>{category}</div>
              {cmds.map((cmd) => {
                const itemIndex = flatIndex++;
                const isSelected = itemIndex === selectedIndex;
                return (
                  <div
                    key={cmd.id}
                    id={`cmd-${cmd.id}`}
                    role="option"
                    aria-selected={isSelected}
                    style={{
                      ...styles.item,
                      ...(isSelected ? styles.itemSelected : {}),
                    }}
                    onClick={() => void executeCmd(cmd)}
                    onMouseEnter={() => setSelectedIndex(itemIndex)}
                  >
                    {cmd.label}
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function CommandPalette(): React.ReactElement | null {
  const commandPaletteOpen = useUIStore((s) => s.commandPaletteOpen);
  const setCommandPaletteOpen = useUIStore((s) => s.setCommandPaletteOpen);

  if (!commandPaletteOpen) return null;

  return (
    <CommandPaletteContent
      key={String(commandPaletteOpen)}
      onClose={() => setCommandPaletteOpen(false)}
    />
  );
}

const styles = {
  backdrop: {
    position: 'fixed' as const,
    inset: 0,
    background: 'rgba(0,0,0,0.5)',
    zIndex: 1000,
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'flex-start',
    paddingTop: '20vh',
  },
  modal: {
    background: '#161b22',
    border: '1px solid #30363d',
    borderRadius: '8px',
    width: '100%',
    maxWidth: '600px',
    overflow: 'hidden',
    boxShadow: '0 16px 48px rgba(0,0,0,0.6)',
  },
  input: {
    width: '100%',
    background: 'transparent',
    border: 'none',
    borderBottom: '1px solid #30363d',
    color: '#e6edf3',
    fontSize: '16px',
    padding: '14px 16px',
    outline: 'none',
    boxSizing: 'border-box' as const,
    fontFamily: 'ui-sans-serif, system-ui, sans-serif',
  },
  results: {
    maxHeight: '400px',
    overflowY: 'auto' as const,
    padding: '8px 0',
  },
  categoryLabel: {
    color: '#57606a',
    fontSize: '10px',
    fontWeight: 600,
    textTransform: 'uppercase' as const,
    letterSpacing: '0.08em',
    padding: '8px 16px 4px',
  },
  item: {
    padding: '8px 16px',
    color: '#e6edf3',
    fontSize: '14px',
    cursor: 'pointer',
    borderRadius: '4px',
    margin: '0 4px',
  },
  itemSelected: {
    background: '#21262d',
  },
  empty: {
    padding: '16px',
    color: '#57606a',
    fontSize: '13px',
    textAlign: 'center' as const,
  },
} as const;
