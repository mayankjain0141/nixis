import { useCallback, useEffect, useRef, useState } from 'react';
import { useUIStore } from '../../stores/ui-store';
import { useGovernanceStore } from '../../stores/governance-store';
import { useStreamStore } from '../../stores/stream-store';

interface Command {
  id: string;
  label: string;
  category: string;
  action: () => void;
}

function buildCommands(
  setFilter: (verdict: string | null) => void,
  reconnect: () => void,
  startMock: () => void,
  stopMock: () => void,
  setCommandPaletteOpen: (open: boolean) => void,
): Command[] {
  return [
    {
      id: 'filter-deny',
      label: 'Filter: Show deny events only',
      category: 'Filter',
      action: () => setFilter('deny'),
    },
    {
      id: 'filter-allow',
      label: 'Filter: Show allow events only',
      category: 'Filter',
      action: () => setFilter('allow'),
    },
    {
      id: 'filter-clear',
      label: 'Filter: Clear all filters',
      category: 'Filter',
      action: () => setFilter(null),
    },
    {
      id: 'panel-stream',
      label: 'Go to: Event Stream',
      category: 'Navigation',
      action: () => {
        // Navigation panels are future work — close palette only for now.
        setCommandPaletteOpen(false);
      },
    },
    {
      id: 'panel-inspector',
      label: 'Go to: Inspector',
      category: 'Navigation',
      action: () => {
        setCommandPaletteOpen(false);
      },
    },
    {
      id: 'connect',
      label: 'Connection: Reconnect to daemon',
      category: 'Connection',
      action: reconnect,
    },
    {
      id: 'mock-start',
      label: 'Demo: Start mock event stream',
      category: 'Demo',
      action: startMock,
    },
    {
      id: 'mock-stop',
      label: 'Demo: Stop mock event stream',
      category: 'Demo',
      action: stopMock,
    },
  ];
}

function matchesQuery(label: string, query: string): boolean {
  if (query === '') return true;
  return label.toLowerCase().includes(query.toLowerCase());
}

export function CommandPalette(): React.ReactElement | null {
  const commandPaletteOpen = useUIStore((s) => s.commandPaletteOpen);
  const setCommandPaletteOpen = useUIStore((s) => s.setCommandPaletteOpen);
  const setConnectionState = useStreamStore((s) => s.setConnectionState);
  const clearEvents = useGovernanceStore((s) => s.clear);

  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const close = useCallback(() => {
    setCommandPaletteOpen(false);
    setQuery('');
    setSelectedIndex(0);
  }, [setCommandPaletteOpen]);

  const commands = buildCommands(
    (_verdict) => {
      // Filter actions: governance store filter will be wired when filter state lands.
      close();
    },
    () => {
      setConnectionState('RECONNECTING');
      close();
    },
    () => {
      close();
    },
    () => {
      clearEvents();
      close();
    },
    setCommandPaletteOpen,
  );

  const filtered = commands.filter((c) => matchesQuery(c.label, query));

  const groupedByCategory = filtered.reduce<Map<string, Command[]>>((acc, cmd) => {
    const group = acc.get(cmd.category) ?? [];
    group.push(cmd);
    acc.set(cmd.category, group);
    return acc;
  }, new Map());

  const flatFiltered = Array.from(groupedByCategory.values()).flat();

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  useEffect(() => {
    if (commandPaletteOpen) {
      setQuery('');
      setSelectedIndex(0);
      requestAnimationFrame(() => {
        inputRef.current?.focus();
      });
    }
  }, [commandPaletteOpen]);

  const execute = useCallback(
    (cmd: Command) => {
      cmd.action();
      close();
    },
    [close],
  );

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
        if (cmd) execute(cmd);
        return;
      }
    },
    [close, execute, flatFiltered, selectedIndex],
  );

  if (!commandPaletteOpen) return null;

  let flatIndex = 0;

  return (
    <div
      style={styles.backdrop}
      onClick={close}
      aria-hidden="false"
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
          onChange={(e) => setQuery(e.target.value)}
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
                    onClick={() => execute(cmd)}
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
