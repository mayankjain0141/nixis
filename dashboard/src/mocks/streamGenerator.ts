import { type StreamEvent, type Action, EVENT_TYPES, type EventType } from '../types/aegis';

export interface SequenceOptions {
  sessionCount?: number;
  includeTypes?: EventType[];
  includeSecretEvents?: boolean;
  includeLabelEscalations?: boolean;
}

const ALL_ACTIONS: Action[] = ['deny', 'allow', 'require_approval', 'audit'];
const ALL_TOOLS = [
  'Shell', 'Read', 'Write', 'Edit', 'Bash', 'WebFetch', 'WebSearch',
  'GitCommit', 'GitPush', 'FileDelete', 'DatabaseQuery',
];
const ALL_REASONS = [
  '',
  'Force push to protected branch prohibited',
  'Secret detected in output',
  'Label escalation required',
  'Delegation expired',
  'Policy denied: high-risk operation',
];

// Knuth multiplicative hash kept in uint32 range to avoid float precision loss.
function lcg(seed: number): number {
  return ((seed * 1664525 + 1013904223) >>> 0);
}

function makeLabel(seed: number) {
  const s = seed >>> 0;
  const conf = (s % 4) * 16384;
  const integ = ((s >>> 4) % 4) * 16384;
  const cat = (s >>> 8) % 8;
  return { confidentiality: conf, integrity: integ, categories: cat };
}

function makeSessionId(index: number): string {
  return `sess_${index.toString(16).padStart(8, '0')}`;
}

export function createMockStreamEvent(overrides?: Partial<StreamEvent>): StreamEvent {
  // Use a local counter that is independent of any sequence generator.
  createMockStreamEvent._localSeq = (createMockStreamEvent._localSeq ?? 0) + 1;
  const seq = createMockStreamEvent._localSeq;
  const seed = lcg(seq ^ (Date.now() & 0xffffffff));
  const base: StreamEvent = {
    type: EVENT_TYPES.DECISION,
    aegisSequence: seq,
    sessionId: makeSessionId(seed % 16),
    tool: ALL_TOOLS[(seed >>> 4) % ALL_TOOLS.length],
    action: ALL_ACTIONS[(seed >>> 8) % ALL_ACTIONS.length],
    reason: ALL_REASONS[(seed >>> 12) % ALL_REASONS.length],
    label: makeLabel(seed >>> 16),
    timestamp: Date.now() * 1_000_000,
  };
  return { ...base, ...overrides };
}
createMockStreamEvent._localSeq = 0;

export function createMockEventSequence(count: number, options: SequenceOptions = {}): StreamEvent[] {
  const {
    sessionCount = 2,
    includeTypes,
    includeSecretEvents = true,
    includeLabelEscalations = true,
  } = options;

  let types: EventType[] = includeTypes ?? (Object.values(EVENT_TYPES) as EventType[]);

  if (!includeSecretEvents) {
    types = types.filter(t => t !== EVENT_TYPES.SECRET_FOUND);
  }
  if (!includeLabelEscalations) {
    types = types.filter(t => t !== EVENT_TYPES.LABEL_ESCALATED && t !== EVENT_TYPES.LABEL_TAINTED);
  }
  if (types.length === 0) {
    types = [EVENT_TYPES.DECISION];
  }

  const events: StreamEvent[] = [];

  for (let i = 0; i < count; i++) {
    const seed = lcg(i);
    // Round-robin over type and session arrays to guarantee full coverage regardless of count.
    const typeIndex = i % types.length;
    const sessionIndex = i % sessionCount;
    const actionIndex = (seed >>> 4) % ALL_ACTIONS.length;
    const toolIndex = (seed >>> 8) % ALL_TOOLS.length;
    const reasonIndex = (seed >>> 12) % ALL_REASONS.length;

    events.push({
      type: types[typeIndex],
      aegisSequence: i + 1, // 1-indexed, strictly monotonic, independent of other generators
      sessionId: makeSessionId(sessionIndex),
      tool: ALL_TOOLS[toolIndex],
      action: ALL_ACTIONS[actionIndex],
      reason: ALL_REASONS[reasonIndex],
      label: makeLabel(seed >>> 16),
      timestamp: (Date.now() + i * 100) * 1_000_000,
    });
  }

  return events;
}

export interface MockStreamGenerator {
  start(): void;
  stop(): void;
  onEvent(cb: (e: StreamEvent) => void): void;
}

export function createMockStreamGenerator(intervalMs: number): MockStreamGenerator {
  let timer: ReturnType<typeof setInterval> | null = null;
  // Private counter; never shared with createMockStreamEvent or createMockEventSequence.
  let seq = 0;
  const listeners: Array<(e: StreamEvent) => void> = [];
  const allTypes = Object.values(EVENT_TYPES) as EventType[];

  function emit(): void {
    seq++;
    // Keep arithmetic in uint32 to avoid float imprecision for large seq values.
    const seed = lcg(seq);
    // Round-robin type so coverage is guaranteed without requiring a large sample.
    const typeIndex = (seq - 1) % allTypes.length;
    const actionIndex = (seed >>> 3) % ALL_ACTIONS.length;
    const toolIndex = (seed >>> 7) % ALL_TOOLS.length;

    const event: StreamEvent = {
      type: allTypes[typeIndex],
      aegisSequence: seq,
      sessionId: makeSessionId((seed >>> 11) % 3),
      tool: ALL_TOOLS[toolIndex],
      action: ALL_ACTIONS[actionIndex],
      reason: '',
      label: makeLabel(seed >>> 15),
      timestamp: Date.now() * 1_000_000,
    };

    for (const cb of listeners) {
      cb(event);
    }
  }

  return {
    start() {
      if (timer !== null) return;
      timer = setInterval(emit, intervalMs);
    },
    stop() {
      if (timer !== null) {
        clearInterval(timer);
        timer = null;
      }
    },
    onEvent(cb: (e: StreamEvent) => void) {
      listeners.push(cb);
    },
  };
}
