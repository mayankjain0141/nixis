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

let _seq = 0;

function nextSeq(): number {
  return ++_seq;
}

function pickRandom<T>(arr: T[], seed: number): T {
  return arr[Math.abs(seed) % arr.length];
}

function makeLabel(seed: number) {
  const conf = (seed % 4) * 16384;
  const integ = ((seed >> 2) % 4) * 16384;
  const cat = (seed >> 4) % 8;
  return { confidentiality: conf, integrity: integ, category: cat };
}

function makeSessionId(index: number): string {
  return `sess_${index.toString(16).padStart(8, '0')}`;
}

export function createMockStreamEvent(overrides?: Partial<StreamEvent>): StreamEvent {
  const seed = Date.now() ^ (Math.random() * 0xffffffff | 0);
  const base: StreamEvent = {
    type: EVENT_TYPES.DECISION,
    aegisSequence: nextSeq(),
    sessionId: makeSessionId(seed & 0xf),
    tool: pickRandom(ALL_TOOLS, seed),
    action: pickRandom(ALL_ACTIONS, seed >> 4),
    reason: pickRandom(ALL_REASONS, seed >> 8),
    label: makeLabel(seed >> 12),
    timestamp: Date.now() * 1_000_000,
  };
  return { ...base, ...overrides };
}

export function createMockEventSequence(count: number, options: SequenceOptions = {}): StreamEvent[] {
  const {
    sessionCount = 2,
    includeTypes,
    includeSecretEvents = true,
    includeLabelEscalations = true,
  } = options;

  let types: EventType[] = includeTypes ?? Object.values(EVENT_TYPES) as EventType[];

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
  let seq = 0;

  for (let i = 0; i < count; i++) {
    // Use LCG-style mixing to distribute values, but round-robin event types
    // to guarantee full type coverage regardless of count.
    const seed = (i * 1664525 + 1013904223) >>> 0;
    const sessionIndex = i % sessionCount; // round-robin sessions to guarantee diversity
    const typeIndex = i % types.length;    // round-robin guarantees all types covered
    const actionIndex = (seed >> 4) % ALL_ACTIONS.length;
    const toolIndex = (seed >> 8) % ALL_TOOLS.length;
    const reasonIndex = (seed >> 12) % ALL_REASONS.length;

    seq++;
    events.push({
      type: types[typeIndex],
      aegisSequence: seq,
      sessionId: makeSessionId(sessionIndex),
      tool: ALL_TOOLS[toolIndex],
      action: ALL_ACTIONS[actionIndex],
      reason: ALL_REASONS[reasonIndex],
      label: makeLabel((seed >> 16) & 0xffff),
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
  let seq = 0;
  const listeners: Array<(e: StreamEvent) => void> = [];

  const allTypes = Object.values(EVENT_TYPES) as EventType[];

  function emit(): void {
    seq++;
    const seed = seq * 2654435761;
    const typeIndex = Math.abs(seed) % allTypes.length;
    const actionIndex = Math.abs(seed >> 3) % ALL_ACTIONS.length;
    const toolIndex = Math.abs(seed >> 7) % ALL_TOOLS.length;

    const event: StreamEvent = {
      type: allTypes[typeIndex],
      aegisSequence: seq,
      sessionId: makeSessionId(Math.abs(seed >> 11) % 3),
      tool: ALL_TOOLS[toolIndex],
      action: ALL_ACTIONS[actionIndex],
      reason: '',
      label: makeLabel(Math.abs(seed >> 15)),
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
