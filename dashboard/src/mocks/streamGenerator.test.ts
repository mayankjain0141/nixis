import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  createMockStreamEvent,
  createMockEventSequence,
  createMockStreamGenerator,
} from './streamGenerator';
import { EVENT_TYPES } from '../types/aegis';
import type { Action, StreamEvent } from '../types/aegis';

const VALID_ACTIONS = new Set<Action>(['deny', 'allow', 'require_approval', 'audit']);
const ALL_EVENT_TYPES = new Set(Object.values(EVENT_TYPES));

describe('createMockStreamEvent', () => {
  it('returns a valid StreamEvent with all required fields', () => {
    const event = createMockStreamEvent();
    expect(ALL_EVENT_TYPES.has(event.type as never)).toBe(true);
    expect(typeof event.aegisSequence).toBe('number');
    expect(event.aegisSequence).toBeGreaterThan(0);
    expect(VALID_ACTIONS.has(event.action)).toBe(true);
    expect(typeof event.sessionId).toBe('string');
    expect(event.sessionId.length).toBeGreaterThan(0);
    expect(typeof event.label.confidentiality).toBe('number');
    expect(typeof event.label.integrity).toBe('number');
    expect(typeof event.label.category).toBe('number');
    expect(typeof event.timestamp).toBe('number');
  });

  it('applies overrides correctly', () => {
    const event = createMockStreamEvent({ type: EVENT_TYPES.SYSTEM_ERROR, action: 'deny' });
    expect(event.type).toBe(EVENT_TYPES.SYSTEM_ERROR);
    expect(event.action).toBe('deny');
  });

  it('overrides do not affect unspecified fields', () => {
    const event = createMockStreamEvent({ action: 'deny' });
    expect(event.type).toBeDefined();
    expect(event.sessionId).toBeDefined();
    expect(event.label).toBeDefined();
  });

  it('aegisSequence is positive and increases across successive calls', () => {
    const a = createMockStreamEvent();
    const b = createMockStreamEvent();
    expect(b.aegisSequence).toBeGreaterThan(a.aegisSequence);
  });

  it('never generates a non-canonical action', () => {
    for (let i = 0; i < 50; i++) {
      expect(VALID_ACTIONS.has(createMockStreamEvent().action)).toBe(true);
    }
  });
});

describe('createMockEventSequence', () => {
  it('generates the requested count of events', () => {
    const events = createMockEventSequence(20);
    expect(events).toHaveLength(20);
  });

  it('returns an empty array for count = 0', () => {
    expect(createMockEventSequence(0)).toHaveLength(0);
  });

  it('aegisSequence starts at 1 and is strictly monotonically increasing', () => {
    const events = createMockEventSequence(100);
    expect(events[0].aegisSequence).toBe(1);
    for (let i = 1; i < events.length; i++) {
      expect(events[i].aegisSequence).toBe(events[i - 1].aegisSequence + 1);
    }
  });

  it('all generated actions are canonical', () => {
    const events = createMockEventSequence(200);
    for (const e of events) {
      expect(VALID_ACTIONS.has(e.action)).toBe(true);
    }
  });

  it('all event types are canonical', () => {
    const events = createMockEventSequence(200);
    for (const e of events) {
      expect(ALL_EVENT_TYPES.has(e.type as never)).toBe(true);
    }
  });

  it('covers all 12 canonical event types when count >= 12', () => {
    // Round-robin assignment: 12 events is sufficient to see all 12 types.
    const events = createMockEventSequence(12);
    const seen = new Set(events.map(e => e.type));
    for (const t of Object.values(EVENT_TYPES)) {
      expect(seen.has(t), `Event type "${t}" was not generated`).toBe(true);
    }
  });

  it('excludes secret events when includeSecretEvents=false', () => {
    const events = createMockEventSequence(200, { includeSecretEvents: false });
    for (const e of events) {
      expect(e.type).not.toBe(EVENT_TYPES.SECRET_FOUND);
    }
  });

  it('excludes label escalations when includeLabelEscalations=false', () => {
    const events = createMockEventSequence(200, { includeLabelEscalations: false });
    for (const e of events) {
      expect(e.type).not.toBe(EVENT_TYPES.LABEL_ESCALATED);
      expect(e.type).not.toBe(EVENT_TYPES.LABEL_TAINTED);
    }
  });

  it('respects includeTypes filter', () => {
    const types = [EVENT_TYPES.DECISION, EVENT_TYPES.SYSTEM_ERROR];
    const events = createMockEventSequence(50, { includeTypes: types });
    for (const e of events) {
      expect(types).toContain(e.type);
    }
  });

  it('falls back to DECISION when all types are filtered out', () => {
    // Exclude both secrets and escalations on a two-type includeTypes list
    // that only has those two types — triggers the empty-fallback path.
    const events = createMockEventSequence(10, {
      includeTypes: [EVENT_TYPES.SECRET_FOUND, EVENT_TYPES.LABEL_ESCALATED],
      includeSecretEvents: false,
      includeLabelEscalations: false,
    });
    for (const e of events) {
      expect(e.type).toBe(EVENT_TYPES.DECISION);
    }
  });

  it('SecurityLabel fields are always numeric', () => {
    const events = createMockEventSequence(50);
    for (const e of events) {
      expect(typeof e.label.confidentiality).toBe('number');
      expect(typeof e.label.integrity).toBe('number');
      expect(typeof e.label.category).toBe('number');
    }
  });

  it('produces diverse sessionIds when sessionCount > 1', () => {
    const events = createMockEventSequence(10, { sessionCount: 5 });
    const sessions = new Set(events.map(e => e.sessionId));
    expect(sessions.size).toBeGreaterThan(1);
  });

  it('produces one sessionId when sessionCount=1', () => {
    const events = createMockEventSequence(20, { sessionCount: 1 });
    const sessions = new Set(events.map(e => e.sessionId));
    expect(sessions.size).toBe(1);
  });
});

describe('createMockStreamGenerator', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('emits one event per interval tick', () => {
    const gen = createMockStreamGenerator(100);
    const received: StreamEvent[] = [];
    gen.onEvent(e => received.push(e));
    gen.start();
    // Advance by exactly 4 full intervals; setInterval fires at 100, 200, 300, 400.
    vi.advanceTimersByTime(400);
    gen.stop();
    expect(received.length).toBe(4);
  });

  it('stops emitting after stop() is called', () => {
    const gen = createMockStreamGenerator(100);
    const received: StreamEvent[] = [];
    gen.onEvent(e => received.push(e));
    gen.start();
    vi.advanceTimersByTime(200);
    gen.stop();
    const countAfterStop = received.length;
    vi.advanceTimersByTime(500);
    expect(received.length).toBe(countAfterStop);
  });

  it('calling start() twice does not create a second timer', () => {
    const gen = createMockStreamGenerator(100);
    const received: StreamEvent[] = [];
    gen.onEvent(e => received.push(e));
    gen.start();
    gen.start(); // second call is a no-op
    vi.advanceTimersByTime(200);
    gen.stop();
    expect(received.length).toBe(2); // exactly 2, not 4
  });

  it('emitted events use canonical event types', () => {
    const gen = createMockStreamGenerator(50);
    const received: StreamEvent[] = [];
    gen.onEvent(e => received.push(e));
    gen.start();
    vi.advanceTimersByTime(2400);
    gen.stop();
    for (const e of received) {
      expect(ALL_EVENT_TYPES.has(e.type as never)).toBe(true);
    }
  });

  it('covers all 12 canonical event types given enough ticks', () => {
    const gen = createMockStreamGenerator(50);
    const received: StreamEvent[] = [];
    gen.onEvent(e => received.push(e));
    gen.start();
    // 12 types, round-robin: 12 ticks × 50ms = 600ms
    vi.advanceTimersByTime(600);
    gen.stop();
    const seen = new Set(received.map(e => e.type));
    for (const t of Object.values(EVENT_TYPES)) {
      expect(seen.has(t), `Generator never emitted event type "${t}"`).toBe(true);
    }
  });

  it('emitted events have strictly monotonically increasing aegisSequence', () => {
    const gen = createMockStreamGenerator(50);
    const received: StreamEvent[] = [];
    gen.onEvent(e => received.push(e));
    gen.start();
    vi.advanceTimersByTime(1000);
    gen.stop();
    for (let i = 1; i < received.length; i++) {
      expect(received[i].aegisSequence).toBeGreaterThan(received[i - 1].aegisSequence);
    }
  });

  it('notifies all registered listeners on each tick', () => {
    const gen = createMockStreamGenerator(100);
    const a: number[] = [];
    const b: number[] = [];
    gen.onEvent(() => a.push(1));
    gen.onEvent(() => b.push(1));
    gen.start();
    vi.advanceTimersByTime(300);
    gen.stop();
    expect(a.length).toBe(3);
    expect(b.length).toBe(3);
  });

  it('emitted events have canonical actions only', () => {
    const gen = createMockStreamGenerator(50);
    const received: StreamEvent[] = [];
    gen.onEvent(e => received.push(e));
    gen.start();
    vi.advanceTimersByTime(1000);
    gen.stop();
    for (const e of received) {
      expect(VALID_ACTIONS.has(e.action)).toBe(true);
    }
  });
});
