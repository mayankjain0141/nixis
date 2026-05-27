import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  createMockStreamEvent,
  createMockEventSequence,
  createMockStreamGenerator,
} from './streamGenerator';
import { EVENT_TYPES } from '../types/aegis';
import type { Action } from '../types/aegis';

const VALID_ACTIONS = new Set<Action>(['deny', 'allow', 'require_approval', 'audit']);
const ALL_EVENT_TYPES = new Set(Object.values(EVENT_TYPES));

describe('createMockStreamEvent', () => {
  it('returns a valid StreamEvent with all required fields', () => {
    const event = createMockStreamEvent();
    expect(event.type).toBeDefined();
    expect(ALL_EVENT_TYPES.has(event.type as never)).toBe(true);
    expect(typeof event.aegisSequence).toBe('number');
    expect(event.aegisSequence).toBeGreaterThan(0);
    expect(VALID_ACTIONS.has(event.action)).toBe(true);
    expect(typeof event.sessionId).toBe('string');
    expect(typeof event.label.confidentiality).toBe('number');
    expect(typeof event.label.integrity).toBe('number');
    expect(typeof event.label.category).toBe('number');
  });

  it('applies overrides correctly', () => {
    const event = createMockStreamEvent({ type: EVENT_TYPES.SYSTEM_ERROR, action: 'deny' });
    expect(event.type).toBe(EVENT_TYPES.SYSTEM_ERROR);
    expect(event.action).toBe('deny');
  });

  it('never generates content_publish action', () => {
    for (let i = 0; i < 50; i++) {
      const event = createMockStreamEvent();
      expect((event.action as string)).not.toBe('content_publish');
    }
  });
});

describe('createMockEventSequence', () => {
  it('generates the requested count of events', () => {
    const events = createMockEventSequence(20);
    expect(events).toHaveLength(20);
  });

  it('aegisSequence is monotonically increasing', () => {
    const events = createMockEventSequence(100);
    for (let i = 1; i < events.length; i++) {
      expect(events[i].aegisSequence).toBeGreaterThan(events[i - 1].aegisSequence);
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

  it('covers all 12 canonical event types across a large sequence', () => {
    const events = createMockEventSequence(240);
    const seen = new Set(events.map(e => e.type));
    for (const t of Object.values(EVENT_TYPES)) {
      expect(seen.has(t), `Event type ${t} was not generated`).toBe(true);
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

  it('SecurityLabel fields are always numeric', () => {
    const events = createMockEventSequence(50);
    for (const e of events) {
      expect(typeof e.label.confidentiality).toBe('number');
      expect(typeof e.label.integrity).toBe('number');
      expect(typeof e.label.category).toBe('number');
    }
  });

  it('uses multiple sessions when sessionCount > 1', () => {
    const events = createMockEventSequence(100, { sessionCount: 5 });
    const sessions = new Set(events.map(e => e.sessionId));
    expect(sessions.size).toBeGreaterThan(1);
  });
});

describe('createMockStreamGenerator', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('emits events at the configured interval', () => {
    const gen = createMockStreamGenerator(100);
    const received: ReturnType<typeof createMockStreamEvent>[] = [];
    gen.onEvent(e => received.push(e));
    gen.start();
    vi.advanceTimersByTime(350);
    gen.stop();
    expect(received.length).toBe(3);
  });

  it('stops emitting after stop() is called', () => {
    const gen = createMockStreamGenerator(100);
    const received: ReturnType<typeof createMockStreamEvent>[] = [];
    gen.onEvent(e => received.push(e));
    gen.start();
    vi.advanceTimersByTime(200);
    gen.stop();
    const countAfterStop = received.length;
    vi.advanceTimersByTime(500);
    expect(received.length).toBe(countAfterStop);
  });

  it('emitted events use canonical event types', () => {
    const gen = createMockStreamGenerator(50);
    const received: ReturnType<typeof createMockStreamEvent>[] = [];
    gen.onEvent(e => received.push(e));
    gen.start();
    vi.advanceTimersByTime(2400);
    gen.stop();
    for (const e of received) {
      expect(ALL_EVENT_TYPES.has(e.type as never)).toBe(true);
    }
  });

  it('emitted events have monotonically increasing aegisSequence', () => {
    const gen = createMockStreamGenerator(50);
    const received: ReturnType<typeof createMockStreamEvent>[] = [];
    gen.onEvent(e => received.push(e));
    gen.start();
    vi.advanceTimersByTime(1000);
    gen.stop();
    for (let i = 1; i < received.length; i++) {
      expect(received[i].aegisSequence).toBeGreaterThan(received[i - 1].aegisSequence);
    }
  });

  it('notifies all registered listeners', () => {
    const gen = createMockStreamGenerator(100);
    const a: number[] = [];
    const b: number[] = [];
    gen.onEvent(() => a.push(1));
    gen.onEvent(() => b.push(1));
    gen.start();
    vi.advanceTimersByTime(100);
    gen.stop();
    expect(a.length).toBe(1);
    expect(b.length).toBe(1);
  });
});
