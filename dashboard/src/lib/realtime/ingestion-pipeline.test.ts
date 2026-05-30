import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createEventIngestionPipeline } from './ingestion-pipeline';
import type { ValidatedEvent } from './ingestion-pipeline';
import type { IWebSocketManager, MessageMeta } from './ws-manager';

const META: MessageMeta = { receivedAt: 0 };
function makeSend() { return vi.fn<IWebSocketManager['send']>(); }

function makePolicyEvaluated(seq: number, id?: string, verdict = 'allow'): string {
  return JSON.stringify({
    type: 'policy.evaluated', id: id ?? `evt-${seq}`, nixissequence: seq,
    data: { tool: 'Shell', session_id: 'sess-1', decision: { action: verdict, reason: '', policy_id: 'pol-1', enforcing_layer: 'adapter', labels: { confidentiality: 0, integrity: 0, categories: 0 } }, label_state: 'fresh', latency_ns: 1000 },
  });
}
function makePolicyDenied(seq: number, id?: string): string {
  return JSON.stringify({
    type: 'policy.denied', id: id ?? `evt-${seq}`, nixissequence: seq,
    data: { tool: 'Shell', session_id: 'sess-1', decision: { action: 'deny', reason: 'Denied', policy_id: 'pol-1', enforcing_layer: 'cel', labels: { confidentiality: 0, integrity: 0, categories: 0 } }, label_state: 'fresh', latency_ns: 2000 },
  });
}

describe('createEventIngestionPipeline', () => {
  describe('JSON parse failures', () => {
    it('discards malformed JSON without throwing', () => {
      const pipeline = createEventIngestionPipeline({ send: makeSend() });
      const received: ValidatedEvent[] = [];
      pipeline.onValidated(e => received.push(e));
      expect(() => pipeline.ingest('{invalid', META)).not.toThrow();
      expect(received).toHaveLength(0);
    });
    it('discards empty string', () => {
      const pipeline = createEventIngestionPipeline({ send: makeSend() });
      const received: ValidatedEvent[] = [];
      pipeline.onValidated(e => received.push(e));
      expect(() => pipeline.ingest('', META)).not.toThrow();
      expect(received).toHaveLength(0);
    });
  });

  describe('Zod envelope validation', () => {
    it('discards events missing nixissequence', () => {
      const pipeline = createEventIngestionPipeline({ send: makeSend() });
      const received: ValidatedEvent[] = [];
      pipeline.onValidated(e => received.push(e));
      pipeline.ingest(JSON.stringify({ type: 'policy.evaluated' }), META);
      expect(received).toHaveLength(0);
    });
    it('accepts a valid policy.evaluated event', () => {
      const pipeline = createEventIngestionPipeline({ send: makeSend() });
      const received: ValidatedEvent[] = [];
      pipeline.onValidated(e => received.push(e));
      pipeline.ingest(makePolicyEvaluated(1), META);
      expect(received).toHaveLength(1);
      expect(received[0].type).toBe('policy.evaluated');
    });
  });

  describe('TestIngestion_StringLabelRejected', () => {
    it('rejects event with string-format SecurityLabel', () => {
      const pipeline = createEventIngestionPipeline({ send: makeSend() });
      const received: ValidatedEvent[] = [];
      pipeline.onValidated(e => received.push(e));
      pipeline.ingest(JSON.stringify({
        type: 'policy.evaluated', nixissequence: 1,
        data: { tool: 'Shell', session_id: 's', decision: { action: 'allow', reason: '', policy_id: 'p', enforcing_layer: 'adapter', labels: { level: 'Confidential' } }, label_state: 'fresh', latency_ns: 0 },
      }), META);
      expect(received).toHaveLength(0);
    });
    it('rejects non-canonical verdict "escalate"', () => {
      const pipeline = createEventIngestionPipeline({ send: makeSend() });
      const received: ValidatedEvent[] = [];
      pipeline.onValidated(e => received.push(e));
      pipeline.ingest(makePolicyEvaluated(1, 'e1', 'escalate'), META);
      expect(received).toHaveLength(0);
    });
  });

  describe('TestIngestion_DuplicateEventDropped', () => {
    it('drops the second event with the same id', () => {
      const pipeline = createEventIngestionPipeline({ send: makeSend() });
      const received: ValidatedEvent[] = [];
      pipeline.onValidated(e => received.push(e));
      const raw = makePolicyEvaluated(1, 'dup-id');
      pipeline.ingest(raw, META);
      pipeline.ingest(raw, META);
      expect(received).toHaveLength(1);
    });
    it('drops duplicate by nixissequence when no id field', () => {
      const pipeline = createEventIngestionPipeline({ send: makeSend() });
      const received: ValidatedEvent[] = [];
      pipeline.onValidated(e => received.push(e));
      const raw = JSON.stringify({ type: 'policy.evaluated', nixissequence: 99, data: { tool: 'Shell', session_id: 's', decision: { action: 'allow', reason: '', policy_id: 'p', enforcing_layer: 'adapter', labels: { confidentiality: 0, integrity: 0, categories: 0 } }, label_state: 'fresh', latency_ns: 0 } });
      pipeline.ingest(raw, META);
      pipeline.ingest(raw, META);
      expect(received).toHaveLength(1);
    });
  });

  describe('TestIngestion_BackfillViaWebSocket', () => {
    beforeEach(() => vi.useFakeTimers());
    afterEach(() => vi.useRealTimers());
    it('sends backfill.request on gap detection after 500ms debounce', () => {
      const send = makeSend();
      const pipeline = createEventIngestionPipeline({ send });
      pipeline.onValidated(() => {});
      pipeline.ingest(makePolicyEvaluated(1, 'e1'), META);
      pipeline.ingest(makePolicyEvaluated(3, 'e3'), META); // gap at seq 2
      expect(send).not.toHaveBeenCalledWith(expect.objectContaining({ type: 'backfill.request' }));
      vi.advanceTimersByTime(600);
      expect(send).toHaveBeenCalledWith(expect.objectContaining({ type: 'backfill.request', from: 2, to: 2 }));
    });
  });

  describe('sequence ordering', () => {
    it('delivers in-order events immediately', () => {
      const pipeline = createEventIngestionPipeline({ send: makeSend() });
      const seqs: number[] = [];
      pipeline.onValidated(e => seqs.push(e.envelope.nixissequence));
      pipeline.ingest(makePolicyEvaluated(1, 'e1'), META);
      pipeline.ingest(makePolicyEvaluated(2, 'e2'), META);
      pipeline.ingest(makePolicyEvaluated(3, 'e3'), META);
      expect(seqs).toEqual([1, 2, 3]);
    });
    it('buffers out-of-order events and delivers once gap is filled', () => {
      const pipeline = createEventIngestionPipeline({ send: makeSend() });
      const seqs: number[] = [];
      pipeline.onValidated(e => seqs.push(e.envelope.nixissequence));
      pipeline.ingest(makePolicyEvaluated(1, 'e1'), META);
      pipeline.ingest(makePolicyEvaluated(3, 'e3'), META);
      expect(seqs).toEqual([1]);
      pipeline.ingest(makePolicyEvaluated(2, 'e2'), META);
      expect(seqs).toEqual([1, 2, 3]);
    });
  });

  describe('onValidated unsubscribe', () => {
    it('stops delivering after unsubscribe', () => {
      const pipeline = createEventIngestionPipeline({ send: makeSend() });
      const received: ValidatedEvent[] = [];
      const unsub = pipeline.onValidated(e => received.push(e));
      pipeline.ingest(makePolicyEvaluated(1, 'e1'), META);
      unsub();
      pipeline.ingest(makePolicyEvaluated(2, 'e2'), META);
      expect(received).toHaveLength(1);
    });
  });

  describe('CRITICAL priority events', () => {
    it('label.escalated has priority CRITICAL', () => {
      const pipeline = createEventIngestionPipeline({ send: makeSend() });
      const received: ValidatedEvent[] = [];
      pipeline.onValidated(e => received.push(e));
      pipeline.ingest(JSON.stringify({ type: 'label.escalated', id: 'esc-1', nixissequence: 1, data: { session_id: 's', label: { confidentiality: 32768, integrity: 32768, categories: 0 }, label_state: 'escalated' } }), META);
      expect(received).toHaveLength(1);
      if (received[0].type === 'label.escalated') expect(received[0].priority).toBe('CRITICAL');
    });
    it('secret.detected has priority CRITICAL', () => {
      const pipeline = createEventIngestionPipeline({ send: makeSend() });
      const received: ValidatedEvent[] = [];
      pipeline.onValidated(e => received.push(e));
      pipeline.ingest(JSON.stringify({ type: 'secret.detected', id: 'sec-1', nixissequence: 1, data: { session_id: 's', tool: 'Shell' } }), META);
      expect(received).toHaveLength(1);
      if (received[0].type === 'secret.detected') expect(received[0].priority).toBe('CRITICAL');
    });
  });

  describe('unknown and invalid events', () => {
    it('discards unknown event types', () => {
      const pipeline = createEventIngestionPipeline({ send: makeSend() });
      const received: ValidatedEvent[] = [];
      pipeline.onValidated(e => received.push(e));
      pipeline.ingest(JSON.stringify({ type: 'some.unknown.type', nixissequence: 1, data: {} }), META);
      expect(received).toHaveLength(0);
    });
  });

  describe('policy.denied', () => {
    it('validates and emits policy.denied events', () => {
      const pipeline = createEventIngestionPipeline({ send: makeSend() });
      const received: ValidatedEvent[] = [];
      pipeline.onValidated(e => received.push(e));
      pipeline.ingest(makePolicyDenied(1, 'd1'), META);
      expect(received).toHaveLength(1);
      expect(received[0].type).toBe('policy.denied');
    });
  });
});
