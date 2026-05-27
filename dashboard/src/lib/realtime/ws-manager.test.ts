import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createWebSocketManager } from './ws-manager';

// Minimal WebSocket mock.
class MockWebSocket {
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState = MockWebSocket.OPEN;
  url: string;
  sent: string[] = [];

  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    // Simulate async open on next tick so tests can register handlers.
    Promise.resolve().then(() => this.onopen?.());
  }

  send(data: string): void {
    this.sent.push(data);
  }

  close(): void {
    this.readyState = MockWebSocket.CLOSED;
    Promise.resolve().then(() => this.onclose?.());
  }

  simulateMessage(data: string): void {
    this.onmessage?.({ data });
  }

  simulateClose(): void {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.();
  }
}

// vi.stubGlobal handles the runtime replacement; no type override needed here.

describe('createWebSocketManager', () => {
  let lastSocket: MockWebSocket | null = null;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.stubGlobal('WebSocket', class extends MockWebSocket {
      constructor(url: string) {
        super(url);
        lastSocket = this;
      }
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    lastSocket = null;
  });

  it('starts in IDLE state', () => {
    const mgr = createWebSocketManager('ws://localhost:9090/ws');
    expect(mgr.getState()).toBe('IDLE');
  });

  it('transitions to CONNECTING then CONNECTED', async () => {
    const mgr = createWebSocketManager('ws://localhost:9090/ws');
    mgr.connect();
    expect(mgr.getState()).toBe('CONNECTING');
    await Promise.resolve(); // let MockWebSocket fire onopen
    expect(mgr.getState()).toBe('CONNECTED');
  });

  it('delivers messages to registered handlers', async () => {
    const mgr = createWebSocketManager('ws://localhost:9090/ws');
    const received: string[] = [];
    mgr.onMessage((raw) => received.push(raw));
    mgr.connect();
    await Promise.resolve();
    lastSocket?.simulateMessage('{"type":"test"}');
    expect(received).toHaveLength(1);
    expect(received[0]).toBe('{"type":"test"}');
  });

  it('unsubscribes handler when the returned function is called', async () => {
    const mgr = createWebSocketManager('ws://localhost:9090/ws');
    const received: string[] = [];
    const unsub = mgr.onMessage((raw) => received.push(raw));
    mgr.connect();
    await Promise.resolve();
    unsub();
    lastSocket?.simulateMessage('{"type":"test"}');
    expect(received).toHaveLength(0);
  });

  it('transitions to DISCONNECTED and then RECONNECTING on unexpected close', async () => {
    const mgr = createWebSocketManager('ws://localhost:9090/ws');
    mgr.connect();
    await Promise.resolve(); // onopen
    lastSocket?.simulateClose(); // triggers onclose → scheduleReconnect
    expect(mgr.getState()).toBe('RECONNECTING');
  });

  it('reconnects after backoff delay', async () => {
    const mgr = createWebSocketManager('ws://localhost:9090/ws');
    mgr.connect();
    await Promise.resolve();
    lastSocket?.simulateClose();
    expect(mgr.getState()).toBe('RECONNECTING');

    // First backoff is 1000ms.
    vi.advanceTimersByTime(1100);
    await Promise.resolve(); // second onopen
    expect(mgr.getState()).toBe('CONNECTED');
    expect(mgr.getMetrics().reconnectCount).toBe(1);
  });

  it('sends resumeFrom on reconnect when lastSequenceId > 0', async () => {
    const mgr = createWebSocketManager('ws://localhost:9090/ws');
    mgr.connect();
    await Promise.resolve();
    // Simulate a message with aegissequence.
    lastSocket?.simulateMessage('{"type":"decision","aegissequence":42}');
    lastSocket?.simulateClose();
    vi.advanceTimersByTime(1100);
    await Promise.resolve();
    // The second socket should have received a subscribe.filter message.
    const filterMsg = lastSocket?.sent.find(s => s.includes('subscribe.filter'));
    expect(filterMsg).toBeDefined();
    expect(JSON.parse(filterMsg!).resumeFrom).toBe(42);
  });

  it('transitions to IDLE and stops reconnecting after disconnect()', async () => {
    const mgr = createWebSocketManager('ws://localhost:9090/ws');
    mgr.connect();
    await Promise.resolve();
    mgr.disconnect();
    expect(mgr.getState()).toBe('IDLE');
    // Advance past all backoff delays — no reconnect should happen.
    vi.advanceTimersByTime(30000);
    expect(mgr.getState()).toBe('IDLE');
  });

  it('send() serializes ClientMessage as JSON', async () => {
    const mgr = createWebSocketManager('ws://localhost:9090/ws');
    mgr.connect();
    await Promise.resolve();
    mgr.send({ type: 'ping', clientTime: 12345 });
    expect(lastSocket?.sent).toContain('{"type":"ping","clientTime":12345}');
  });

  it('ignores send() when not connected', () => {
    const mgr = createWebSocketManager('ws://localhost:9090/ws');
    // Not connected — should not throw.
    expect(() => mgr.send({ type: 'ping' })).not.toThrow();
  });

  it('calling connect() twice does not open a second socket', async () => {
    let socketCount = 0;
    vi.stubGlobal('WebSocket', class extends MockWebSocket {
      constructor(url: string) {
        super(url);
        socketCount++;
        lastSocket = this;
      }
    });
    const mgr = createWebSocketManager('ws://localhost:9090/ws');
    mgr.connect();
    mgr.connect(); // second call is a no-op while CONNECTING
    await Promise.resolve();
    expect(socketCount).toBe(1);
  });

  it('updates clockOffsetMs from heartbeat serverTime', async () => {
    const mgr = createWebSocketManager('ws://localhost:9090/ws');
    mgr.connect();
    await Promise.resolve();
    // Fake serverTime = Date.now() + 50 (server is 50ms ahead).
    const serverTime = Date.now() + 50;
    lastSocket?.simulateMessage(JSON.stringify({ type: 'stream.heartbeat', serverTime }));
    // clockOffsetMs should be approximately +50.
    expect(Math.abs(mgr.getMetrics().clockOffsetMs - 50)).toBeLessThan(5);
  });
});
