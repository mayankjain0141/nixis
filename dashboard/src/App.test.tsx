import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { StoreProvider } from './providers/StoreProvider';

// WebSocket needs to be a class (constructor) in the test environment.
class MockWebSocket {
  close = vi.fn();
  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;
  readyState = 0; // CONNECTING
}

vi.stubGlobal('WebSocket', MockWebSocket);

// Prevent timers from the mock stream generator from running.
vi.mock('./mocks/streamGenerator', () => ({
  createMockStreamGenerator: vi.fn(() => ({
    start: vi.fn(),
    stop: vi.fn(),
    onEvent: vi.fn(),
  })),
}));

afterEach(() => {
  vi.clearAllMocks();
});

describe('App', () => {
  it('renders without crashing', async () => {
    const { default: App } = await import('./App');
    render(
      <StoreProvider>
        <App />
      </StoreProvider>,
    );
    // AppHeader renders NIXIS brand name
    expect(screen.getByText('NIXIS')).toBeInTheDocument();
    // EventStreamList renders empty state when no events
    expect(screen.getByText('Waiting for events…')).toBeInTheDocument();
  });
});
