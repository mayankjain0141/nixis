import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { PolicyPlayground } from './PolicyPlayground';
import { usePolicyStore } from '../../stores/policy-store';

beforeEach(() => {
  usePolicyStore.getState().setPolicies([]);
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('PolicyPlayground — offline error state', () => {
  it('shows daemon-required error when fetch rejects, no result rendered', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Failed to fetch')));

    render(<PolicyPlayground />);

    fireEvent.change(screen.getByPlaceholderText(/git push/i), { target: { value: 'git push --force' } });
    fireEvent.click(screen.getByText(/Evaluate against/i));

    await waitFor(() => {
      expect(screen.getByText(/Daemon required/i)).toBeInTheDocument();
    });

    expect(screen.queryByText(/ALLOW|DENY|REQUIRE APPROVAL|AUDIT/i)).toBeNull();
  });

  it('shows daemon-required error when fetch returns HTTP 500, no result rendered', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
    } as Response));

    render(<PolicyPlayground />);

    fireEvent.change(screen.getByPlaceholderText(/git push/i), { target: { value: 'some command' } });
    fireEvent.click(screen.getByText(/Evaluate against/i));

    await waitFor(() => {
      expect(screen.getByText(/Daemon required/i)).toBeInTheDocument();
    });

    expect(screen.queryByText(/ALLOW|DENY|REQUIRE APPROVAL|AUDIT/i)).toBeNull();
  });

  it('clears error and shows result on successful fetch', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ verdict: 'allow', explanation: 'No policy matched.', latencyNs: 500000 }),
    } as unknown as Response));

    render(<PolicyPlayground />);

    fireEvent.change(screen.getByPlaceholderText(/git push/i), { target: { value: 'echo hello' } });
    fireEvent.click(screen.getByText(/Evaluate against/i));

    await waitFor(() => {
      expect(screen.getByText('ALLOW')).toBeInTheDocument();
    });

    expect(screen.queryByText(/Daemon required/i)).toBeNull();
  });

  it('disables button while loading', async () => {
    let resolvePromise!: (value: unknown) => void;
    vi.stubGlobal('fetch', vi.fn().mockReturnValue(new Promise(res => { resolvePromise = res; })));

    render(<PolicyPlayground />);

    fireEvent.change(screen.getByPlaceholderText(/git push/i), { target: { value: 'some command' } });
    const button = screen.getByText(/Evaluate against/i);
    fireEvent.click(button);

    await waitFor(() => {
      expect(screen.getByText(/Evaluating/i)).toBeInTheDocument();
    });

    const evaluatingButton = screen.getByText(/Evaluating/i);
    expect(evaluatingButton).toBeDisabled();

    act(() => {
      resolvePromise({ ok: false, status: 503 });
    });

    await waitFor(() => {
      expect(screen.getByText(/Daemon required/i)).toBeInTheDocument();
    });
  });
});

describe('PolicyPlayground — fetch payload', () => {
  it('sends correct JSON body to /simulate endpoint', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ Decision: { Action: 'deny', Reason: 'Blocked.', PolicyID: 'test-policy' }, LatencyNs: 1000000 }),
    } as unknown as Response);
    vi.stubGlobal('fetch', mockFetch);

    render(<PolicyPlayground />);

    fireEvent.change(screen.getByPlaceholderText(/git push/i), { target: { value: 'rm -rf /' } });
    fireEvent.click(screen.getByText(/Evaluate against/i));

    await waitFor(() => {
      expect(screen.getByText('DENY')).toBeInTheDocument();
    });

    const [url, options] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/simulate$/);
    expect(options.method).toBe('POST');

    const body = JSON.parse(options.body as string) as Record<string, unknown>;
    expect(body.Tool).toBe('Bash');
    expect(body.Args).toMatchObject({ command: expect.any(String) });
    expect(body.SessionID).toBeDefined();
    expect(body.Timestamp).toBeTypeOf('number');
  });
});
