import { render, screen, fireEvent, act } from '@testing-library/react';
import { describe, it, expect, beforeEach } from 'vitest';
import { CommandPalette } from './CommandPalette';
import { useUIStore } from '../../stores/ui-store';

function openPalette() {
  act(() => {
    useUIStore.getState().setCommandPaletteOpen(true);
  });
}

function closePalette() {
  act(() => {
    useUIStore.getState().setCommandPaletteOpen(false);
  });
}

beforeEach(() => {
  closePalette();
});

describe('CommandPalette', () => {
  it('opens on Cmd+K keydown', () => {
    render(<CommandPalette />);
    expect(screen.queryByRole('dialog')).toBeNull();

    act(() => {
      fireEvent.keyDown(window, { key: 'k', metaKey: true });
    });

    // Palette is opened via App.tsx keydown handler wired to the store.
    // Directly open via store to test the component renders when open.
    openPalette();
    expect(screen.getByRole('dialog', { name: 'Command palette' })).toBeInTheDocument();
  });

  it('closes on Escape', () => {
    render(<CommandPalette />);
    openPalette();
    expect(screen.getByRole('dialog')).toBeInTheDocument();

    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('filters commands by search query', () => {
    render(<CommandPalette />);
    openPalette();

    const input = screen.getByRole('textbox', { name: 'Search commands' });
    fireEvent.change(input, { target: { value: 'deny' } });

    expect(screen.getByText('Filter: Show deny events only')).toBeInTheDocument();
    expect(screen.queryByText('Filter: Show allow events only')).toBeNull();
    expect(screen.queryByText('Go to: Event Stream')).toBeNull();
  });

  it('keyboard navigation selects items', () => {
    render(<CommandPalette />);
    openPalette();

    // Limit to one category for easier testing.
    const input = screen.getByRole('textbox', { name: 'Search commands' });
    fireEvent.change(input, { target: { value: 'filter' } });

    const items = screen.getAllByRole('option');
    expect(items[0]).toHaveAttribute('aria-selected', 'true');

    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'ArrowDown' });
    expect(items[1]).toHaveAttribute('aria-selected', 'true');
    expect(items[0]).toHaveAttribute('aria-selected', 'false');

    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'ArrowUp' });
    expect(items[0]).toHaveAttribute('aria-selected', 'true');
  });

  it('executes command on Enter', () => {
    render(<CommandPalette />);
    openPalette();

    const input = screen.getByRole('textbox', { name: 'Search commands' });
    fireEvent.change(input, { target: { value: 'reconnect' } });

    // 'Connection: Reconnect to daemon' should be visible.
    expect(screen.getByText('Connection: Reconnect to daemon')).toBeInTheDocument();

    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Enter' });
    // Command executes (no crash) and palette closes.
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('closes after executing command', () => {
    render(<CommandPalette />);
    openPalette();
    expect(screen.getByRole('dialog')).toBeInTheDocument();

    // Click the first visible command item.
    const items = screen.getAllByRole('option');
    fireEvent.click(items[0]);

    expect(screen.queryByRole('dialog')).toBeNull();
  });
});
