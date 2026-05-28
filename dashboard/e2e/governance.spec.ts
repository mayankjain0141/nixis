import { test, expect } from '@playwright/test';

test.describe('Governance Dashboard', () => {
  test('loads without errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('console', msg => { if (msg.type() === 'error') errors.push(msg.text()); });
    await page.goto('/');
    await expect(page).toHaveTitle(/Aegis/);
    await page.waitForTimeout(1000);
    expect(errors.filter(e => !e.includes('WebSocket'))).toHaveLength(0);
  });

  test('displays connection status', async ({ page }) => {
    await page.goto('/');
    const status = page.locator('[aria-label="Connection and policy summary"]');
    await expect(status).toBeVisible();
  });

  test('MetricsBar is visible', async ({ page }) => {
    await page.goto('/');
    const metricsBar = page.locator('[role="status"][aria-label="Dashboard metrics"]');
    await expect(metricsBar).toBeVisible();
    await expect(metricsBar).not.toBeEmpty();
  });

  test('command palette opens on Cmd+K', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.keyboard.press('Meta+k');
    const input = page.locator('input[placeholder*="command"], input[placeholder*="Command"], input[type="text"]').first();
    await expect(input).toBeVisible({ timeout: 2000 });
  });

  test('event stream panel is present', async ({ page }) => {
    await page.goto('/');
    const main = page.locator('main[aria-label="Live event stream"]');
    await expect(main).toBeVisible();
  });
});
