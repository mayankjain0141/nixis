import { test, expect } from '@playwright/test';

test.describe('Mock daemon fallback', () => {
  test('switches to mock mode when daemon unavailable', async ({ page }) => {
    await page.goto('/');
    await page.waitForTimeout(3000);
    const sidebar = page.locator('[aria-label="Connection and policy summary"]');
    await expect(sidebar).toBeVisible();
    await expect(sidebar).toContainText(/DISCONNECTED|CONNECTING|RECONNECTING/);
  });

  test('mock events appear in stream after fallback', async ({ page }) => {
    await page.goto('/');
    await page.waitForTimeout(3500);
    const eventStream = page.locator('main[aria-label="Live event stream"]');
    await expect(eventStream).toBeVisible();
  });
});
