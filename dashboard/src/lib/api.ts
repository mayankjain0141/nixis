export function getDaemonApiBase(): string {
  const override = (window as unknown as Record<string, unknown>).__NIXIS_DAEMON_URL__;
  if (typeof override === 'string' && override) {
    try {
      const url = new URL(override);
      if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
        return override;
      }
    } catch { /* invalid URL — fall through */ }
  }
  return import.meta.env.VITE_DAEMON_URL ?? 'http://localhost:9090';
}
