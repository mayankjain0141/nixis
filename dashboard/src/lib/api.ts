export function getDaemonApiBase(): string {
  return (window as unknown as { __AEGIS_DAEMON_URL__?: string }).__AEGIS_DAEMON_URL__
    ?? import.meta.env.VITE_DAEMON_URL
    ?? 'http://localhost:9090';
}
