# Nixis Dashboard

Real-time monitoring and analytics UI for the Nixis governance daemon.

## Quick Start

Prerequisites: Node.js 18+, Nixis daemon running on localhost:9090.

```bash
npm install
npm run dev
```

Opens on http://localhost:5173. Connects to the daemon at `ws://127.0.0.1:9090/ws` by default.

## Environment Variables

- `VITE_DAEMON_STREAM_ADDR` — WebSocket URL for event streaming (default: `ws://127.0.0.1:9090/ws`)
- `VITE_DAEMON_API_ADDR` — HTTP base URL for the daemon REST API (default: `http://127.0.0.1:9090`)

## Scripts

- `npm run dev` — start dev server
- `npm run build` — production build
- `npm test` — run unit tests
- `npm run type-check` — TypeScript check
- `npm run lint` — lint check
