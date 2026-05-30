import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// Production CSP — strict, no eval, applied to `vite preview` and production servers.
// Do NOT apply to the dev server: Vite HMR requires 'unsafe-eval' to inject the
// React Fast Refresh preamble. Applying script-src 'self' in dev blocks HMR entirely.
const prodSecurityHeaders = {
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "connect-src 'self' ws://localhost:* wss://localhost:* http://localhost:* http://127.0.0.1:*",
    "img-src 'self' data:",
    "font-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
  ].join('; '),
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
};

// Dev server headers — no CSP (localhost is not a security boundary; HMR needs eval).
const devSecurityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
};

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'require-daemon-url',
      config(_, { mode }) {
        if (mode === 'production' && !process.env.VITE_DAEMON_URL) {
          throw new Error('VITE_DAEMON_URL must be set for production builds');
        }
      },
    },
  ],
  build: {
    sourcemap: false,
  },
  server: {
    headers: devSecurityHeaders,
    proxy: {
      '/simulate': 'http://localhost:9090',
      '/healthz': 'http://localhost:9090',
    },
  },
  preview: {
    headers: prodSecurityHeaders,
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
    exclude: ['e2e/**', 'node_modules/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html', 'json'],
      thresholds: {
        statements: 80,
        branches: 80,
        functions: 80,
        lines: 80,
      },
      include: ['src/**'],
      exclude: ['src/**/*.test.*', 'src/**/*.spec.*', 'src/mocks/**'],
    },
  },
});
