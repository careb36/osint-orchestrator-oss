import { defineConfig } from 'vitest/config';
import { loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// The dashboard is served by the orchestrator under /console (see
// orchestrator/api.py): assets resolve relative to that prefix and the router
// uses it as its basename.
// `npm run dev` serves the app from Vite; the API paths it calls are proxied
// to a running orchestrator so the same-origin default of src/lib/api.ts
// holds in development too (no CORS, X-API-Key travels as is).
const API_PATHS = ['/health', '/targets', '/runs', '/analytics'];

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', 'VITE_');
  const devApiTarget = env.VITE_DEV_API_TARGET || 'http://localhost:8000';
  return {
  base: '/console/',
  plugins: [react()],
  server: {
    proxy: Object.fromEntries(API_PATHS.map((path) => [path, { target: devApiTarget, changeOrigin: true }])),
  },
  build: {
    // Hashed asset names let the backend serve them with immutable caching.
    assetsDir: 'assets',
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test/setup.ts',
  },
  };
});
