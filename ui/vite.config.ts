import { defineConfig } from 'vitest/config';
import { loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { API_PATH_PREFIXES } from './src/lib/apiPaths';

// The dashboard is served by the orchestrator under /console (see
// orchestrator/api.py): assets resolve relative to that prefix and the router
// uses it as its basename.
//
// `npm run dev` serves the app from Vite; the API prefixes it calls
// (src/lib/apiPaths.ts, checked against api.ts by a test) are proxied to a
// running orchestrator so the same-origin default of src/lib/api.ts holds in
// development too (no CORS, X-API-Key travels as is).
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', 'VITE_');
  const devApiTarget = env.VITE_DEV_API_TARGET || 'http://localhost:8000';

  return {
    base: '/console/',
    plugins: [react()],
    server: {
      proxy: Object.fromEntries(
        API_PATH_PREFIXES.map((prefix) => [prefix, { target: devApiTarget, changeOrigin: true, configure: (proxy) => { proxy.on('proxyReq', (outgoing, incoming) => { if (incoming.headers.origin) outgoing.setHeader('Origin', new URL(devApiTarget).origin); }); } }]),
      ),
    },
    build: {
      // Hashed asset names let the backend serve them with immutable caching.
      assetsDir: 'assets',
      rollupOptions: {
        output: {
          // The libraries change far less often than the views: one vendor
          // chunk keeps its immutable cache entry across dashboard releases,
          // and each lazily loaded view (src/App.tsx) gets its own chunk.
          manualChunks: {
            react: ['react', 'react-dom', 'react-router-dom'],
            query: ['@tanstack/react-query'],
          },
        },
      },
    },
    test: {
      environment: 'jsdom',
      globals: true,
      setupFiles: './src/test/setup.ts',
    },
  };
});
