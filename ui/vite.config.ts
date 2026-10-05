import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// The dashboard is served by the orchestrator under /console (see
// orchestrator/api.py): assets resolve relative to that prefix and the router
// uses it as its basename.
export default defineConfig({
  base: '/console/',
  plugins: [react()],
  build: {
    // Hashed asset names let the backend serve them with immutable caching.
    assetsDir: 'assets',
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test/setup.ts',
  },
});
