/**
 * Top-level API prefixes the dashboard calls (see `api` in ./api.ts). The Vite
 * dev server proxies exactly these to the orchestrator; a new endpoint outside
 * them must be added here or `npm run dev` 404s it. `apiPaths.test.ts`
 * checks every path in api.ts against this list.
 */
export const API_PATH_PREFIXES = ['/auth', '/accounts', '/cases', '/health', '/targets', '/runs', '/analytics', '/alerts'] as const;
