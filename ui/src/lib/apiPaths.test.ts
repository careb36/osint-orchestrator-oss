import { API_PATH_PREFIXES } from './apiPaths';
// Vite's ?raw import hands over the source text; no Node fs needed.
import apiSource from './api.ts?raw';

// Every path the client requests must sit under a prefix the dev proxy
// forwards, or `npm run dev` silently 404s that endpoint.
describe('API path prefixes', () => {
  it('cover every path requested by api.ts', () => {
    const paths = [...apiSource.matchAll(/request<[^>]+>\(\s*[`'](\/[a-z-]+)/g)].map((match) => match[1]);
    expect(paths.length).toBeGreaterThan(5);
    for (const path of new Set(paths)) {
      expect(API_PATH_PREFIXES.some((prefix) => path === prefix || path.startsWith(`${prefix}/`))).toBe(true);
    }
  });
});
