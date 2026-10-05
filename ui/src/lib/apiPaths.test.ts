import { API_PATH_PREFIXES } from './apiPaths';
// Vite's ?raw import hands over the source text; no Node fs needed.
import apiSource from './api.ts?raw';

// Every path the client requests must sit under a prefix the dev proxy
// forwards, or `npm run dev` silently 404s that endpoint.
describe('API path prefixes', () => {
  // Only the request-making code: the `api` object and what follows it
  // (downloadArtifact), with comments stripped so prose cannot be mistaken
  // for a path. Each match is a whole string or template literal.
  const start = apiSource.indexOf('export const api = {');
  const requestCode = apiSource
    .slice(start)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*$/gm, '');
  const literals = [...requestCode.matchAll(/[`'"](\/[^`'"]*)[`'"]/g)].map((match) => match[1]);
  const firstSegment = (literal: string) => `/${literal.slice(1).split(/[/?]/, 1)[0]}`;

  it('finds the request-making code', () => {
    expect(start).toBeGreaterThan(-1);
    expect(literals.length).toBeGreaterThan(5);
    // The conditional in getRuns is the call a call-site-anchored scan misses.
    expect(literals.some((literal) => literal.startsWith('/runs?target_id='))).toBe(true);
  });

  it('cover every path requested by api.ts', () => {
    for (const literal of new Set(literals)) {
      // Exact first-segment match: `/runs_v2` is not covered by `/runs`.
      expect(API_PATH_PREFIXES as readonly string[]).toContain(firstSegment(literal));
    }
  });
});
