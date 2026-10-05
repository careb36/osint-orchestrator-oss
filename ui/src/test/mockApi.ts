import { vi } from 'vitest';
import type { DeltaRow, EvidenceRow, Finding, HealthStatus, RiskTrend, RunDetail, RunSummary, TargetSummary } from '../types';

export const sampleHealth: HealthStatus = {
  status: 'ok',
  version: '0.1.0-test',
  checks: {
    database: { status: 'ok', detail: 'SQLite reachable' },
    scheduler: { status: 'ok', detail: 'APScheduler running' },
    opencti: { status: 'disabled', detail: 'OpenCTI disabled in demo mode' },
  },
};

export const sampleTargets: TargetSummary[] = [
  {
    id: 'example-corp',
    enabled: true,
    fqdn: 'example.com',
    authorization: 'Internal test authorization',
    purpose: 'Exposure monitoring',
    collectors: { openosint: { enabled: true }, spiderfoot: { enabled: true } },
    schedule: { cron: '0 6 * * *' },
    llm: 'local',
    language: 'es',
  },
  {
    id: 'paused-target',
    enabled: false,
    fqdn: 'paused.example',
    authorization: 'Internal test authorization',
    purpose: 'Paused coverage',
    collectors: { openosint: { enabled: true } },
    schedule: { cron: '0 7 * * *' },
    llm: 'local',
    language: 'en',
  },
];

export const sampleRuns: RunSummary[] = [
  {
    id: 42,
    target_id: 'example-corp',
    started_at: '2026-10-01T06:00:00Z',
    finished_at: '2026-10-01T06:04:00Z',
    status: 'success',
    collectors_run: 'openosint,spiderfoot',
    new_observables: 3,
    error: null,
    report_path: 'daily_reports/2026-10-01/example-corp/report.md',
    manifest_sha256: 'a'.repeat(64),
  },
  {
    id: 43,
    target_id: 'paused-target',
    started_at: '2026-10-02T07:00:00Z',
    finished_at: '2026-10-02T07:01:00Z',
    status: 'failed',
    collectors_run: 'openosint',
    new_observables: 0,
    error: 'collector timeout',
    report_path: null,
    manifest_sha256: null,
  },
];

export const sampleRunDetail: RunDetail = { ...sampleRuns[0], alerts: [] };

export const sampleTrends: RiskTrend[] = [
  {
    target_id: 'example-corp',
    runs_considered: 1,
    latest_run_id: 42,
    latest_status: 'success',
    latest_risk_level: 'high',
    peak_risk_level: 'high',
    risk_history: ['high'],
    new_observables_history: [3],
  },
  {
    target_id: 'paused-target',
    runs_considered: 1,
    latest_run_id: 43,
    latest_status: 'failed',
    latest_risk_level: 'unknown',
    peak_risk_level: 'unknown',
    risk_history: ['unknown'],
    new_observables_history: [0],
  },
];

export const sampleFinding: Finding = {
  run_id: sampleRuns[0].id,
  target_id: sampleRuns[0].target_id,
  summary: 'Two new subdomains expose an outdated login portal; one leaked credential pair was found in a paste.',
  risk_level: 'high',
  risk_justification: 'Exposed authentication surface plus leaked credentials.',
  new_since_last_run: ['login.example.com', 'vpn.example.com'],
  suggested_pivots: ['Check the paste source for further dumps.'],
  provider: 'nebius',
  model: 'test-model',
  duration_ms: 1200,
  generated_at: '2026-10-01T06:05:00',
};

export const sampleEvidence: EvidenceRow[] = [
  {
    id: 1,
    run_id: sampleRuns[0].id,
    target_id: sampleRuns[0].target_id,
    url: 'https://paste.example/abc',
    title: 'Leaked credential pair',
    category: 'credential-leak',
    relevance: 'high',
    confidence: 0.91,
    rationale: 'Matches the target domain and a current employee handle.',
    provider: 'nebius',
    model: 'test-model',
  },
  {
    id: 2,
    run_id: sampleRuns[0].id,
    target_id: sampleRuns[0].target_id,
    url: 'https://news.example/outage',
    title: 'Regional outage report',
    category: 'news',
    relevance: 'low',
    confidence: 0.35,
    rationale: 'Mentions the sector, not the target.',
    provider: 'nebius',
    model: 'test-model',
  },
  {
    id: 3,
    run_id: sampleRuns[0].id,
    target_id: sampleRuns[0].target_id,
    url: 'https://forum.example/thread/9',
    title: 'Forum thread naming the login portal',
    category: 'exposure',
    relevance: 'medium',
    confidence: 0.6,
    rationale: 'Discusses an exposed subdomain of the target.',
    provider: 'nebius',
    model: 'test-model',
  },
];

export const sampleDelta: DeltaRow[] = [
  { stix_id: 'domain-name--1', stix_type: 'domain-name', value: 'login.example.com' },
  { stix_id: 'domain-name--2', stix_type: 'domain-name', value: 'vpn.example.com' },
  { stix_id: 'url--1', stix_type: 'url', value: 'https://paste.example/abc' },
];

type Route = {
  pattern: RegExp;
  status?: number;
  body: unknown | ((match: RegExpMatchArray) => unknown);
};

type MockOptions = {
  /** When set, requests without this X-API-Key header answer 401. */
  requireKey?: string;
  routes?: Route[];
};

export const defaultRoutes: Route[] = [
  { pattern: /^\/health$/, body: sampleHealth },
  { pattern: /^\/targets$/, body: sampleTargets },
  {
    pattern: /^\/targets\/([^/]+)$/,
    body: (match: RegExpMatchArray) => sampleTargets.find((target) => target.id === decodeURIComponent(match[1])) ?? null,
  },
  { pattern: /^\/runs(\?.*)?$/, body: sampleRuns },
  { pattern: /^\/runs\/\d+$/, body: sampleRunDetail },
  // The finding fixture belongs to the first sample run; every other run has none.
  { pattern: new RegExp(`^/runs/${sampleFinding.run_id}/finding$`), body: sampleFinding },
  { pattern: /^\/runs\/\d+\/finding$/, status: 404, body: { detail: 'No finding for this run' } },
  { pattern: new RegExp(`^/runs/${sampleRuns[0].id}/evidence$`), body: sampleEvidence },
  { pattern: new RegExp(`^/runs/${sampleRuns[0].id}/delta$`), body: sampleDelta },
  { pattern: /^\/runs\/\d+\/evidence$/, body: [] },
  { pattern: /^\/runs\/\d+\/delta$/, body: [] },
  { pattern: /^\/analytics\/risk-trends$/, body: sampleTrends },
];

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Replace window.fetch with an in-memory stand-in for the orchestrator API.
 * Returns the mock so tests can assert on the calls made.
 */
export function installFetchMock(options: MockOptions = {}) {
  const routes = [...(options.routes ?? []), ...defaultRoutes];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const path = url.replace(/^https?:\/\/[^/]+/, '');
    const headers = new Headers(init?.headers);

    if (options.requireKey !== undefined && headers.get('X-API-Key') !== options.requireKey) {
      return jsonResponse(401, { detail: 'Missing or invalid API key' });
    }

    for (const route of routes) {
      const match = path.match(route.pattern);
      if (match) {
        const body = typeof route.body === 'function' ? route.body(match) : route.body;
        if (body === null) {
          return jsonResponse(404, { detail: 'Not found' });
        }
        return jsonResponse(route.status ?? 200, body);
      }
    }
    return jsonResponse(404, { detail: `Unmocked path ${path}` });
  });

  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}
