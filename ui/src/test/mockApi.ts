import { vi } from 'vitest';
import type { AlertCase, ChainVerification, DeltaRow, EvidenceRow, Finding, HealthStatus, RiskTrend, RunDetail, RunSummary, TargetSummary } from '../types';

// The default deployment has the OpenCTI sink off (ADR-008). A disabled check
// does not degrade the rollup, so the overall status stays ok.
export const sampleHealth: HealthStatus = {
  status: 'ok',
  version: '0.1.0-test',
  checks: {
    database: { status: 'ok', detail: 'SQLite reachable' },
    scheduler: { status: 'ok', detail: 'APScheduler running' },
    // A switched-off sink is a configuration, not a fault (ADR-008).
    opencti: { status: 'disabled', detail: 'OpenCTI sink disabled' },
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
    classification: 'restricted',
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
    classification: 'osint',
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
    risk_level: 'high',
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
    risk_level: null,
  },
];

export const sampleRunDetail: RunDetail = {
  ...sampleRuns[0],
  alerts: [{ id: 1, run_id: 42, channel: 'webhook', status: 'sent', sent_at: '2026-10-01T06:04:30Z', error: null }],
};

export const sampleVerification: ChainVerification = {
  ok: true,
  checked: 1,
  unsealed: 0,
  first_broken_run_id: null,
  reason: null,
  detail: null,
  anchor_run_id: null,
  anchor_previous_manifest_sha256: null,
};

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

export const sampleAlertCases: AlertCase[] = [
  {
    id: 7,
    run_id: sampleRuns[0].id,
    target_id: sampleRuns[0].target_id,
    created_at: '2026-10-01T06:12:00',
    run_status: 'success',
    risk_level: 'high',
    new_observable_count: 2,
    reason: 'new_observables',
    state: 'open',
    acknowledged_at: null,
    acknowledged_by: null,
    resolved_at: null,
    resolved_by: null,
    note: null,
  },
  {
    id: 8,
    run_id: sampleRuns[1].id,
    target_id: sampleRuns[1].target_id,
    created_at: '2026-09-30T06:05:00',
    run_status: 'failed',
    risk_level: 'unknown',
    new_observable_count: 0,
    reason: 'run_failure',
    state: 'acknowledged',
    acknowledged_at: '2026-09-30T07:00:00',
    acknowledged_by: 'ana',
    resolved_at: null,
    resolved_by: null,
    note: 'collector outage',
  },
];

/**
 * The alert routes keep state across a test (acknowledge, then resolve), on a
 * copy of the fixture so one test never sees another's triage.
 */
function alertRoutes(): Route[] {
  const cases = sampleAlertCases.map((row) => ({ ...row }));
  const act = (match: RegExpMatchArray, kind: 'ack' | 'resolve') => {
    const row = cases.find((candidate) => candidate.id === Number(match[1]));
    if (!row) return null;
    if (kind === 'ack') {
      row.state = 'acknowledged';
      row.acknowledged_at = '2026-10-01T09:00:00';
      row.acknowledged_by = 'tester';
    } else {
      row.state = 'resolved';
      row.resolved_at = '2026-10-01T09:30:00';
      row.resolved_by = 'tester';
    }
    return row;
  };
  return [
    {
      pattern: /^\/alerts(?:\?(.*))?$/,
      body: (match: RegExpMatchArray) => {
        const params = new URLSearchParams(match[1] ?? '');
        const target = params.get('target_id');
        const state = params.get('state');
        const items = cases.filter((row) => (!target || row.target_id === target) && (!state || row.state === state));
        return { items, total: items.length, limit: Number(params.get('limit') ?? 100), offset: 0 };
      },
    },
    { pattern: /^\/alerts\/(\d+)\/ack$/, body: (match: RegExpMatchArray) => act(match, 'ack') },
    { pattern: /^\/alerts\/(\d+)\/resolve$/, body: (match: RegExpMatchArray) => act(match, 'resolve') },
    { pattern: /^\/alerts\/(\d+)$/, body: (match: RegExpMatchArray) => cases.find((row) => row.id === Number(match[1])) ?? null },
  ];
}

type Route = {
  pattern: RegExp;
  status?: number;
  body: unknown | ((match: RegExpMatchArray) => unknown);
  /** Serve the body as text/plain instead of JSON (the Markdown report). */
  text?: boolean;
  headers?: Record<string, string>;
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
  { pattern: /^\/targets\/[^/]+\/chain\/verify$/, body: sampleVerification },
  // Binary exports: the body only has to be a blob the download helper can hand over.
  { pattern: /^\/runs\/\d+\/bundle$/, body: 'zip-bytes', headers: { 'Content-Disposition': 'attachment; filename="run-42-example-corp.zip"' } },
  { pattern: /^\/runs\/\d+\/report\.pdf$/, body: 'pdf-bytes' },
  { pattern: new RegExp(`^/runs/${sampleRuns[0].id}/report$`), body: '# Report\n\nTwo new subdomains.\n', text: true },
  {
    pattern: new RegExp(`^/runs/${sampleRuns[0].id}/manifest$`),
    body: { manifest_version: 1, run_id: sampleRuns[0].id, target_id: sampleRuns[0].target_id, artefacts: { 'report.md': 'sha256:1' }, signature: 'hmac-sha256:test' },
  },
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
  const routes = [...(options.routes ?? []), ...alertRoutes(), ...defaultRoutes];
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
        if (route.text) {
          return new Response(String(body), { status: route.status ?? 200, headers: { 'Content-Type': 'text/plain', ...route.headers } });
        }
        const response = jsonResponse(route.status ?? 200, body);
        for (const [name, value] of Object.entries(route.headers ?? {})) response.headers.set(name, value);
        return response;
      }
    }
    return jsonResponse(404, { detail: `Unmocked path ${path}` });
  });

  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}
