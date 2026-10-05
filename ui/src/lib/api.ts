import type {
  DeltaRow,
  EvidenceRow,
  Finding,
  HealthStatus,
  RiskTrend,
  RunDetail,
  RunSummary,
  TargetSummary,
  TriggerRunResponse,
} from '../types';
import { reportUiError, trackUiTelemetry } from './telemetry';

// Same origin by default: the orchestrator serves this app under /console and
// the API at the root. In `npm run dev` the Vite server proxies the API paths
// to the orchestrator (ui/vite.config.ts), so the default holds there too;
// VITE_API_BASE_URL exists only to point at another origin explicitly.
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '');

export const API_KEY_STORAGE_KEY = 'osint-operator-api-key';
export const API_KEY_REMEMBER_KEY = 'osint-operator-api-key-remember';
/** Dispatched on window when the backend answers 401: the key is gone or wrong. */
export const UNAUTHORIZED_EVENT = 'osint-unauthorized';

export class ApiError extends Error {
  constructor(
    message: string,
    public status?: number,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

function storage(kind: 'session' | 'local'): Storage | null {
  try {
    return kind === 'session' ? window.sessionStorage : window.localStorage;
  } catch {
    return null;
  }
}

/** The operator's key: this tab's session first, then a remembered one. */
export function readApiKey(): string | null {
  const fromSession = storage('session')?.getItem(API_KEY_STORAGE_KEY);
  if (fromSession) {
    return fromSession;
  }
  return storage('local')?.getItem(API_KEY_STORAGE_KEY) ?? null;
}

export function storeApiKey(key: string, remember: boolean): void {
  const trimmed = key.trim();
  storage('session')?.setItem(API_KEY_STORAGE_KEY, trimmed);
  if (remember) {
    storage('local')?.setItem(API_KEY_STORAGE_KEY, trimmed);
    storage('local')?.setItem(API_KEY_REMEMBER_KEY, '1');
  } else {
    storage('local')?.removeItem(API_KEY_STORAGE_KEY);
    storage('local')?.removeItem(API_KEY_REMEMBER_KEY);
  }
}

/** True when the operator asked to keep the key on this browser. */
export function isKeyRemembered(): boolean {
  return storage('local')?.getItem(API_KEY_REMEMBER_KEY) === '1';
}

/**
 * Drop the key everywhere. The "remember" preference stays: it holds no
 * secret, and the gate uses it to pre-tick the checkbox for the next key.
 * Only `storeApiKey(key, false)` clears it.
 */
export function clearApiKey(): void {
  storage('session')?.removeItem(API_KEY_STORAGE_KEY);
  storage('local')?.removeItem(API_KEY_STORAGE_KEY);
}

type RequestOptions = {
  method?: 'GET' | 'POST';
  parse?: 'json' | 'text' | 'blob';
  body?: unknown;
  /** Try this key instead of the stored one (used to validate a key before storing it). */
  apiKey?: string | null;
  /** Do not announce a 401 (used by the key gate's own probe). */
  quiet?: boolean;
};

export function authHeaders(apiKey?: string | null): Record<string, string> {
  const key = apiKey === undefined ? readApiKey() : apiKey;
  return key ? { 'X-API-Key': key } : {};
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', parse = 'json', body, apiKey, quiet = false } = options;
  const url = `${API_BASE_URL}${path}`;
  const headers: Record<string, string> = {
    Accept: parse === 'json' ? 'application/json' : 'text/plain, application/json',
    ...authHeaders(apiKey),
  };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  try {
    const response = await fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });

    if (!response.ok) {
      let detail = `Request failed with status ${response.status}`;
      try {
        const payload = (await response.json()) as { detail?: unknown };
        if (typeof payload.detail === 'string') {
          detail = payload.detail;
        }
      } catch {
        // No JSON body: keep the generic message.
      }
      if (response.status === 401 && !quiet) {
        window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
      }
      trackUiTelemetry('api_error', { path, status: response.status, message: detail });
      throw new ApiError(detail, response.status);
    }

    trackUiTelemetry('api_request', { path, status: response.status });

    if (response.status === 204) {
      return undefined as T;
    }
    if (parse === 'text') {
      return (await response.text()) as T;
    }
    if (parse === 'blob') {
      return (await response.blob()) as T;
    }
    return (await response.json()) as T;
  } catch (error) {
    if (!(error instanceof ApiError)) {
      reportUiError(error, { source: 'api_request', path });
    }
    throw error;
  }
}

export const api = {
  getHealth: () => request<HealthStatus>('/health'),
  getTargets: (options?: Pick<RequestOptions, 'apiKey' | 'quiet'>) =>
    request<TargetSummary[]>('/targets', options),
  getTarget: (targetId: string) => request<TargetSummary>(`/targets/${encodeURIComponent(targetId)}`),
  getRuns: (targetId?: string) =>
    request<RunSummary[]>(targetId ? `/runs?target_id=${encodeURIComponent(targetId)}` : '/runs'),
  getRun: (runId: string | number) => request<RunDetail>(`/runs/${runId}`),
  getRunDelta: (runId: string | number) => request<DeltaRow[]>(`/runs/${runId}/delta`),
  getRunReport: (runId: string | number) => request<string>(`/runs/${runId}/report`, { parse: 'text' }),
  getRunFinding: (runId: string | number) => request<Finding>(`/runs/${runId}/finding`),
  getRunEvidence: (runId: string | number) => request<EvidenceRow[]>(`/runs/${runId}/evidence`),
  getRunManifest: (runId: string | number) => request<Record<string, unknown>>(`/runs/${runId}/manifest`),
  getRiskTrends: () => request<RiskTrend[]>('/analytics/risk-trends'),
  triggerRun: (targetId: string) =>
    request<TriggerRunResponse>(`/targets/${encodeURIComponent(targetId)}/run`, { method: 'POST' }),
};

/**
 * Download an artefact through fetch (a plain <a download> cannot send the
 * API key header) and hand the bytes to the browser as a file.
 */
export async function downloadArtifact(runId: string | number, artifact: 'report' | 'finding' | 'evidence' | 'manifest' | 'delta') {
  const isText = artifact === 'report';
  const blob = await request<Blob>(`/runs/${runId}/${artifact}`, { parse: 'blob' });
  const extension = isText ? 'md' : 'json';
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `run-${runId}-${artifact}.${extension}`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  // Revoking in the same task as click() can abort the transfer (Firefox,
  // some Safari versions): let the browser start reading the blob first.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
