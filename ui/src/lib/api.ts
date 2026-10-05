import type { HealthStatus, RunDetail, RunSummary, TargetSummary } from '../types';
import { reportUiError, trackUiTelemetry } from './telemetry';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '/api';
const LEGACY_API_KEY_STORAGE_KEY = 'osint-operator-api-key';

class ApiError extends Error {
  constructor(
    message: string,
    public status?: number,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

function getLegacyApiKey(): string | undefined {
  if (typeof window === 'undefined') {
    return undefined;
  }

  const key = window.sessionStorage.getItem(LEGACY_API_KEY_STORAGE_KEY);
  return key ? key.trim() : undefined;
}

async function request<T>(path: string, parseJson = true): Promise<T> {
  const legacyApiKey = getLegacyApiKey();
  const url = `${API_BASE_URL}${path}`;

  try {
    const response = await fetch(url, {
      headers: {
        Accept: parseJson ? 'application/json' : 'text/plain, application/json',
        ...(legacyApiKey ? { 'X-API-Key': legacyApiKey } : {}),
      },
    });

    if (response.status === 204) {
      return undefined as T;
    }

    if (!response.ok) {
      const message = `Request failed with status ${response.status}`;
      trackUiTelemetry('api_error', { path, status: response.status, message });
      throw new ApiError(message, response.status);
    }

    trackUiTelemetry('api_request', { path, status: response.status });

    if (!parseJson) {
      return (await response.text()) as T;
    }

    return (await response.json()) as T;
  } catch (error) {
    reportUiError(error, { source: 'api_request', path, url });
    throw error;
  }
}

export const api = {
  getHealth: () => request<HealthStatus>('/health'),
  getTargets: () => request<TargetSummary[]>('/targets'),
  getRuns: () => request<RunSummary[]>('/runs'),
  getRun: (runId: string) => request<RunDetail>(`/runs/${runId}`),
  getRunReport: (runId: string) => request<string>(`/runs/${runId}/report`, false),
  getRunFinding: (runId: string) => request<string>(`/runs/${runId}/finding`, false),
  getRunEvidence: (runId: string) => request<Array<Record<string, unknown>>>(`/runs/${runId}/evidence`),
  getRunManifest: (runId: string) => request<Record<string, unknown>>(`/runs/${runId}/manifest`),
};

export { ApiError };
