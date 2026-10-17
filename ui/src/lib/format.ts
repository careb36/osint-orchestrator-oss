import type { RunStatus } from '../types';

export type Tone = '' | 'ok' | 'warning' | 'error' | 'muted' | 'info';

/** Visual tone of a run status: the five persisted values of RunStatus. */
export function runStatusTone(status: RunStatus): Tone {
  switch (status) {
    case 'success':
      return 'ok';
    case 'partial':
      return 'warning';
    case 'failed':
      return 'error';
    case 'running':
      return 'info';
    case 'pending':
      return 'muted';
    default:
      return '';
  }
}

/** Visual tone of an alert dispatch outcome (orchestrator/models.py::AlertStatus). */
export function alertStatusTone(status: string): Tone {
  switch (status) {
    case 'sent':
      return 'ok';
    case 'failed':
      return 'error';
    case 'skipped':
      return 'muted';
    default:
      return '';
  }
}

/** Visual tone of an alert case's triage state (orchestrator/models.py::AlertCaseState). */
export function alertCaseTone(state: string): Tone {
  switch (state) {
    case 'open':
      return 'warning';
    case 'acknowledged':
      return 'info';
    case 'resolved':
      return 'ok';
    default:
      return '';
  }
}

/** Visual tone of the rule that opened an alert case: a failed run is the loudest. */
export function alertReasonTone(reason: string): Tone {
  switch (reason) {
    case 'run_failure':
      return 'error';
    case 'risk_level':
      return 'warning';
    case 'new_observables':
      return 'info';
    default:
      return '';
  }
}

export function riskTone(level: string): Tone {
  switch (level) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'ok';
    default:
      return 'muted';
  }
}

// ISO date-time with an explicit zone: trailing Z or ±hh[:mm].
const HAS_OFFSET = /(Z|[+-]\d{2}(:?\d{2})?)$/i;

/**
 * Parse a timestamp from the API. Run timestamps are stored in SQLite, which
 * drops the offset, so they arrive as `2026-10-01T06:00:00`: a naive value is
 * UTC by the repository's convention, while `Date` would read it as local.
 */
export function parseApiDate(value: string): Date {
  const trimmed = value.trim();
  const isDateTime = trimmed.includes('T') || / \d{2}:\d{2}/.test(trimmed);
  return new Date(isDateTime && !HAS_OFFSET.test(trimmed) ? `${trimmed}Z` : trimmed);
}

export function formatDateTime(value: string | null | undefined, locale?: string): string {
  if (!value) {
    return '—';
  }
  const date = parseApiDate(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString(locale);
}

export function formatDuration(startedAt: string, finishedAt: string | null): string {
  if (!finishedAt) {
    return '—';
  }
  const ms = parseApiDate(finishedAt).getTime() - parseApiDate(startedAt).getTime();
  if (!Number.isFinite(ms) || ms < 0) {
    return '—';
  }
  // SI symbols (s, min), the same in Spanish and English; "m" would read as metres.
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) {
    return `${seconds} s`;
  }
  const minutes = Math.floor(seconds / 60);
  return `${minutes} min ${seconds % 60} s`;
}
