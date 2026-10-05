import type { RunStatus } from '../types';

export type Tone = '' | 'ok' | 'warning' | 'error' | 'muted';

/** Visual tone of a run status: the five persisted values of RunStatus. */
export function runStatusTone(status: RunStatus): Tone {
  switch (status) {
    case 'success':
      return 'ok';
    case 'partial':
      return 'warning';
    case 'failed':
      return 'error';
    case 'pending':
    case 'running':
      return 'muted';
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

export function formatDateTime(value: string | null | undefined): string {
  if (!value) {
    return '—';
  }
  const date = parseApiDate(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function formatDuration(startedAt: string, finishedAt: string | null): string {
  if (!finishedAt) {
    return '—';
  }
  const ms = parseApiDate(finishedAt).getTime() - parseApiDate(startedAt).getTime();
  if (!Number.isFinite(ms) || ms < 0) {
    return '—';
  }
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) {
    return `${seconds}s`;
  }
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}
