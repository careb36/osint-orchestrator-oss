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

export function formatDateTime(value: string | null | undefined): string {
  if (!value) {
    return '—';
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function formatDuration(startedAt: string, finishedAt: string | null): string {
  if (!finishedAt) {
    return '—';
  }
  const ms = new Date(finishedAt).getTime() - new Date(startedAt).getTime();
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
