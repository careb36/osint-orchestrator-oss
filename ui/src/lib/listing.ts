import { parseApiDate } from './format';
import { RISK_RANK, type TargetRow } from './overview';
import type { DeltaRow, EvidenceRow, RunStatus, RunSummary } from '../types';

export type SortDirection = 'asc' | 'desc';
export type Sort<K extends string> = { key: K; dir: SortDirection };

/** Case-insensitive "every word matches somewhere" search over a few fields. */
export function matchesQuery(fields: Array<string | null | undefined>, query: string): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return true;
  const haystack = fields
    .filter((field): field is string => typeof field === 'string' && field.length > 0)
    .join(' ')
    .toLowerCase();
  return words.every((word) => haystack.includes(word));
}

function compare(a: string | number | null, b: string | number | null): number {
  if (a === b) return 0;
  if (a === null) return 1; // missing values sort last whatever the direction
  if (b === null) return -1;
  return typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b));
}

function sortBy<T>(items: T[], dir: SortDirection, pick: (item: T) => string | number | null): T[] {
  const sign = dir === 'asc' ? 1 : -1;
  return items
    .map((item, index) => ({ item, index }))
    .sort((x, y) => {
      const a = pick(x.item);
      const b = pick(y.item);
      // Missing values stay last in both directions; ties keep the input order.
      if (a === null || b === null) return compare(a, b) || x.index - y.index;
      return sign * compare(a, b) || x.index - y.index;
    })
    .map(({ item }) => item);
}

/** Terminal and active run statuses in a stable "attention" order for sorting. */
const STATUS_ORDER: Record<string, number> = { running: 0, pending: 1, failed: 2, partial: 3, success: 4 };

// ---------------------------------------------------------------- targets

export type EnabledFilter = 'all' | 'enabled' | 'disabled';
export type TargetSortKey = 'attention' | 'target' | 'lastRun' | 'status' | 'risk';
export type TargetFilters = {
  query: string;
  enabled: EnabledFilter;
  /** A run status, 'never' for targets without a run, or '' for all. */
  status: RunStatus | 'never' | '';
  /** A risk level or '' for all. */
  risk: string;
};

export function filterTargets(rows: TargetRow[], filters: TargetFilters): TargetRow[] {
  return rows.filter((row) => {
    if (filters.enabled === 'enabled' && !row.target.enabled) return false;
    if (filters.enabled === 'disabled' && row.target.enabled) return false;
    if (filters.status === 'never' && row.lastRun) return false;
    if (filters.status && filters.status !== 'never' && row.lastRun?.status !== filters.status) return false;
    if (filters.risk && row.latestRisk !== filters.risk) return false;
    const collectors = Object.entries(row.target.collectors ?? {})
      .filter(([, cfg]) => cfg && cfg.enabled)
      .map(([name]) => name);
    return matchesQuery([row.target.id, row.target.fqdn, row.target.purpose, ...collectors], filters.query);
  });
}

export function sortTargets(rows: TargetRow[], sort: Sort<TargetSortKey>): TargetRow[] {
  switch (sort.key) {
    case 'target':
      return sortBy(rows, sort.dir, (row) => row.target.fqdn.toLowerCase());
    case 'lastRun':
      return sortBy(rows, sort.dir, (row) => (row.lastRun ? parseApiDate(row.lastRun.started_at).getTime() : null));
    case 'status':
      return sortBy(rows, sort.dir, (row) => (row.lastRun ? (STATUS_ORDER[row.lastRun.status] ?? 9) : null));
    case 'risk':
      return sortBy(rows, sort.dir, (row) => RISK_RANK[row.latestRisk] ?? 0);
    case 'attention':
    default:
      return sortBy(rows, sort.dir, (row) => row.attention);
  }
}

// ------------------------------------------------------------------- runs

export type SinceFilter = '' | '24h' | '7d';
export type RunSortKey = 'started' | 'duration' | 'observables' | 'status' | 'target';
export type RunFilters = {
  query: string;
  target: string;
  status: RunStatus | '';
  since: SinceFilter;
};

const SINCE_MS: Record<Exclude<SinceFilter, ''>, number> = {
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
};

export function runDurationMs(run: RunSummary, now: Date): number | null {
  const end = run.finished_at ? parseApiDate(run.finished_at) : now;
  const ms = end.getTime() - parseApiDate(run.started_at).getTime();
  return Number.isFinite(ms) && ms >= 0 ? ms : null;
}

export function filterRuns(runs: RunSummary[], filters: RunFilters, now: Date): RunSummary[] {
  const sinceMs = filters.since ? now.getTime() - SINCE_MS[filters.since] : null;
  return runs.filter((run) => {
    if (filters.target && run.target_id !== filters.target) return false;
    if (filters.status && run.status !== filters.status) return false;
    if (sinceMs !== null && parseApiDate(run.started_at).getTime() < sinceMs) return false;
    return matchesQuery([String(run.id), run.target_id, run.error, run.collectors_run, run.report_path], filters.query);
  });
}

export function sortRuns(runs: RunSummary[], sort: Sort<RunSortKey>, now: Date): RunSummary[] {
  switch (sort.key) {
    case 'duration':
      return sortBy(runs, sort.dir, (run) => runDurationMs(run, now));
    case 'observables':
      return sortBy(runs, sort.dir, (run) => run.new_observables);
    case 'status':
      return sortBy(runs, sort.dir, (run) => STATUS_ORDER[run.status] ?? 9);
    case 'target':
      return sortBy(runs, sort.dir, (run) => run.target_id.toLowerCase());
    case 'started':
    default:
      return sortBy(runs, sort.dir, (run) => parseApiDate(run.started_at).getTime());
  }
}

// --------------------------------------------------------------- evidence

export type EvidenceSortKey = 'relevance' | 'confidence' | 'category' | 'title';
export type EvidenceFilters = { query: string; relevance: string; category: string };

const RELEVANCE_RANK: Record<string, number> = { high: 3, medium: 2, low: 1 };

export function filterEvidence(rows: EvidenceRow[], filters: EvidenceFilters): EvidenceRow[] {
  return rows.filter(
    (row) =>
      (!filters.relevance || row.relevance === filters.relevance) &&
      (!filters.category || row.category === filters.category) &&
      matchesQuery([row.title, row.url, row.rationale, row.category], filters.query),
  );
}

export function sortEvidence(rows: EvidenceRow[], sort: Sort<EvidenceSortKey>): EvidenceRow[] {
  switch (sort.key) {
    case 'confidence':
      return sortBy(rows, sort.dir, (row) => Number(row.confidence));
    case 'category':
      return sortBy(rows, sort.dir, (row) => row.category.toLowerCase());
    case 'title':
      return sortBy(rows, sort.dir, (row) => (row.title || row.url).toLowerCase());
    case 'relevance':
    default:
      return sortBy(rows, sort.dir, (row) => RELEVANCE_RANK[row.relevance] ?? 0);
  }
}

// ------------------------------------------------------------------ delta

export type DeltaFilters = { query: string; type: string };

export function filterDelta(rows: DeltaRow[], filters: DeltaFilters): DeltaRow[] {
  return rows.filter((row) => (!filters.type || row.stix_type === filters.type) && matchesQuery([row.value, row.stix_type], filters.query));
}

/** Distinct values of one field, sorted, for a filter's options. */
export function distinct<T>(items: T[], pick: (item: T) => string | null | undefined): string[] {
  return Array.from(new Set(items.map(pick).filter((value): value is string => Boolean(value)))).sort();
}
