import { parseApiDate } from './format';
import type { RiskTrend, RunStatus, RunSummary, TargetSummary } from '../types';

/** Risk levels as the backend ranks them (orchestrator/api.py::risk_trends). */
export const RISK_RANK: Record<string, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function isActiveStatus(status: RunStatus): boolean {
  return status === 'pending' || status === 'running';
}

export type TargetRow = {
  target: TargetSummary;
  lastRun: RunSummary | null;
  /** Latest and peak risk over the target's recent runs, 'unknown' without a finding. */
  latestRisk: string;
  peakRisk: string;
  active: boolean;
  /** Lower sorts first: what needs attention leads the table. */
  attention: number;
};

/**
 * One row per target joining the inventory, the newest run and the risk
 * trend. Ordered by attention: running first, then high or critical risk,
 * then a failed or partial last run, then targets never collected, then the
 * rest; ties keep the inventory order.
 */
export function buildTargetRows(targets: TargetSummary[], runs: RunSummary[], trends: RiskTrend[]): TargetRow[] {
  const lastRunByTarget = new Map<string, RunSummary>();
  for (const run of runs) {
    const seen = lastRunByTarget.get(run.target_id);
    if (!seen || parseApiDate(run.started_at) > parseApiDate(seen.started_at)) {
      lastRunByTarget.set(run.target_id, run);
    }
  }
  const trendByTarget = new Map(trends.map((trend) => [trend.target_id, trend]));

  const rows = targets.map((target, index): TargetRow & { index: number } => {
    const lastRun = lastRunByTarget.get(target.id) ?? null;
    const trend = trendByTarget.get(target.id);
    const latestRisk = trend?.latest_risk_level ?? 'unknown';
    const peakRisk = trend?.peak_risk_level ?? 'unknown';
    const active = lastRun ? isActiveStatus(lastRun.status) : false;
    let attention = 5;
    if (active) attention = 0;
    else if ((RISK_RANK[latestRisk] ?? 0) >= RISK_RANK.high) attention = 1;
    else if (lastRun && (lastRun.status === 'failed' || lastRun.status === 'partial')) attention = 2;
    else if (!lastRun && target.enabled) attention = 3;
    else if (!target.enabled) attention = 6;
    return { target, lastRun, latestRisk, peakRisk, active, attention, index };
  });

  return rows
    .sort((a, b) => a.attention - b.attention || a.index - b.index)
    .map(({ target, lastRun, latestRisk, peakRisk, active, attention }) => ({
      target,
      lastRun,
      latestRisk,
      peakRisk,
      active,
      attention,
    }));
}

export type Kpis = {
  activeRuns: number;
  runsLast24h: number;
  /** Success share of terminal runs in the loaded window, null without any. */
  successRate: number | null;
  /** Median minutes from started_at to finished_at over terminal runs (task completion time, ui/docs/kpis.md). */
  medianRunMinutes: number | null;
  terminalRuns: number;
  targetsAtRisk: number;
  enabledTargets: number;
  /** Enabled targets with at least one run in the last 7 days. */
  coveredTargets: number;
};

export function median(values: number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

/**
 * KPIs computable from what the API already returns (ui/docs/kpis.md
 * guardrail: nothing that needs telemetry the backend does not emit).
 */
export function computeKpis(targets: TargetSummary[], runs: RunSummary[], trends: RiskTrend[], now: Date): Kpis {
  const dayAgo = now.getTime() - 24 * 60 * 60 * 1000;
  const weekAgo = now.getTime() - 7 * 24 * 60 * 60 * 1000;
  const terminal = runs.filter((run) => !isActiveStatus(run.status));
  const durations = terminal
    .filter((run) => run.finished_at)
    .map((run) => (parseApiDate(run.finished_at as string).getTime() - parseApiDate(run.started_at).getTime()) / 60000)
    .filter((minutes) => Number.isFinite(minutes) && minutes >= 0);
  const recentTargets = new Set(
    runs.filter((run) => parseApiDate(run.started_at).getTime() >= weekAgo).map((run) => run.target_id),
  );
  const enabled = targets.filter((target) => target.enabled);
  const medianMinutes = median(durations);

  return {
    activeRuns: runs.filter((run) => isActiveStatus(run.status)).length,
    runsLast24h: runs.filter((run) => parseApiDate(run.started_at).getTime() >= dayAgo).length,
    successRate: terminal.length ? terminal.filter((run) => run.status === 'success').length / terminal.length : null,
    medianRunMinutes: medianMinutes === null ? null : Math.round(medianMinutes * 10) / 10,
    terminalRuns: terminal.length,
    targetsAtRisk: trends.filter((trend) => (RISK_RANK[trend.latest_risk_level] ?? 0) >= RISK_RANK.high).length,
    enabledTargets: enabled.length,
    coveredTargets: enabled.filter((target) => recentTargets.has(target.id)).length,
  };
}

export function formatPercent(value: number | null): string {
  return value === null ? '—' : `${Math.round(value * 100)}%`;
}

export function formatMinutes(value: number | null): string {
  if (value === null) return '—';
  if (value < 1) return '<1 min';
  return `${value} min`;
}
