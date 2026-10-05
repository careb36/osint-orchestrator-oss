import { useQuery } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { RunNotice } from '../components/RunNotice';
import { StatusPill } from '../components/StatusPill';
import { useListControls } from '../hooks/useListControls';
import { useStartRun } from '../hooks/useStartRun';
import { api } from '../lib/api';
import { formatDateTime, formatDuration, riskTone, runStatusTone } from '../lib/format';
import { filterRuns, sortRuns, type RunSortKey } from '../lib/listing';
import { isActiveStatus } from '../lib/overview';
import type { RunStatus } from '../types';

const STATUSES: RunStatus[] = ['running', 'pending', 'failed', 'partial', 'success'];
const DEFAULTS = { status: '' };

export function TargetDetailPage() {
  const { targetId = '' } = useParams();
  const target = useQuery({ queryKey: ['target', targetId], queryFn: () => api.getTarget(targetId), enabled: Boolean(targetId) });
  const runs = useQuery({ queryKey: ['runs', targetId], queryFn: () => api.getRuns(targetId), enabled: Boolean(targetId) });
  const trends = useQuery({ queryKey: ['risk-trends'], queryFn: api.getRiskTrends });
  const { start, isPending, notice } = useStartRun();
  const controls = useListControls<RunSortKey>(DEFAULTS, { key: 'started', dir: 'desc' });

  const title = target.data?.fqdn ?? targetId;
  const trend = trends.data?.find((row) => row.target_id === targetId);
  const now = new Date();
  const active = (runs.data ?? []).some((run) => isActiveStatus(run.status));
  const visibleRuns = runs.data
    ? sortRuns(filterRuns(runs.data, { query: '', target: '', status: controls.get('status') as RunStatus | '', since: '' }, now), controls.sort, now)
    : [];

  return (
    <PageLayout
      title={title}
      subtitle={target.data ? `${target.data.purpose} · authorisation: ${target.data.authorization}` : 'Target workspace'}
      actions={
        <>
          <Link to="/targets">Back to targets</Link>
          {target.data ? (
            <button type="button" className="primary-action" disabled={isPending || active || !target.data.enabled} onClick={() => start(targetId)}>
              {active ? 'Running…' : 'Start run'}
            </button>
          ) : null}
        </>
      }
    >
      <RunNotice notice={notice} />
      {target.isLoading ? <LoadingState message="Loading target…" /> : null}
      {target.error ? <ErrorState description={`Target "${targetId}" could not be loaded.`} /> : null}

      {target.data ? (
        <div className="stats-grid">
          <div className="state-card">
            <span className="label">Enabled</span>
            <strong>{target.data.enabled ? 'Yes' : 'No'}</strong>
          </div>
          <div className="state-card">
            <span className="label">Schedule (UTC cron)</span>
            <strong>{String(target.data.schedule?.cron ?? '—')}</strong>
          </div>
          <div className="state-card">
            <span className="label">LLM route</span>
            <strong>{target.data.llm ?? 'local'}</strong>
          </div>
          <div className="state-card">
            <span className="label">Risk</span>
            <strong>
              <StatusPill label={trend?.latest_risk_level ?? 'unknown'} tone={riskTone(trend?.latest_risk_level ?? 'unknown')} />
            </strong>
            <small>
              peak {trend?.peak_risk_level ?? 'unknown'} over {trend?.runs_considered ?? 0} runs
            </small>
            {trend && trend.risk_history.length > 1 ? (
              <div className="risk-history" aria-label="Risk history, oldest first">
                {trend.risk_history.map((level, index) => (
                  <StatusPill key={`${index}-${level}`} label={level} tone={riskTone(level)} />
                ))}
              </div>
            ) : null}
          </div>
        </div>
      ) : null}

      <h2 className="section-title">Runs</h2>
      {runs.isLoading ? <LoadingState message="Loading runs…" /> : null}
      {runs.error ? <ErrorState description="Unable to load this target's runs." /> : null}
      {runs.data && runs.data.length === 0 ? (
        <EmptyState title="No runs yet" description="This target has not been collected yet. Use Start run above to collect it now." />
      ) : null}
      {runs.data && runs.data.length > 0 ? (
        <div className="filters" role="search" aria-label="Filter runs">
          <label>
            <span className="label">Status</span>
            <select value={controls.get('status')} onChange={(event) => controls.set('status', event.target.value)}>
              <option value="">All statuses</option>
              {STATUSES.map((status) => (
                <option key={status} value={status}>
                  {status}
                </option>
              ))}
            </select>
          </label>
          <span className="count" role="status" aria-live="polite">
            {visibleRuns.length} of {runs.data.length}
          </span>
        </div>
      ) : null}
      {runs.data && runs.data.length > 0 && visibleRuns.length === 0 ? (
        <EmptyState title="No runs match" description="Clear the status filter to see every run of this target." />
      ) : null}
      {visibleRuns.length > 0 ? (
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">Run</th>
              <th scope="col">Status</th>
              <th scope="col">Collectors</th>
              <th scope="col">New observables</th>
              <th scope="col">Started</th>
              <th scope="col">Duration</th>
            </tr>
          </thead>
          <tbody>
            {visibleRuns.map((run) => (
              <tr key={run.id}>
                <td>
                  <Link to={`/targets/${encodeURIComponent(targetId)}/runs/${run.id}`}>#{run.id}</Link>
                </td>
                <td>
                  <StatusPill label={run.status} tone={runStatusTone(run.status)} />
                </td>
                <td>{run.collectors_run || '—'}</td>
                <td>{run.new_observables}</td>
                <td>{formatDateTime(run.started_at)}</td>
                <td>{formatDuration(run.started_at, run.finished_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </PageLayout>
  );
}
