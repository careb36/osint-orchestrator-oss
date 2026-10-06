import { useQuery } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { RunChange } from '../components/RunChange';
import { RunNotice } from '../components/RunNotice';
import { StatusPill } from '../components/StatusPill';
import { useListControls } from '../hooks/useListControls';
import { useStartRun } from '../hooks/useStartRun';
import { useLocale } from '../i18n';
import { api } from '../lib/api';
import { formatDateTime, formatDuration, riskTone, runStatusTone } from '../lib/format';
import { runTransitions } from '../lib/history';
import { filterRuns, sortRuns, type RunSortKey } from '../lib/listing';
import { isActiveStatus } from '../lib/overview';
import type { RunStatus } from '../types';

const STATUSES: RunStatus[] = ['running', 'pending', 'failed', 'partial', 'success'];
const DEFAULTS = { status: '' };
const SORT_KEYS: RunSortKey[] = ['started'];
const ALLOWED = { status: ['', ...STATUSES] };

export function TargetDetailPage() {
  const { targetId = '' } = useParams();
  const { t, tv, locale } = useLocale();
  const target = useQuery({ queryKey: ['target', targetId], queryFn: () => api.getTarget(targetId), enabled: Boolean(targetId) });
  const runs = useQuery({ queryKey: ['runs', targetId], queryFn: () => api.getRuns(targetId), enabled: Boolean(targetId) });
  const trends = useQuery({ queryKey: ['risk-trends'], queryFn: api.getRiskTrends });
  const { start, isPending, notice } = useStartRun();
  const controls = useListControls<RunSortKey>({ defaults: DEFAULTS, defaultSort: { key: 'started', dir: 'desc' }, sortKeys: SORT_KEYS, allowed: ALLOWED });

  const title = target.data?.fqdn ?? targetId;
  const trend = trends.data?.find((row) => row.target_id === targetId);
  const latestRisk = trend?.latest_risk_level ?? 'unknown';
  const now = new Date();
  const active = (runs.data ?? []).some((run) => isActiveStatus(run.status));
  const transitions = runTransitions(runs.data ?? []);
  const chronological = runs.data ? sortRuns(runs.data, { key: 'started', dir: 'asc' }, now) : [];
  const visibleRuns = runs.data
    ? sortRuns(filterRuns(runs.data, { query: '', target: '', status: controls.get('status') as RunStatus | '', since: '' }, now), controls.sort, now)
    : [];

  return (
    <PageLayout
      title={title}
      subtitle={target.data ? t('target.subtitle', { purpose: target.data.purpose, authorization: target.data.authorization }) : t('target.workspace')}
      actions={
        <>
          <Link to="/targets">{t('target.back')}</Link>
          {target.data ? (
            <button type="button" className="primary-action" disabled={isPending || active || !target.data.enabled} onClick={() => start(targetId)}>
              {active ? t('run.running') : t('run.start')}
            </button>
          ) : null}
        </>
      }
    >
      <RunNotice notice={notice} />
      {target.isLoading ? <LoadingState message={t('target.loading')} /> : null}
      {target.error ? <ErrorState description={t('target.down', { targetId })} /> : null}

      {target.data ? (
        <div className="stats-grid">
          <div className="state-card">
            <span className="label">{t('target.enabled')}</span>
            <strong>{target.data.enabled ? t('yes') : t('no')}</strong>
          </div>
          <div className="state-card">
            <span className="label">{t('target.schedule')}</span>
            <strong>{String(target.data.schedule?.cron ?? '—')}</strong>
          </div>
          <div className="state-card">
            <span className="label">{t('target.llm')}</span>
            <strong>{target.data.llm ?? 'local'}</strong>
          </div>
          <div className="state-card">
            <span className="label">{t('target.risk')}</span>
            <strong>
              <StatusPill label={latestRisk} tone={riskTone(latestRisk)} />
            </strong>
            <small>
              {t('target.peak', {
                peak: tv(trend?.peak_risk_level ?? 'unknown'),
                count: trend?.runs_considered ?? 0,
                runs: trend?.runs_considered === 1 ? t('target.run') : t('target.runs'),
              })}
            </small>
            {trend && trend.risk_history.length > 1 ? (
              <div className="risk-history" aria-label={t('target.riskHistory')}>
                {trend.risk_history.map((level, index) => (
                  <StatusPill key={`${index}-${level}`} label={level} tone={riskTone(level)} />
                ))}
              </div>
            ) : null}
          </div>
        </div>
      ) : null}

      <h2 className="section-title">{t('target.runsTitle')}</h2>
      {runs.isLoading ? <LoadingState message={t('target.runsLoading')} /> : null}
      {runs.error ? <ErrorState description={t('target.runsDown')} /> : null}
      {runs.data && runs.data.length === 0 ? <EmptyState title={t('target.noRuns.title')} description={t('target.noRuns.body')} /> : null}
      {chronological.length > 1 ? (
        <ol className="run-timeline" aria-label={t('history.timeline')}>
          {chronological.map((run) => (
            <li key={run.id}>
              <Link
                to={`/targets/${encodeURIComponent(targetId)}/runs/${run.id}`}
                className={`timeline-dot tone-${runStatusTone(run.status) || 'muted'}`}
                aria-label={t('history.timelineItem', { runId: run.id, status: tv(run.status), risk: tv(run.risk_level ?? 'unknown') })}
                title={formatDateTime(run.started_at, locale)}
              >
                <span aria-hidden="true">#{run.id}</span>
              </Link>
            </li>
          ))}
        </ol>
      ) : null}
      {runs.data && runs.data.length > 0 ? (
        <div className="filters" role="search" aria-label={t('runs.filters')}>
          <label>
            <span className="label">{t('col.status')}</span>
            <select value={controls.get('status')} onChange={(event) => controls.set('status', event.target.value)}>
              <option value="">{t('runs.allStatuses')}</option>
              {STATUSES.map((status) => (
                <option key={status} value={status}>
                  {tv(status)}
                </option>
              ))}
            </select>
          </label>
          <span className="count" role="status" aria-live="polite">
            {t('count.of', { visible: visibleRuns.length, total: runs.data.length })}
          </span>
        </div>
      ) : null}
      {runs.data && runs.data.length > 0 && visibleRuns.length === 0 ? <EmptyState title={t('target.noMatch.title')} description={t('target.noMatch.body')} /> : null}
      {visibleRuns.length > 0 ? (
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">{t('col.run')}</th>
              <th scope="col">{t('col.status')}</th>
              <th scope="col">{t('col.risk')}</th>
              <th scope="col">{t('col.change')}</th>
              <th scope="col">{t('col.collectors')}</th>
              <th scope="col">{t('col.newObservables')}</th>
              <th scope="col">{t('col.started')}</th>
              <th scope="col">{t('col.duration')}</th>
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
                <td>{run.risk_level ? <StatusPill label={run.risk_level} tone={riskTone(run.risk_level)} /> : <span className="muted">—</span>}</td>
                <td>
                  <RunChange transition={transitions.get(run.id)} />
                </td>
                <td>{run.collectors_run || '—'}</td>
                <td>{run.new_observables}</td>
                <td>{formatDateTime(run.started_at, locale)}</td>
                <td>{formatDuration(run.started_at, run.finished_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </PageLayout>
  );
}
