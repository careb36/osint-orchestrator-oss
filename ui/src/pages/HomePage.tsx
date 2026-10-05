import { useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { RunNotice } from '../components/RunNotice';
import { StatusPill } from '../components/StatusPill';
import { useStartRun } from '../hooks/useStartRun';
import { useLocale } from '../i18n';
import { api, ApiError } from '../lib/api';
import { formatDateTime, formatDuration, riskTone, runStatusTone } from '../lib/format';
import { buildTargetRows, computeKpis, formatMinutes, formatPercent, isActiveStatus } from '../lib/overview';
import type { HealthCheck, RunSummary } from '../types';

const RECENT_FINDINGS = 5;
const ACTIVE_REFRESH_MS = 10_000;

function healthTone(status: string) {
  if (status === 'ok') return 'ok';
  if (status === 'degraded') return 'warning';
  if (status === 'offline') return 'error';
  return 'muted';
}

function hasActive(runs: RunSummary[] | undefined): boolean {
  return (runs ?? []).some((run) => isActiveStatus(run.status));
}

export function HomePage() {
  const { t, locale } = useLocale();
  const health = useQuery({ queryKey: ['health'], queryFn: api.getHealth });
  const targets = useQuery({ queryKey: ['targets'], queryFn: () => api.getTargets() });
  // While a run is pending or running the list refreshes itself.
  const runs = useQuery({
    queryKey: ['runs'],
    queryFn: () => api.getRuns(),
    refetchInterval: (query) => (hasActive(query.state.data) ? ACTIVE_REFRESH_MS : false),
  });
  const trends = useQuery({ queryKey: ['risk-trends'], queryFn: api.getRiskTrends });
  const { start, isPending, notice } = useStartRun();
  const queryClient = useQueryClient();

  const runList = runs.data ?? [];

  // When a run leaves the active set it has a terminal status, a possible
  // finding and a new place in the risk trend: refresh what depends on it.
  const activeIds = runList.filter((run) => isActiveStatus(run.status)).map((run) => run.id);
  const activeKey = activeIds.join(',');
  const previousActive = useRef<Set<number> | null>(null);
  useEffect(() => {
    const current = new Set(activeIds);
    const previous = previousActive.current;
    previousActive.current = current;
    if (previous && [...previous].some((id) => !current.has(id))) {
      void queryClient.invalidateQueries({ queryKey: ['risk-trends'] });
      void queryClient.invalidateQueries({ queryKey: ['finding'] });
    }
    // activeKey is the stable serialisation of activeIds.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeKey, queryClient]);

  const recentTerminal = runList.filter((run) => !isActiveStatus(run.status)).slice(0, RECENT_FINDINGS);
  // One bounded request per recent run; a 404 means the run has no finding.
  const findings = useQueries({
    queries: recentTerminal.map((run) => ({
      queryKey: ['finding', run.id],
      // A 404 is the normal answer for a run without synthesis: not an error to log.
      queryFn: () => api.getRunFinding(run.id, { optional: true }),
      retry: false,
      staleTime: Infinity,
    })),
  });

  if (health.isLoading || targets.isLoading || runs.isLoading) {
    return (
      <PageLayout title={t('overview.title')} subtitle={t('overview.loadingSubtitle')}>
        <LoadingState message={t('overview.loading')} />
      </PageLayout>
    );
  }

  if (health.error && targets.error) {
    return (
      <PageLayout title={t('overview.title')} subtitle={t('overview.downSubtitle')}>
        <ErrorState description={t('overview.down')} />
      </PageLayout>
    );
  }

  const now = new Date();
  const checks = Object.entries(health.data?.checks ?? {}) as Array<[string, HealthCheck]>;
  const targetList = targets.data ?? [];
  const trendList = trends.data ?? [];
  const rows = buildTargetRows(targetList, runList, trendList);
  const kpis = computeKpis(targetList, runList, trendList, now);
  const activeRuns = runList.filter((run) => isActiveStatus(run.status));
  const recentFindings = recentTerminal
    .map((run, index) => ({ run, query: findings[index] }))
    .filter(({ query }) => query.data)
    .map(({ run, query }) => ({ run, finding: query.data! }));
  const findingsLoading = findings.some((query) => query.isLoading);
  const findingsFailed = findings.filter((query) => query.error && !(query.error instanceof ApiError && query.error.status === 404));

  return (
    <PageLayout title={t('overview.title')} subtitle={t('overview.subtitle')}>
      <RunNotice notice={notice} />

      <section aria-labelledby="kpi-title">
        <h2 id="kpi-title" className="section-title">
          {t('overview.kpis')}
        </h2>
        <p className="helper-text">{t('overview.window', { count: kpis.runsLoaded })}</p>
        <dl className="kpi-grid">
          <div className="kpi">
            <dt>
              {t('kpi.activeRuns')}
              <small>{t('kpi.activeRuns.caption')}</small>
            </dt>
            <dd>{kpis.activeRuns}</dd>
          </div>
          <div className="kpi">
            <dt>
              {t('kpi.runs24h')}
              <small>{t('kpi.runs24h.caption')}</small>
            </dt>
            <dd>{kpis.runsLast24h}</dd>
          </div>
          <div className={`kpi ${kpis.successRate !== null && kpis.successRate < 0.8 ? 'warning' : ''}`.trim()}>
            <dt>
              {t('kpi.successRate')}
              <small>{t('kpi.successRate.caption', { count: kpis.terminalRuns })}</small>
            </dt>
            <dd>{formatPercent(kpis.successRate)}</dd>
          </div>
          <div className="kpi">
            <dt>
              {t('kpi.medianRun')}
              <small>{t('kpi.medianRun.caption')}</small>
            </dt>
            <dd>{formatMinutes(kpis.medianRunMinutes)}</dd>
          </div>
          <div className={`kpi ${kpis.targetsAtRisk ? 'error' : ''}`.trim()}>
            <dt>
              {t('kpi.atRisk')}
              <small>{t('kpi.atRisk.caption')}</small>
            </dt>
            <dd>{kpis.targetsAtRisk}</dd>
          </div>
          <div className={`kpi ${kpis.enabledTargets && kpis.coveredTargets < kpis.enabledTargets ? 'warning' : ''}`.trim()}>
            <dt>
              {t('kpi.coverage')}
              <small>{t('kpi.coverage.caption')}</small>
            </dt>
            <dd>
              {kpis.coveredTargets}/{kpis.enabledTargets}
            </dd>
          </div>
        </dl>
      </section>

      <section aria-labelledby="targets-title">
        <h2 id="targets-title" className="section-title">
          {t('overview.targets')}
        </h2>
        {targets.error ? <ErrorState description={t('overview.inventoryDown')} /> : null}
        {trends.error ? <p className="helper-text">{t('overview.trendsDown')}</p> : null}
        {!targets.error && rows.length === 0 ? <EmptyState title={t('overview.noTargets.title')} description={t('overview.noTargets.body')} /> : null}
        {rows.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">{t('col.target')}</th>
                <th scope="col">{t('col.lastRun')}</th>
                <th scope="col">{t('col.status')}</th>
                <th scope="col">{t('col.risk')}</th>
                <th scope="col">{t('col.peakRisk')}</th>
                <th scope="col">{t('col.newObservables')}</th>
                <th scope="col">{t('col.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ target, lastRun, latestRisk, peakRisk, active }) => (
                <tr key={target.id}>
                  <td>
                    <Link to={`/targets/${encodeURIComponent(target.id)}`}>
                      <strong>{target.fqdn}</strong>
                    </Link>
                    <br />
                    <small>
                      {target.id}
                      {target.enabled ? '' : t('disabledSuffix')}
                    </small>
                  </td>
                  <td>
                    {lastRun ? (
                      <Link to={`/runs/${lastRun.id}`}>
                        #{lastRun.id} · {formatDateTime(lastRun.started_at, locale)}
                      </Link>
                    ) : (
                      <span className="muted">{t('never')}</span>
                    )}
                  </td>
                  <td>{lastRun ? <StatusPill label={lastRun.status} tone={runStatusTone(lastRun.status)} /> : <span className="muted">{t('noRuns')}</span>}</td>
                  <td>
                    <StatusPill label={latestRisk} tone={riskTone(latestRisk)} />
                  </td>
                  <td>
                    <StatusPill label={peakRisk} tone={riskTone(peakRisk)} />
                  </td>
                  <td>{lastRun ? lastRun.new_observables : '—'}</td>
                  <td>
                    <button type="button" className="ghost-button" disabled={isPending || active || !target.enabled} onClick={() => start(target.id)}>
                      {active ? t('run.running') : t('run.start')}
                      <span className="visually-hidden">{t('run.startFor', { targetId: target.id })}</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>

      <section aria-labelledby="active-title">
        <h2 id="active-title" className="section-title">
          {t('overview.active')}
        </h2>
        {runs.error ? <ErrorState description={t('overview.runsDown')} /> : null}
        {!runs.error && activeRuns.length === 0 ? <EmptyState title={t('overview.nothingRunning.title')} description={t('overview.nothingRunning.body')} /> : null}
        {activeRuns.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">{t('col.run')}</th>
                <th scope="col">{t('col.target')}</th>
                <th scope="col">{t('col.status')}</th>
                <th scope="col">{t('col.started')}</th>
                <th scope="col">{t('col.elapsed')}</th>
              </tr>
            </thead>
            <tbody>
              {activeRuns.map((run) => (
                <tr key={run.id}>
                  <td>
                    <Link to={`/runs/${run.id}`}>#{run.id}</Link>
                  </td>
                  <td>
                    <Link to={`/targets/${encodeURIComponent(run.target_id)}`}>{run.target_id}</Link>
                  </td>
                  <td>
                    <StatusPill label={run.status} tone={runStatusTone(run.status)} />
                  </td>
                  <td>{formatDateTime(run.started_at, locale)}</td>
                  <td>{formatDuration(run.started_at, now.toISOString())}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>

      <section aria-labelledby="findings-title">
        <h2 id="findings-title" className="section-title">
          {t('overview.findings')}
        </h2>
        {findingsLoading ? <LoadingState message={t('overview.findingsLoading')} /> : null}
        {findingsFailed.length > 0 ? <ErrorState description={t('overview.findingsFailed', { count: findingsFailed.length })} /> : null}
        {!runs.error && !findingsLoading && recentTerminal.length === 0 ? (
          <EmptyState
            title={t('overview.noRuns.title')}
            description={t('overview.noRuns.body')}
            action={<Link to="/targets">{t('overview.goToTargets')}</Link>}
          />
        ) : null}
        {!findingsLoading && recentTerminal.length > 0 && recentFindings.length === 0 && findingsFailed.length === 0 ? (
          <EmptyState title={t('overview.noFindings.title')} description={t('overview.noFindings.body')} />
        ) : null}
        {recentFindings.length > 0 ? (
          <ul className="finding-list">
            {recentFindings.map(({ run, finding }) => (
              <li key={run.id} className="state-card">
                <div className="finding-head">
                  <StatusPill label={finding.risk_level} tone={riskTone(finding.risk_level)} />
                  <Link to={`/runs/${run.id}`}>{t('overview.findingLink', { runId: run.id, targetId: run.target_id })}</Link>
                  <small>{formatDateTime(finding.generated_at ?? run.finished_at ?? run.started_at, locale)}</small>
                </div>
                <p>{finding.summary}</p>
                {finding.new_since_last_run.length > 0 ? <small>{t('overview.newSince', { count: finding.new_since_last_run.length })}</small> : null}
              </li>
            ))}
          </ul>
        ) : null}
      </section>

      <section aria-labelledby="health-title">
        <h2 id="health-title" className="section-title">
          {t('overview.health')} {health.data ? <StatusPill label={health.data.status} tone={healthTone(health.data.status)} /> : null}
        </h2>
        {health.error ? <ErrorState description={t('overview.healthDown')} /> : null}
        <div className="stats-grid">
          {checks.map(([name, check]) => (
            <article key={name} className={`state-card ${healthTone(check.status)}`.trim()} data-status={check.status}>
              <span className="label">{name}</span>
              <strong>
                <StatusPill label={check.status} tone={healthTone(check.status)} />
              </strong>
              <small>{check.detail}</small>
            </article>
          ))}
        </div>
      </section>
    </PageLayout>
  );
}
