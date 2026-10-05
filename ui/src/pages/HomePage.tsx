import { useQueries, useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { RunNotice } from '../components/RunNotice';
import { StatusPill } from '../components/StatusPill';
import { useStartRun } from '../hooks/useStartRun';
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

  const runList = runs.data ?? [];
  const recentTerminal = runList.filter((run) => !isActiveStatus(run.status)).slice(0, RECENT_FINDINGS);
  // One bounded request per recent run; a 404 means the run has no finding.
  const findings = useQueries({
    queries: recentTerminal.map((run) => ({
      queryKey: ['finding', run.id],
      queryFn: () => api.getRunFinding(run.id),
      retry: false,
      staleTime: Infinity,
    })),
  });

  if (health.isLoading || targets.isLoading || runs.isLoading) {
    return (
      <PageLayout title="Overview" subtitle="Checking the current operating state.">
        <LoadingState message="Loading service health, targets and runs…" />
      </PageLayout>
    );
  }

  if (health.error && targets.error) {
    return (
      <PageLayout title="Overview" subtitle="The orchestrator API could not be reached.">
        <ErrorState description="Neither the health check nor the target inventory answered. Verify the API is running and reachable from this browser." />
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
    <PageLayout title="Overview" subtitle="What needs attention: active runs, risk, failures and coverage at a glance.">
      <RunNotice notice={notice} />

      <section aria-labelledby="kpi-title">
        <h2 id="kpi-title" className="section-title">
          Key figures
        </h2>
        <dl className="kpi-grid">
          <div className={`kpi ${kpis.activeRuns ? 'muted' : ''}`.trim()}>
            <dt>Active runs</dt>
            <dd>{kpis.activeRuns}</dd>
            <small>pending or running now</small>
          </div>
          <div className="kpi">
            <dt>Runs in 24 h</dt>
            <dd>{kpis.runsLast24h}</dd>
            <small>started in the last day</small>
          </div>
          <div className={`kpi ${kpis.successRate !== null && kpis.successRate < 0.8 ? 'warning' : ''}`.trim()}>
            <dt>Success rate</dt>
            <dd>{formatPercent(kpis.successRate)}</dd>
            <small>of {kpis.terminalRuns} finished runs loaded</small>
          </div>
          <div className="kpi">
            <dt>Median run time</dt>
            <dd>{formatMinutes(kpis.medianRunMinutes)}</dd>
            <small>task completion time, start to final status</small>
          </div>
          <div className={`kpi ${kpis.targetsAtRisk ? 'error' : ''}`.trim()}>
            <dt>Targets at risk</dt>
            <dd>{kpis.targetsAtRisk}</dd>
            <small>latest finding high or critical</small>
          </div>
          <div className={`kpi ${kpis.enabledTargets && kpis.coveredTargets < kpis.enabledTargets ? 'warning' : ''}`.trim()}>
            <dt>Coverage, 7 days</dt>
            <dd>
              {kpis.coveredTargets}/{kpis.enabledTargets}
            </dd>
            <small>enabled targets with a run this week</small>
          </div>
        </dl>
      </section>

      <section aria-labelledby="targets-title">
        <h2 id="targets-title" className="section-title">
          Targets by attention
        </h2>
        {targets.error ? <ErrorState description="The target inventory is unavailable." /> : null}
        {trends.error ? <p className="helper-text">Risk levels are unavailable right now; the table shows run status only.</p> : null}
        {!targets.error && rows.length === 0 ? (
          <EmptyState
            title="No targets configured"
            description="Add a target to targets.yaml and reload the scheduler; it appears here with its runs and risk."
          />
        ) : null}
        {rows.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Target</th>
                <th scope="col">Last run</th>
                <th scope="col">Status</th>
                <th scope="col">Risk</th>
                <th scope="col">Peak risk</th>
                <th scope="col">New observables</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ target, lastRun, latestRisk, peakRisk, active }) => (
                <tr key={target.id} data-attention={active ? 'active' : latestRisk}>
                  <td>
                    <Link to={`/targets/${encodeURIComponent(target.id)}`}>
                      <strong>{target.fqdn}</strong>
                    </Link>
                    <br />
                    <small>
                      {target.id}
                      {target.enabled ? '' : ' · disabled'}
                    </small>
                  </td>
                  <td>{lastRun ? <Link to={`/runs/${lastRun.id}`}>#{lastRun.id} · {formatDateTime(lastRun.started_at)}</Link> : <span className="muted">never</span>}</td>
                  <td>{lastRun ? <StatusPill label={lastRun.status} tone={runStatusTone(lastRun.status)} /> : <span className="muted">no runs</span>}</td>
                  <td>
                    <StatusPill label={latestRisk} tone={riskTone(latestRisk)} />
                  </td>
                  <td>
                    <StatusPill label={peakRisk} tone={riskTone(peakRisk)} />
                  </td>
                  <td>{lastRun ? lastRun.new_observables : '—'}</td>
                  <td>
                    <button
                      type="button"
                      className="ghost-button"
                      disabled={isPending || active || !target.enabled}
                      onClick={() => start(target.id)}
                    >
                      {active ? 'Running…' : 'Start run'}
                      <span className="visually-hidden"> for {target.id}</span>
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
          Active runs
        </h2>
        {runs.error ? <ErrorState description="Run history is unavailable." /> : null}
        {!runs.error && activeRuns.length === 0 ? (
          <EmptyState
            title="Nothing running"
            description="No run is pending or in progress. Start one from the table above; this list refreshes itself while it runs."
          />
        ) : null}
        {activeRuns.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Run</th>
                <th scope="col">Target</th>
                <th scope="col">Status</th>
                <th scope="col">Started</th>
                <th scope="col">Elapsed</th>
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
                  <td>{formatDateTime(run.started_at)}</td>
                  <td>{formatDuration(run.started_at, now.toISOString())}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>

      <section aria-labelledby="findings-title">
        <h2 id="findings-title" className="section-title">
          Recent findings
        </h2>
        {findingsLoading ? <LoadingState message="Loading findings…" /> : null}
        {findingsFailed.length > 0 ? <ErrorState description={`${findingsFailed.length} finding(s) could not be loaded.`} /> : null}
        {!findingsLoading && recentTerminal.length === 0 ? (
          <EmptyState
            title="No runs yet"
            description="Findings appear here once a run finishes with a model synthesis."
            action={<Link to="/targets">Go to targets</Link>}
          />
        ) : null}
        {!findingsLoading && recentTerminal.length > 0 && recentFindings.length === 0 && findingsFailed.length === 0 ? (
          <EmptyState
            title="No findings for the latest runs"
            description="The recent runs finished without a synthesis (no model configured, or the run failed before it). Open a run to see its evidence and delta."
          />
        ) : null}
        {recentFindings.length > 0 ? (
          <ul className="finding-list">
            {recentFindings.map(({ run, finding }) => (
              <li key={run.id} className="state-card">
                <div className="finding-head">
                  <StatusPill label={finding.risk_level} tone={riskTone(finding.risk_level)} />
                  <Link to={`/runs/${run.id}`}>
                    Run #{run.id} · {run.target_id}
                  </Link>
                  <small>{formatDateTime(finding.generated_at ?? run.finished_at ?? run.started_at)}</small>
                </div>
                <p>{finding.summary}</p>
                {finding.new_since_last_run.length > 0 ? (
                  <small>
                    {finding.new_since_last_run.length} new since last run
                  </small>
                ) : null}
              </li>
            ))}
          </ul>
        ) : null}
      </section>

      <section aria-labelledby="health-title">
        <h2 id="health-title" className="section-title">
          Service health{' '}
          {health.data ? <StatusPill label={health.data.status} tone={healthTone(health.data.status)} /> : null}
        </h2>
        {health.error ? <ErrorState description="The health endpoint did not answer." /> : null}
        <div className="stats-grid">
          {checks.map(([name, check]) => (
            <article key={name} className={`state-card ${healthTone(check.status)}`.trim()} data-status={check.status}>
              <span className="label">{name}</span>
              <strong>{check.status}</strong>
              <small>{check.detail}</small>
            </article>
          ))}
        </div>
      </section>
    </PageLayout>
  );
}
