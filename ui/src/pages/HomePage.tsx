import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { StatusPill } from '../components/StatusPill';
import { api } from '../lib/api';
import { formatDateTime, runStatusTone } from '../lib/format';
import type { HealthCheck, RunSummary } from '../types';

function healthTone(status: string) {
  if (status === 'ok') return 'ok';
  if (status === 'degraded') return 'warning';
  if (status === 'offline') return 'error';
  return 'muted';
}

function countByStatus(runs: RunSummary[]) {
  const counts = { success: 0, partial: 0, failed: 0, active: 0 };
  for (const run of runs) {
    if (run.status === 'success') counts.success += 1;
    else if (run.status === 'partial') counts.partial += 1;
    else if (run.status === 'failed') counts.failed += 1;
    else counts.active += 1;
  }
  return counts;
}

export function HomePage() {
  const health = useQuery({ queryKey: ['health'], queryFn: api.getHealth });
  const targets = useQuery({ queryKey: ['targets'], queryFn: () => api.getTargets() });
  const runs = useQuery({ queryKey: ['runs'], queryFn: () => api.getRuns() });

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

  const checks = Object.entries(health.data?.checks ?? {}) as Array<[string, HealthCheck]>;
  const runList = runs.data ?? [];
  const counts = countByStatus(runList);
  const recent = runList.slice(0, 8);

  return (
    <PageLayout title="Overview" subtitle="Service health, target coverage and the latest runs at a glance.">
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

      <section aria-labelledby="summary-title">
        <h2 id="summary-title" className="section-title">
          Activity
        </h2>
        <div className="stats-grid">
          <div className="state-card">
            <span className="label">Targets</span>
            <strong>{targets.data?.length ?? '—'}</strong>
            <small>{targets.data ? `${targets.data.filter((t) => t.enabled).length} enabled` : 'inventory unavailable'}</small>
          </div>
          <div className="state-card ok">
            <span className="label">Successful runs</span>
            <strong>{counts.success}</strong>
            <small>of the last {runList.length}</small>
          </div>
          <div className="state-card warning">
            <span className="label">Partial</span>
            <strong>{counts.partial}</strong>
            <small>some collector failed</small>
          </div>
          <div className="state-card error">
            <span className="label">Failed</span>
            <strong>{counts.failed}</strong>
            <small>{counts.active} active</small>
          </div>
        </div>
      </section>

      <section aria-labelledby="recent-title">
        <h2 id="recent-title" className="section-title">
          Recent runs
        </h2>
        {runs.error ? <ErrorState description="Run history is unavailable." /> : null}
        {!runs.error && recent.length === 0 ? (
          <EmptyState
            title="No runs yet"
            description="Start a run from the Targets view; it appears here as soon as it is accepted."
            action={<Link to="/targets">Go to targets</Link>}
          />
        ) : null}
        {recent.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Run</th>
                <th scope="col">Target</th>
                <th scope="col">Status</th>
                <th scope="col">New observables</th>
                <th scope="col">Started</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((run) => (
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
                  <td>{run.new_observables}</td>
                  <td>{formatDateTime(run.started_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>
    </PageLayout>
  );
}
