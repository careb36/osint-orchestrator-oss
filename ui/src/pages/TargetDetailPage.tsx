import { useQuery } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { StatusPill } from '../components/StatusPill';
import { api } from '../lib/api';
import { formatDateTime, formatDuration, runStatusTone } from '../lib/format';

export function TargetDetailPage() {
  const { targetId = '' } = useParams();
  const target = useQuery({ queryKey: ['target', targetId], queryFn: () => api.getTarget(targetId), enabled: Boolean(targetId) });
  const runs = useQuery({ queryKey: ['runs', targetId], queryFn: () => api.getRuns(targetId), enabled: Boolean(targetId) });

  const title = target.data?.fqdn ?? targetId;

  return (
    <PageLayout
      title={title}
      subtitle={target.data ? `${target.data.purpose} · authorisation: ${target.data.authorization}` : 'Target workspace'}
      actions={<Link to="/targets">Back to targets</Link>}
    >
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
        </div>
      ) : null}

      <h2 className="section-title">Runs</h2>
      {runs.isLoading ? <LoadingState message="Loading runs…" /> : null}
      {runs.error ? <ErrorState description="Unable to load this target's runs." /> : null}
      {runs.data && runs.data.length === 0 ? (
        <EmptyState title="No runs yet" description="This target has not been collected yet. Start a run from the Targets view." />
      ) : null}
      {runs.data && runs.data.length > 0 ? (
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
            {runs.data.map((run) => (
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
