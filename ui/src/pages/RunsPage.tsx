import { useQuery } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { StatusPill } from '../components/StatusPill';
import { api } from '../lib/api';
import { formatDateTime, formatDuration, runStatusTone } from '../lib/format';

const STATUSES = ['pending', 'running', 'success', 'partial', 'failed'] as const;

export function RunsPage() {
  const runs = useQuery({ queryKey: ['runs'], queryFn: () => api.getRuns() });
  const [targetFilter, setTargetFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  const targetIds = useMemo(() => Array.from(new Set((runs.data ?? []).map((run) => run.target_id))).sort(), [runs.data]);
  const visible = useMemo(
    () =>
      (runs.data ?? []).filter(
        (run) => (!targetFilter || run.target_id === targetFilter) && (!statusFilter || run.status === statusFilter),
      ),
    [runs.data, targetFilter, statusFilter],
  );

  if (runs.isLoading) {
    return (
      <PageLayout title="Runs" subtitle="Review recent execution history and current system activity.">
        <LoadingState message="Loading recent runs…" />
      </PageLayout>
    );
  }

  if (runs.error) {
    return (
      <PageLayout title="Runs" subtitle="Recent execution history is unavailable.">
        <ErrorState description="Unable to load run history." />
      </PageLayout>
    );
  }

  if (!runs.data || runs.data.length === 0) {
    return (
      <PageLayout title="Runs" subtitle="Recent execution history and current activities.">
        <EmptyState title="No runs yet" description="There are no recent runs to display. Start one from the Targets view." />
      </PageLayout>
    );
  }

  return (
    <PageLayout title="Runs" subtitle="The last 100 runs, newest first.">
      <div className="filters" role="group" aria-label="Filters">
        <label>
          <span className="label">Target</span>
          <select value={targetFilter} onChange={(event) => setTargetFilter(event.target.value)}>
            <option value="">All targets</option>
            {targetIds.map((id) => (
              <option key={id} value={id}>
                {id}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="label">Status</span>
          <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
            <option value="">All statuses</option>
            {STATUSES.map((status) => (
              <option key={status} value={status}>
                {status}
              </option>
            ))}
          </select>
        </label>
        <span className="muted" aria-live="polite">
          {visible.length} of {runs.data.length}
        </span>
      </div>
      {visible.length === 0 ? (
        <EmptyState title="No runs match" description="Clear a filter to see more runs." />
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">Run</th>
              <th scope="col">Target</th>
              <th scope="col">Status</th>
              <th scope="col">New observables</th>
              <th scope="col">Started</th>
              <th scope="col">Duration</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((run) => (
              <tr key={run.id}>
                <td>
                  <Link to={`/runs/${run.id}`}>#{run.id}</Link>
                </td>
                <td>
                  <Link to={`/targets/${encodeURIComponent(run.target_id)}`}>{run.target_id}</Link>
                </td>
                <td>
                  <StatusPill label={run.status} tone={runStatusTone(run.status)} />
                  {run.error ? <small className="error-text"> {run.error}</small> : null}
                </td>
                <td>{run.new_observables}</td>
                <td>{formatDateTime(run.started_at)}</td>
                <td>{formatDuration(run.started_at, run.finished_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </PageLayout>
  );
}
