import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { SearchField } from '../components/SearchField';
import { SortableHeader } from '../components/SortableHeader';
import { StatusPill } from '../components/StatusPill';
import { useListControls } from '../hooks/useListControls';
import { api } from '../lib/api';
import { formatDateTime, formatDuration, runStatusTone } from '../lib/format';
import { distinct, filterRuns, SINCE_OPTIONS, sortRuns, type RunSortKey, type SinceFilter } from '../lib/listing';
import { isActiveStatus } from '../lib/overview';
import type { RunStatus } from '../types';

const STATUSES: RunStatus[] = ['running', 'pending', 'failed', 'partial', 'success'];
const DEFAULTS = { q: '', target: '', status: '', since: '' };
const SORT_KEYS: RunSortKey[] = ['started', 'duration', 'observables', 'status', 'target'];
const ACTIVE_REFRESH_MS = 10_000;

export function RunsPage() {
  const runs = useQuery({
    queryKey: ['runs'],
    queryFn: () => api.getRuns(),
    refetchInterval: (query) => ((query.state.data ?? []).some((run) => isActiveStatus(run.status)) ? ACTIVE_REFRESH_MS : false),
  });
  // The target list is only known once the runs are loaded; an unknown target in the URL reads as "all".
  const targetIds = distinct(runs.data ?? [], (run) => run.target_id);
  const controls = useListControls<RunSortKey>({
    defaults: DEFAULTS,
    defaultSort: { key: 'started', dir: 'desc' },
    sortKeys: SORT_KEYS,
    allowed: { target: ['', ...targetIds], status: ['', ...STATUSES], since: SINCE_OPTIONS },
  });

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

  const now = new Date();
  const visible = sortRuns(
    filterRuns(
      runs.data,
      {
        query: controls.get('q'),
        target: controls.get('target'),
        status: controls.get('status') as RunStatus | '',
        since: controls.get('since') as SinceFilter,
      },
      now,
    ),
    controls.sort,
    now,
  );

  return (
    <PageLayout title="Runs" subtitle={`The ${runs.data.length} most recent runs the API returns (at most 100).`}>
      <div className="filters" role="search" aria-label="Filter runs">
        <SearchField label="Search" value={controls.get('q')} onChange={(value) => controls.set('q', value)} placeholder="run id, target, collector or error" />
        <label>
          <span className="label">Target</span>
          <select value={controls.get('target')} onChange={(event) => controls.set('target', event.target.value)}>
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
          <select value={controls.get('status')} onChange={(event) => controls.set('status', event.target.value)}>
            <option value="">All statuses</option>
            {STATUSES.map((status) => (
              <option key={status} value={status}>
                {status}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="label">Started</span>
          <select value={controls.get('since')} onChange={(event) => controls.set('since', event.target.value)}>
            <option value="">Any time</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
          </select>
        </label>
        <span className="count" role="status" aria-live="polite">
          {visible.length} of {runs.data.length}
        </span>
        {controls.isFiltered ? (
          <button type="button" className="ghost-button" onClick={controls.clear}>
            Clear filters
          </button>
        ) : null}
      </div>
      {visible.length === 0 ? (
        <EmptyState
          title="No runs match"
          description="Clear a filter or widen the search to see more runs."
          action={
            <button type="button" className="ghost-button" onClick={controls.clear}>
              Clear filters
            </button>
          }
        />
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">Run</th>
              <SortableHeader label="Target" column="target" sort={controls.sort} onSort={controls.toggleSort} />
              <SortableHeader label="Status" column="status" sort={controls.sort} onSort={controls.toggleSort} />
              <SortableHeader label="New observables" column="observables" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
              <SortableHeader label="Started" column="started" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
              <SortableHeader label="Duration" column="duration" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
            </tr>
          </thead>
          <tbody>
            {visible.map((run) => {
              const active = isActiveStatus(run.status);
              return (
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
                  <td>
                    {active ? (
                      <>
                        {formatDuration(run.started_at, now.toISOString())} <small className="muted">so far</small>
                      </>
                    ) : (
                      formatDuration(run.started_at, run.finished_at)
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </PageLayout>
  );
}
