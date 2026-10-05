import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { RunNotice } from '../components/RunNotice';
import { SearchField } from '../components/SearchField';
import { SortableHeader } from '../components/SortableHeader';
import { StatusPill } from '../components/StatusPill';
import { useListControls } from '../hooks/useListControls';
import { useStartRun } from '../hooks/useStartRun';
import { api } from '../lib/api';
import { formatDateTime, riskTone, runStatusTone } from '../lib/format';
import { filterTargets, sortTargets, type EnabledFilter, type TargetSortKey } from '../lib/listing';
import { buildTargetRows } from '../lib/overview';
import type { RunStatus, TargetSummary } from '../types';

const STATUSES: Array<RunStatus | 'never'> = ['running', 'pending', 'failed', 'partial', 'success', 'never'];
const RISKS = ['critical', 'high', 'medium', 'low', 'unknown'];
const DEFAULTS = { q: '', enabled: 'all', status: '', risk: '' };

function enabledCollectors(target: TargetSummary): string[] {
  return Object.entries(target.collectors ?? {})
    .filter(([, cfg]) => cfg && cfg.enabled)
    .map(([name]) => name);
}

export function TargetsPage() {
  const targets = useQuery({ queryKey: ['targets'], queryFn: () => api.getTargets() });
  const runs = useQuery({ queryKey: ['runs'], queryFn: () => api.getRuns() });
  const trends = useQuery({ queryKey: ['risk-trends'], queryFn: api.getRiskTrends });
  const { start, isPending, notice } = useStartRun();
  const controls = useListControls<TargetSortKey>(DEFAULTS, { key: 'attention', dir: 'asc' });

  if (targets.isLoading) {
    return (
      <PageLayout title="Targets" subtitle="Review the active target set and coverage status.">
        <LoadingState message="Loading targets…" />
      </PageLayout>
    );
  }

  if (targets.error) {
    return (
      <PageLayout title="Targets" subtitle="The target inventory is currently unavailable.">
        <ErrorState description="Unable to load targets." />
      </PageLayout>
    );
  }

  if (!targets.data || targets.data.length === 0) {
    return (
      <PageLayout title="Targets" subtitle="The target inventory for this operator workspace.">
        <EmptyState title="No targets configured" description="Add a target to targets.yaml and reload the scheduler to start tracking it." />
      </PageLayout>
    );
  }

  const rows = buildTargetRows(targets.data, runs.data ?? [], trends.data ?? []);
  const visible = sortTargets(
    filterTargets(rows, {
      query: controls.get('q'),
      enabled: controls.get('enabled') as EnabledFilter,
      status: controls.get('status') as RunStatus | 'never' | '',
      risk: controls.get('risk'),
    }),
    controls.sort,
  );

  return (
    <PageLayout title="Targets" subtitle="The target inventory for this operator workspace.">
      <RunNotice notice={notice} />
      {trends.error ? <p className="helper-text">Risk levels are unavailable right now; the table shows run status only.</p> : null}

      <div className="filters" role="search" aria-label="Filter targets">
        <SearchField label="Search" value={controls.get('q')} onChange={(value) => controls.set('q', value)} placeholder="id, domain, purpose or collector" />
        <label>
          <span className="label">Enabled</span>
          <select value={controls.get('enabled')} onChange={(event) => controls.set('enabled', event.target.value)}>
            <option value="all">All</option>
            <option value="enabled">Enabled only</option>
            <option value="disabled">Disabled only</option>
          </select>
        </label>
        <label>
          <span className="label">Last run</span>
          <select value={controls.get('status')} onChange={(event) => controls.set('status', event.target.value)}>
            <option value="">Any status</option>
            {STATUSES.map((status) => (
              <option key={status} value={status}>
                {status === 'never' ? 'never collected' : status}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="label">Risk</span>
          <select value={controls.get('risk')} onChange={(event) => controls.set('risk', event.target.value)}>
            <option value="">Any risk</option>
            {RISKS.map((risk) => (
              <option key={risk} value={risk}>
                {risk}
              </option>
            ))}
          </select>
        </label>
        <span className="count" role="status" aria-live="polite">
          {visible.length} of {rows.length}
        </span>
        {controls.isFiltered ? (
          <button type="button" className="ghost-button" onClick={controls.clear}>
            Clear filters
          </button>
        ) : null}
      </div>

      {visible.length === 0 ? (
        <EmptyState
          title="No targets match"
          description="Clear a filter or widen the search to see more targets."
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
              <SortableHeader label="Target" column="target" sort={controls.sort} onSort={controls.toggleSort} />
              <th scope="col">Collectors</th>
              <SortableHeader label="Last run" column="lastRun" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
              <SortableHeader label="Status" column="status" sort={controls.sort} onSort={controls.toggleSort} />
              <SortableHeader label="Risk" column="risk" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {visible.map(({ target, lastRun, latestRisk, active }) => (
              <tr key={target.id}>
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
                <td>{enabledCollectors(target).join(', ') || '—'}</td>
                <td>{lastRun ? <Link to={`/runs/${lastRun.id}`}>#{lastRun.id} · {formatDateTime(lastRun.started_at)}</Link> : <span className="muted">never</span>}</td>
                <td>{lastRun ? <StatusPill label={lastRun.status} tone={runStatusTone(lastRun.status)} /> : <span className="muted">no runs</span>}</td>
                <td>
                  <StatusPill label={latestRisk} tone={riskTone(latestRisk)} />
                </td>
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
      )}
    </PageLayout>
  );
}
