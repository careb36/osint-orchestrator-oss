import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { RunChange } from '../components/RunChange';
import { SearchField } from '../components/SearchField';
import { SortableHeader } from '../components/SortableHeader';
import { StatusPill } from '../components/StatusPill';
import { useListControls } from '../hooks/useListControls';
import { useLocale } from '../i18n';
import { api } from '../lib/api';
import { formatDateTime, formatDuration, riskTone, runStatusTone } from '../lib/format';
import { runTransitions } from '../lib/history';
import { distinct, filterRuns, SINCE_OPTIONS, sortRuns, type RunSortKey, type SinceFilter } from '../lib/listing';
import { isActiveStatus } from '../lib/overview';
import type { RunStatus } from '../types';

const STATUSES: RunStatus[] = ['running', 'pending', 'failed', 'partial', 'success'];
const DEFAULTS = { q: '', target: '', status: '', since: '' };
const SORT_KEYS: RunSortKey[] = ['started', 'duration', 'observables', 'status', 'target', 'risk'];
const ACTIVE_REFRESH_MS = 10_000;

export function RunsPage() {
  const { t, tv, locale } = useLocale();
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
      <PageLayout title={t('runs.title')} subtitle={t('runs.loadingSubtitle')}>
        <LoadingState message={t('runs.loading')} />
      </PageLayout>
    );
  }

  if (runs.error) {
    return (
      <PageLayout title={t('runs.title')} subtitle={t('runs.downSubtitle')}>
        <ErrorState description={t('runs.down')} />
      </PageLayout>
    );
  }

  if (!runs.data || runs.data.length === 0) {
    return (
      <PageLayout title={t('runs.title')} subtitle={t('runs.emptySubtitle')}>
        <EmptyState title={t('runs.empty.title')} description={t('runs.empty.body')} />
      </PageLayout>
    );
  }

  const now = new Date();
  // Transitions are computed over the whole loaded window, not the filtered rows.
  const transitions = runTransitions(runs.data);
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
  const clearButton = (
    <button type="button" className="ghost-button" onClick={controls.clear}>
      {t('clearFilters')}
    </button>
  );

  return (
    <PageLayout title={t('runs.title')} subtitle={t('runs.subtitle', { count: runs.data.length })}>
      <div className="filters" role="search" aria-label={t('runs.filters')}>
        <SearchField label={t('search')} value={controls.get('q')} onChange={(value) => controls.set('q', value)} placeholder={t('runs.searchPlaceholder')} />
        <label>
          <span className="label">{t('col.target')}</span>
          <select value={controls.get('target')} onChange={(event) => controls.set('target', event.target.value)}>
            <option value="">{t('runs.allTargets')}</option>
            {targetIds.map((id) => (
              <option key={id} value={id}>
                {id}
              </option>
            ))}
          </select>
        </label>
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
        <label>
          <span className="label">{t('col.started')}</span>
          <select value={controls.get('since')} onChange={(event) => controls.set('since', event.target.value)}>
            <option value="">{t('runs.anyTime')}</option>
            <option value="24h">{t('runs.last24h')}</option>
            <option value="7d">{t('runs.last7d')}</option>
          </select>
        </label>
        <span className="count" role="status" aria-live="polite">
          {t('count.of', { visible: visible.length, total: runs.data.length })}
        </span>
        {controls.isFiltered ? clearButton : null}
      </div>
      {visible.length === 0 ? (
        <EmptyState title={t('runs.noMatch.title')} description={t('runs.noMatch.body')} action={clearButton} />
      ) : (
        <table className="data-table" role="table">
          <thead role="rowgroup">
            <tr role="row">
              <th role="columnheader" scope="col">{t('col.run')}</th>
              <SortableHeader label={t('col.target')} column="target" sort={controls.sort} onSort={controls.toggleSort} />
              <SortableHeader label={t('col.status')} column="status" sort={controls.sort} onSort={controls.toggleSort} />
              <SortableHeader label={t('col.risk')} column="risk" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
              <th role="columnheader" scope="col">{t('col.change')}</th>
              <SortableHeader label={t('col.newObservables')} column="observables" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
              <SortableHeader label={t('col.started')} column="started" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
              <SortableHeader label={t('col.duration')} column="duration" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
            </tr>
          </thead>
          <tbody role="rowgroup">
            {visible.map((run) => {
              const active = isActiveStatus(run.status);
              return (
                <tr role="row" key={run.id}>
                  <td role="cell" data-label={t('col.run')}>
                    <Link to={`/runs/${run.id}`}>#{run.id}</Link>
                  </td>
                  <td role="cell" data-label={t('col.target')}>
                    <Link to={`/targets/${encodeURIComponent(run.target_id)}`}>{run.target_id}</Link>
                  </td>
                  <td role="cell" data-label={t('col.status')}>
                    <StatusPill label={run.status} tone={runStatusTone(run.status)} />
                    {run.error ? <small className="error-text"> {run.error}</small> : null}
                  </td>
                  <td role="cell" data-label={t('col.risk')}>{run.risk_level ? <StatusPill label={run.risk_level} tone={riskTone(run.risk_level)} /> : <span className="muted">—</span>}</td>
                  <td role="cell" data-label={t('col.change')}>
                    <RunChange transition={transitions.get(run.id)} />
                  </td>
                  <td role="cell" data-label={t('col.newObservables')}>{run.new_observables}</td>
                  <td role="cell" data-label={t('col.started')}>{formatDateTime(run.started_at, locale)}</td>
                  <td role="cell" data-label={t('col.duration')}>
                    {active ? (
                      <>
                        {formatDuration(run.started_at, now.toISOString())} <small className="muted">{t('soFar')}</small>
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
