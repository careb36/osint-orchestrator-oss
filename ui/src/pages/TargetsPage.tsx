import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { RunNotice } from '../components/RunNotice';
import { SearchField } from '../components/SearchField';
import { SortableHeader } from '../components/SortableHeader';
import { StatusPill } from '../components/StatusPill';
import { useListControls } from '../hooks/useListControls';
import { useStartRun } from '../hooks/useStartRun';
import { useLocale, type MessageKey } from '../i18n';
import { api } from '../lib/api';
import { formatDateTime, riskTone, runStatusTone } from '../lib/format';
import { filterTargets, sortTargets, type EnabledFilter, type TargetSortKey } from '../lib/listing';
import { buildTargetRows } from '../lib/overview';
import type { RunStatus, TargetSummary } from '../types';

const STATUSES: Array<RunStatus | 'never'> = ['running', 'pending', 'failed', 'partial', 'success', 'never'];
const RISKS = ['critical', 'high', 'medium', 'low', 'unknown'];
const ENABLED: EnabledFilter[] = ['all', 'enabled', 'disabled'];
const DEFAULTS = { q: '', enabled: 'all', status: '', risk: '' };
const SORT_KEYS: TargetSortKey[] = ['attention', 'target', 'lastRun', 'status', 'risk'];
const ALLOWED = { enabled: ENABLED, status: ['', ...STATUSES], risk: ['', ...RISKS] };

function enabledCollectors(target: TargetSummary): string[] {
  return Object.entries(target.collectors ?? {})
    .filter(([, cfg]) => cfg && cfg.enabled)
    .map(([name]) => name);
}

export function TargetsPage() {
  const { t, tv, locale } = useLocale();
  const targets = useQuery({ queryKey: ['targets'], queryFn: () => api.getTargets() });
  const runs = useQuery({ queryKey: ['runs'], queryFn: () => api.getRuns() });
  const trends = useQuery({ queryKey: ['risk-trends'], queryFn: api.getRiskTrends });
  const { start, isPending, notice } = useStartRun();
  const controls = useListControls<TargetSortKey>({ defaults: DEFAULTS, defaultSort: { key: 'attention', dir: 'asc' }, sortKeys: SORT_KEYS, allowed: ALLOWED });

  if (targets.isLoading) {
    return (
      <PageLayout title={t('targets.title')} subtitle={t('targets.loadingSubtitle')}>
        <LoadingState message={t('targets.loading')} />
      </PageLayout>
    );
  }

  if (targets.error) {
    return (
      <PageLayout title={t('targets.title')} subtitle={t('targets.downSubtitle')}>
        <ErrorState description={t('targets.down')} />
      </PageLayout>
    );
  }

  if (!targets.data || targets.data.length === 0) {
    return (
      <PageLayout title={t('targets.title')} subtitle={t('targets.subtitle')}>
        <EmptyState title={t('targets.empty.title')} description={t('targets.empty.body')} />
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
  const clearButton = (
    <button type="button" className="ghost-button" onClick={controls.clear}>
      {t('clearFilters')}
    </button>
  );

  return (
    <PageLayout title={t('targets.title')} subtitle={t('targets.subtitle')}>
      <RunNotice notice={notice} />
      {trends.error ? <p className="helper-text">{t('overview.trendsDown')}</p> : null}

      <div className="filters" role="search" aria-label={t('targets.filters')}>
        <SearchField label={t('search')} value={controls.get('q')} onChange={(value) => controls.set('q', value)} placeholder={t('targets.searchPlaceholder')} />
        <label>
          <span className="label">{t('targets.enabled')}</span>
          <select value={controls.get('enabled')} onChange={(event) => controls.set('enabled', event.target.value)}>
            {ENABLED.map((option) => (
              <option key={option} value={option}>
                {t(`targets.enabled.${option}` as MessageKey)}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="label">{t('col.lastRun')}</span>
          <select value={controls.get('status')} onChange={(event) => controls.set('status', event.target.value)}>
            <option value="">{t('targets.anyStatus')}</option>
            {STATUSES.map((status) => (
              <option key={status} value={status}>
                {status === 'never' ? t('targets.neverCollected') : tv(status)}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="label">{t('col.risk')}</span>
          <select value={controls.get('risk')} onChange={(event) => controls.set('risk', event.target.value)}>
            <option value="">{t('targets.anyRisk')}</option>
            {RISKS.map((risk) => (
              <option key={risk} value={risk}>
                {tv(risk)}
              </option>
            ))}
          </select>
        </label>
        <span className="count" role="status" aria-live="polite">
          {t('count.of', { visible: visible.length, total: rows.length })}
        </span>
        {controls.isFiltered ? clearButton : null}
      </div>

      {visible.length === 0 ? (
        <EmptyState title={t('targets.noMatch.title')} description={t('targets.noMatch.body')} action={clearButton} />
      ) : (
        <table className="data-table" role="table">
          <thead role="rowgroup">
            <tr role="row">
              <SortableHeader label={t('col.target')} column="target" sort={controls.sort} onSort={controls.toggleSort} />
              <th role="columnheader" scope="col">{t('col.collectors')}</th>
              <SortableHeader label={t('col.lastRun')} column="lastRun" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
              <SortableHeader label={t('col.status')} column="status" sort={controls.sort} onSort={controls.toggleSort} />
              <SortableHeader label={t('col.risk')} column="risk" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
              <th role="columnheader" scope="col">{t('col.actions')}</th>
            </tr>
          </thead>
          <tbody role="rowgroup">
            {visible.map(({ target, lastRun, latestRisk, active }) => (
              <tr role="row" key={target.id}>
                <td role="cell" data-label={t('col.target')}>
                  <Link to={`/targets/${encodeURIComponent(target.id)}`}>
                    <strong>{target.fqdn}</strong>
                  </Link>
                  <br />
                  <small>
                    {target.id}
                    {target.enabled ? '' : t('disabledSuffix')}
                  </small>
                </td>
                <td role="cell" data-label={t('col.collectors')}>{enabledCollectors(target).join(', ') || '—'}</td>
                <td role="cell" data-label={t('col.lastRun')}>
                  {lastRun ? (
                    <Link to={`/runs/${lastRun.id}`}>
                      #{lastRun.id} · {formatDateTime(lastRun.started_at, locale)}
                    </Link>
                  ) : (
                    <span className="muted">{t('never')}</span>
                  )}
                </td>
                <td role="cell" data-label={t('col.status')}>{lastRun ? <StatusPill label={lastRun.status} tone={runStatusTone(lastRun.status)} /> : <span className="muted">{t('noRuns')}</span>}</td>
                <td role="cell" data-label={t('col.risk')}>
                  <StatusPill label={latestRisk} tone={riskTone(latestRisk)} />
                </td>
                <td role="cell" data-label={t('col.actions')}>
                  <button type="button" className="ghost-button" disabled={isPending || active || !target.enabled} onClick={() => start(target.id)}>
                    {active ? t('run.running') : t('run.start')}
                    <span className="visually-hidden">{t('run.startFor', { targetId: target.id })}</span>
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
