import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { SortableHeader } from '../components/SortableHeader';
import { StatusPill } from '../components/StatusPill';
import { useListControls } from '../hooks/useListControls';
import { useLocale } from '../i18n';
import { api, ApiError } from '../lib/api';
import { alertCaseTone, alertReasonTone, formatDateTime, parseApiDate, riskTone, runStatusTone } from '../lib/format';
import { distinct } from '../lib/listing';
import type { AlertCase } from '../types';

/** The operator's name travels with every acknowledgement; remembered per browser. */
export const OPERATOR_NAME_KEY = 'osint-operator-name';

const STATES = ['open', 'acknowledged', 'resolved'] as const;
// `all` is a real value: a blank would read as the default (open) again.
const STATE_FILTERS = [...STATES, 'all'] as const;
const DEFAULTS = { target: '', state: 'open' };
type SortKey = 'opened' | 'risk' | 'target' | 'state';
const SORT_KEYS: SortKey[] = ['opened', 'risk', 'target', 'state'];
const RISK_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const STATE_ORDER: Record<string, number> = { open: 0, acknowledged: 1, resolved: 2 };
const PAGE = 200;

function readOperatorName(): string {
  try {
    return window.localStorage.getItem(OPERATOR_NAME_KEY) ?? '';
  } catch {
    return '';
  }
}

function storeOperatorName(name: string): void {
  try {
    if (name) window.localStorage.setItem(OPERATOR_NAME_KEY, name);
    else window.localStorage.removeItem(OPERATOR_NAME_KEY);
  } catch {
    // Private mode or blocked storage: the name still works for this page.
  }
}

function sortCases(rows: AlertCase[], sort: { key: SortKey; dir: 'asc' | 'desc' }): AlertCase[] {
  const sign = sort.dir === 'asc' ? 1 : -1;
  return [...rows].sort((a, b) => {
    let delta = 0;
    switch (sort.key) {
      case 'opened':
        delta = parseApiDate(a.created_at).getTime() - parseApiDate(b.created_at).getTime();
        break;
      case 'risk':
        delta = (RISK_ORDER[a.risk_level] ?? 0) - (RISK_ORDER[b.risk_level] ?? 0);
        break;
      case 'target':
        delta = a.target_id.localeCompare(b.target_id);
        break;
      case 'state':
        delta = (STATE_ORDER[a.state] ?? 9) - (STATE_ORDER[b.state] ?? 9);
        break;
    }
    return delta !== 0 ? delta * sign : b.id - a.id;
  });
}

export function AlertsPage() {
  const { t, tv, locale } = useLocale();
  const queryClient = useQueryClient();
  const controls = useListControls<SortKey>({
    defaults: DEFAULTS,
    defaultSort: { key: 'opened', dir: 'desc' },
    sortKeys: SORT_KEYS,
    allowed: { state: [...STATE_FILTERS] },
  });
  const stateFilter = controls.get('state');
  const targetFilter = controls.get('target');
  const [operator, setOperator] = useState(readOperatorName);
  const [note, setNote] = useState('');

  // The target filter is sent to the API; the state filter too, except `all`.
  const cases = useQuery({
    queryKey: ['alerts', targetFilter, stateFilter],
    queryFn: () =>
      api.getAlerts({
        targetId: targetFilter || undefined,
        state: stateFilter === 'all' ? undefined : stateFilter,
        limit: PAGE,
      }),
  });
  // Targets for the filter come from an unfiltered listing, so the choice never disappears.
  const targets = useQuery({ queryKey: ['alerts', '', 'all'], queryFn: () => api.getAlerts({ limit: PAGE }) });
  const targetIds = distinct(targets.data?.items ?? [], (row) => row.target_id);

  const action = useMutation({
    mutationFn: ({ caseId, kind }: { caseId: number; kind: 'ack' | 'resolve' }) => {
      const body = { by: operator.trim(), note: note.trim() || undefined };
      return kind === 'ack' ? api.acknowledgeAlert(caseId, body) : api.resolveAlert(caseId, body);
    },
    onSuccess: () => {
      setNote('');
      void queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });
  const actionError = action.error instanceof ApiError ? action.error.message : action.error ? String(action.error) : null;
  const canAct = operator.trim().length > 0 && !action.isPending;

  if (cases.isLoading) {
    return (
      <PageLayout title={t('alerts.title')} subtitle={t('alerts.loadingSubtitle')}>
        <LoadingState message={t('alerts.loading')} />
      </PageLayout>
    );
  }

  if (cases.error || !cases.data) {
    return (
      <PageLayout title={t('alerts.title')} subtitle={t('alerts.downSubtitle')}>
        <ErrorState description={t('alerts.down')} />
      </PageLayout>
    );
  }

  const visible = sortCases(cases.data.items, controls.sort);
  const clearButton = (
    <button type="button" className="ghost-button" onClick={controls.clear}>
      {t('clearFilters')}
    </button>
  );

  return (
    <PageLayout title={t('alerts.title')} subtitle={t('alerts.subtitle', { total: cases.data.total })}>
      <div className="filters" role="search" aria-label={t('alerts.filters')}>
        <label>
          <span className="label">{t('col.target')}</span>
          <select value={targetFilter} onChange={(event) => controls.set('target', event.target.value)}>
            <option value="">{t('runs.allTargets')}</option>
            {targetIds.map((id) => (
              <option key={id} value={id}>
                {id}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="label">{t('col.state')}</span>
          <select value={stateFilter} onChange={(event) => controls.set('state', event.target.value)}>
            {STATES.map((state) => (
              <option key={state} value={state}>
                {tv(state)}
              </option>
            ))}
            <option value="all">{t('alerts.allStates')}</option>
          </select>
        </label>
        <span className="count" role="status" aria-live="polite">
          {t('count.of', { visible: visible.length, total: cases.data.total })}
        </span>
        {controls.isFiltered ? clearButton : null}
      </div>

      <div className="filters" role="group" aria-label={t('alerts.actionsGroup')}>
        <label>
          <span className="label">{t('alerts.operator')}</span>
          <input
            type="text"
            value={operator}
            maxLength={80}
            autoComplete="name"
            onChange={(event) => {
              setOperator(event.target.value);
              storeOperatorName(event.target.value.trim());
            }}
          />
        </label>
        <label>
          <span className="label">{t('alerts.note')}</span>
          <input type="text" value={note} maxLength={500} onChange={(event) => setNote(event.target.value)} />
        </label>
        <small className="muted">{operator.trim() ? t('alerts.operatorHelp') : t('alerts.needName')}</small>
      </div>
      {actionError ? (
        <p className="state-card error" role="alert">
          {t('alerts.actionFailed', { detail: actionError })}
        </p>
      ) : null}

      {visible.length === 0 ? (
        <EmptyState
          title={controls.isFiltered ? t('alerts.noMatch.title') : t('alerts.empty.title')}
          description={controls.isFiltered ? t('alerts.noMatch.body') : t('alerts.empty.body')}
          action={controls.isFiltered ? clearButton : undefined}
        />
      ) : (
        <table className="data-table" role="table">
          <thead role="rowgroup">
            <tr role="row">
              <th role="columnheader" scope="col">{t('col.case')}</th>
              <SortableHeader label={t('col.target')} column="target" sort={controls.sort} onSort={controls.toggleSort} />
              <th role="columnheader" scope="col">{t('col.run')}</th>
              <th role="columnheader" scope="col">{t('col.reason')}</th>
              <SortableHeader label={t('col.risk')} column="risk" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
              <th role="columnheader" scope="col">{t('col.newObservables')}</th>
              <SortableHeader label={t('col.opened')} column="opened" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
              <SortableHeader label={t('col.state')} column="state" sort={controls.sort} onSort={controls.toggleSort} />
              <th role="columnheader" scope="col">{t('col.actions')}</th>
            </tr>
          </thead>
          <tbody role="rowgroup">
            {visible.map((row) => (
              <tr role="row" key={row.id} data-state={row.state}>
                <td role="cell" data-label={t('col.case')}>#{row.id}</td>
                <td role="cell" data-label={t('col.target')}>
                  <Link to={`/targets/${encodeURIComponent(row.target_id)}`}>{row.target_id}</Link>
                </td>
                <td role="cell" data-label={t('col.run')}>
                  <Link to={`/runs/${row.run_id}`}>#{row.run_id}</Link> <StatusPill label={row.run_status} tone={runStatusTone(row.run_status)} />
                </td>
                <td role="cell" data-label={t('col.reason')}>
                  <StatusPill label={row.reason} tone={alertReasonTone(row.reason)} />
                </td>
                <td role="cell" data-label={t('col.risk')}>
                  <StatusPill label={row.risk_level} tone={riskTone(row.risk_level)} />
                </td>
                <td role="cell" data-label={t('col.newObservables')}>{row.new_observable_count}</td>
                <td role="cell" data-label={t('col.opened')}>{formatDateTime(row.created_at, locale)}</td>
                <td role="cell" data-label={t('col.state')}>
                  <StatusPill label={row.state} tone={alertCaseTone(row.state)} />
                  {row.acknowledged_by ? <small className="muted"> {t('alerts.handledBy', { name: row.resolved_by ?? row.acknowledged_by })}</small> : null}
                  {row.note ? <small className="muted"> · {row.note}</small> : null}
                </td>
                <td role="cell" data-label={t('col.actions')}>
                  {row.state === 'open' ? (
                    <button type="button" className="ghost-button" disabled={!canAct} onClick={() => action.mutate({ caseId: row.id, kind: 'ack' })}>
                      {t('alerts.acknowledge')}
                    </button>
                  ) : null}
                  {row.state !== 'resolved' ? (
                    <button type="button" className="ghost-button" disabled={!canAct} onClick={() => action.mutate({ caseId: row.id, kind: 'resolve' })}>
                      {t('alerts.resolve')}
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </PageLayout>
  );
}
