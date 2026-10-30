import { useMutation, useQuery } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { StageSummary } from '../components/StageSummary';
import { RunNotice } from '../components/RunNotice';
import { SearchField } from '../components/SearchField';
import { SortableHeader } from '../components/SortableHeader';
import { StatusPill } from '../components/StatusPill';
import { useListControls } from '../hooks/useListControls';
import { useStartRun } from '../hooks/useStartRun';
import { useLocale, type MessageKey } from '../i18n';
import { api, ApiError, downloadArtifact, downloadRunBundle, downloadRunPdf } from '../lib/api';
import { alertCaseTone, alertStatusTone, formatDateTime, formatDuration, riskTone, runStatusTone } from '../lib/format';
import { buildHandoffSummary, describeVerification } from '../lib/handoff';
import { distinct, filterDelta, filterEvidence, sortEvidence, type EvidenceSortKey } from '../lib/listing';
import { isActiveStatus } from '../lib/overview';
import type { ArtifactKind } from '../types';

const RELEVANCES = ['high', 'medium', 'low'];
// Evidence and observables keep separate keys: a term typed on one tab must
// not filter the other, and each tab's Clear filters touches its own keys only.
const EVIDENCE_KEYS = ['q', 'relevance', 'category'] as const;
const DELTA_KEYS = ['dq', 'type'] as const;
const DEFAULTS = { q: '', relevance: '', category: '', dq: '', type: '' };
const SORT_KEYS: EvidenceSortKey[] = ['relevance', 'confidence', 'category', 'title'];

const STORAGE_PREFIX = 'osint-run-workspace';
const ARTIFACTS: ArtifactKind[] = ['finding', 'evidence', 'delta', 'report', 'manifest'];

function readStoredArtifact(runId: string): ArtifactKind {
  try {
    const raw = window.sessionStorage.getItem(`${STORAGE_PREFIX}:${runId}`);
    const parsed = raw ? (JSON.parse(raw) as { artifact?: string }) : null;
    if (parsed?.artifact && (ARTIFACTS as string[]).includes(parsed.artifact)) {
      return parsed.artifact as ArtifactKind;
    }
  } catch {
    // Storage unavailable: fall back to the default tab.
  }
  return 'finding';
}

function isHttpUrl(value: string) {
  return /^https?:\/\//i.test(value);
}

export function RunWorkspacePage() {
  const { runId = '', targetId } = useParams();
  const { t, tv, locale } = useLocale();
  const [artifact, setArtifact] = useState<ArtifactKind>(() => readStoredArtifact(runId));
  const [downloadError, setDownloadError] = useState<string | null>(null);

  useEffect(() => {
    try {
      window.sessionStorage.setItem(`${STORAGE_PREFIX}:${runId}`, JSON.stringify({ artifact }));
    } catch {
      // Storage unavailable: nothing to persist.
    }
  }, [runId, artifact]);

  const run = useQuery({ queryKey: ['run', runId], queryFn: () => api.getRun(runId), enabled: Boolean(runId) });
  const finding = useQuery({ queryKey: ['run', runId, 'finding'], queryFn: () => api.getRunFinding(runId, { optional: true }), enabled: Boolean(runId) });
  // The run's alert case, if a rule fired: cases are listed per target, not per run.
  const alertCase = useQuery({
    queryKey: ['alerts', run.data?.target_id ?? '', 'all'],
    queryFn: () => api.getAlerts({ targetId: run.data!.target_id, limit: 200 }),
    enabled: Boolean(run.data?.target_id),
    select: (list) => list.items.find((row) => row.run_id === run.data?.id) ?? null,
  });
  // Loaded for every tab: the handoff summary counts the evidence by relevance.
  const evidence = useQuery({ queryKey: ['run', runId, 'evidence'], queryFn: () => api.getRunEvidence(runId), enabled: Boolean(runId) });
  const delta = useQuery({ queryKey: ['run', runId, 'delta'], queryFn: () => api.getRunDelta(runId), enabled: artifact === 'delta' });
  const report = useQuery({ queryKey: ['run', runId, 'report'], queryFn: () => api.getRunReport(runId), enabled: artifact === 'report' });
  const manifest = useQuery({ queryKey: ['run', runId, 'manifest'], queryFn: () => api.getRunManifest(runId), enabled: artifact === 'manifest' });

  const active = { finding, evidence, delta, report, manifest }[artifact];
  // A run without a finding (synthesis off, failed before it, still running) answers 404: that is a state, not an error.
  const noSynthesis = finding.error instanceof ApiError && finding.error.status === 404;
  const activeError = artifact === 'finding' && noSynthesis ? null : active.error;
  const categories = distinct(evidence.data ?? [], (row) => row.category);
  const types = distinct(delta.data ?? [], (row) => row.stix_type);
  const controls = useListControls<EvidenceSortKey>({
    defaults: DEFAULTS,
    defaultSort: { key: 'relevance', dir: 'desc' },
    sortKeys: SORT_KEYS,
    allowed: { relevance: ['', ...RELEVANCES], category: ['', ...categories], type: ['', ...types] },
  });
  const evidenceFiltered = controls.isAnySet(EVIDENCE_KEYS);
  const evidenceRows = evidence.data
    ? sortEvidence(
        filterEvidence(evidence.data, { query: controls.get('q'), relevance: controls.get('relevance'), category: controls.get('category') }),
        controls.sort,
      )
    : [];
  const deltaRows = delta.data ? filterDelta(delta.data, { query: controls.get('dq'), type: controls.get('type') }) : [];
  const deltaFiltered = controls.isAnySet(DELTA_KEYS);
  const artifactName = (kind: ArtifactKind) => t(`artifact.${kind}` as MessageKey);
  const title = run.data ? t('runDetail.title', { runId: run.data.id }) : t('runDetail.fallbackTitle');
  const backTo = targetId ? `/targets/${encodeURIComponent(targetId)}` : run.data ? `/targets/${encodeURIComponent(run.data.target_id)}` : '/runs';

  const handleDownload = async () => {
    setDownloadError(null);
    try {
      await downloadArtifact(runId, artifact);
    } catch {
      setDownloadError(t('runDetail.downloadFailed', { artifact: artifactName(artifact) }));
    }
  };

  // Handoff: verify the target's chain on demand, export, summarise, follow up.
  const verification = useMutation({ mutationFn: (targetId: string) => api.verifyChain(targetId) });
  const [exportError, setExportError] = useState<string | null>(null);
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const [summaryText, setSummaryText] = useState('');
  const followUp = useStartRun();
  const runActive = run.data ? isActiveStatus(run.data.status) : false;

  const handleExport = async (kind: 'bundle' | 'pdf') => {
    setExportError(null);
    try {
      await (kind === 'bundle' ? downloadRunBundle(runId) : downloadRunPdf(runId));
    } catch {
      setExportError(t('runDetail.downloadFailed', { artifact: t(`artifact.${kind}`) }));
    }
  };

  const handleCopySummary = async () => {
    if (!run.data) return;
    const text = buildHandoffSummary(t, tv, locale, {
      run: run.data,
      finding: finding.data,
      evidence: evidence.data,
      verification: verification.data,
      href: window.location.href,
    });
    setSummaryText(text);
    try {
      await navigator.clipboard.writeText(text);
      setCopyState('copied');
    } catch {
      // No clipboard (insecure context, permission denied, old browser): the
      // text is shown instead so it can be copied by hand.
      setCopyState('failed');
    }
  };

  return (
    <PageLayout
      title={title}
      subtitle={
        run.data
          ? t('runDetail.subtitle', {
              targetId: run.data.target_id,
              started: formatDateTime(run.data.started_at, locale),
              duration: formatDuration(run.data.started_at, run.data.finished_at),
            })
          : t('runDetail.loadingContext')
      }
      actions={<Link to={backTo}>{t('back')}</Link>}
    >
      {run.isLoading ? <LoadingState message={t('runDetail.loading')} /> : null}
      {run.error ? <ErrorState description={t('runDetail.down', { runId })} /> : null}

      {run.data ? (
        <div className="stats-grid">
          <div className="state-card">
            <span className="label">{t('runDetail.status')}</span>
            <StatusPill label={run.data.status} tone={runStatusTone(run.data.status)} />
            {run.data.error ? <small className="error-text">{run.data.error}</small> : null}
          </div>
          <div className="state-card">
            <span className="label">{t('runDetail.collectors')}</span>
            <strong>{run.data.collectors_run || '—'}</strong>
          </div>
          <div className="state-card">
            <span className="label">{t('runDetail.newObservables')}</span>
            <strong>{run.data.new_observables}</strong>
          </div>
          <div className="state-card">
            <span className="label">{t('runDetail.sealed')}</span>
            <strong>{run.data.manifest_sha256 ? t('yes') : t('no')}</strong>
            {run.data.manifest_sha256 ? <small className="mono">{run.data.manifest_sha256.slice(0, 16)}…</small> : null}
          </div>
        </div>
      ) : null}

      {run.data ? <StageSummary run={run.data} /> : null}
      <div className="workspace-shell">
        <div className="artifact-toolbar">
          <div className="artifact-tabs" role="tablist" aria-label={t('runDetail.artefacts')}>
            {ARTIFACTS.map((kind) => (
            <button
              key={kind}
              id={`tab-${kind}`}
              type="button"
              role="tab"
              aria-selected={artifact === kind}
              aria-controls={`panel-${kind}`}
              className={artifact === kind ? 'active' : ''}
              onClick={() => setArtifact(kind)}
            >
              {artifactName(kind)}
            </button>
            ))}
          </div>
          {/* Outside the tablist: every child of a tablist must be a tab. */}
          <button type="button" className="ghost-button" onClick={handleDownload} disabled={!run.data}>
            {t('runDetail.download', { artifact: artifactName(artifact) })}
          </button>
        </div>
        {downloadError ? (
          <p className="state-card error" role="alert">
            {downloadError}
          </p>
        ) : null}

        <div id={`panel-${artifact}`} className="artifact-panel" role="tabpanel" aria-labelledby={`tab-${artifact}`}>
          {active.isLoading ? <LoadingState message={t('runDetail.loadingArtifact', { artifact: artifactName(artifact) })} /> : null}
          {activeError ? <ErrorState title={t('runDetail.noArtifact.title', { artifact: artifactName(artifact) })} description={t('runDetail.noArtifact.body')} /> : null}
          {artifact === 'finding' && noSynthesis ? <EmptyState title={t('runDetail.noSynthesis.title')} description={t('runDetail.noSynthesis.body')} /> : null}

          {artifact === 'finding' && finding.data ? (
            <div className="finding">
              <p>
                <span className="label">{t('runDetail.riskLevel')} </span>
                <StatusPill label={finding.data.risk_level} tone={riskTone(finding.data.risk_level)} />
              </p>
              <h3>{t('runDetail.summary')}</h3>
              <p>{finding.data.summary}</p>
              <h3>{t('runDetail.justification')}</h3>
              <p>{finding.data.risk_justification}</p>
              {finding.data.new_since_last_run.length > 0 ? (
                <>
                  <h3>{t('runDetail.newSince')}</h3>
                  <ul>
                    {finding.data.new_since_last_run.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </>
              ) : null}
              {finding.data.suggested_pivots.length > 0 ? (
                <>
                  <h3>{t('runDetail.pivots')}</h3>
                  <ul>
                    {finding.data.suggested_pivots.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </>
              ) : null}
              <p className="muted">
                {finding.data.provider} · {finding.data.model} · {(finding.data.duration_ms / 1000).toFixed(1)} s
              </p>
            </div>
          ) : null}

          {artifact === 'evidence' && evidence.data ? (
            evidence.data.length === 0 ? (
              <p className="muted">{t('runDetail.noEvidence')}</p>
            ) : (
              <>
                {/* Which model qualified the rows: the fast route's provider and model, as persisted. */}
                <p className="muted" data-testid="evidence-qualified-by">
                  {t('evidence.qualifiedBy', { models: distinct(evidence.data, (row) => `${row.provider} · ${row.model}`).join(', ') })}
                </p>
                <div className="filters" role="search" aria-label={t('runDetail.evidenceFilters')}>
                  <SearchField label={t('search')} value={controls.get('q')} onChange={(value) => controls.set('q', value)} placeholder={t('runDetail.evidencePlaceholder')} />
                  <label>
                    <span className="label">{t('col.relevance')}</span>
                    <select value={controls.get('relevance')} onChange={(event) => controls.set('relevance', event.target.value)}>
                      <option value="">{t('runDetail.anyRelevance')}</option>
                      {RELEVANCES.map((level) => (
                        <option key={level} value={level}>
                          {tv(level)}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span className="label">{t('col.category')}</span>
                    <select value={controls.get('category')} onChange={(event) => controls.set('category', event.target.value)}>
                      <option value="">{t('runDetail.anyCategory')}</option>
                      {categories.map((category) => (
                        <option key={category} value={category}>
                          {category}
                        </option>
                      ))}
                    </select>
                  </label>
                  <span className="count" role="status" aria-live="polite">
                    {t('count.of', { visible: evidenceRows.length, total: evidence.data.length })}
                  </span>
                  {evidenceFiltered ? (
                    <button type="button" className="ghost-button" onClick={() => controls.clearKeys(EVIDENCE_KEYS)}>
                      {t('clearFilters')}
                    </button>
                  ) : null}
                </div>
                {evidenceRows.length === 0 ? <p className="muted">{t('runDetail.noEvidenceMatch')}</p> : null}
              <table className="data-table" role="table">
                <thead role="rowgroup">
                  <tr role="row">
                    <SortableHeader label={t('col.category')} column="category" sort={controls.sort} onSort={controls.toggleSort} />
                    <SortableHeader label={t('col.relevance')} column="relevance" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
                    <SortableHeader label={t('col.confidence')} column="confidence" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
                    <SortableHeader label={t('col.source')} column="title" sort={controls.sort} onSort={controls.toggleSort} />
                    <th role="columnheader" scope="col">{t('col.rationale')}</th>
                  </tr>
                </thead>
                <tbody role="rowgroup">
                  {evidenceRows.map((row) => (
                    <tr role="row" key={row.id ?? row.url}>
                      <td role="cell" data-label={t('col.category')}>{row.category}</td>
                      <td role="cell" data-label={t('col.relevance')}>
                        <StatusPill label={row.relevance} tone={riskTone(row.relevance)} />
                      </td>
                      <td role="cell" data-label={t('col.confidence')}>{Number(row.confidence).toFixed(2)}</td>
                      <td role="cell" data-label={t('col.source')}>
                        {isHttpUrl(row.url) ? (
                          <a href={row.url} rel="noopener noreferrer nofollow" target="_blank">
                            {row.title || row.url}
                          </a>
                        ) : (
                          row.title || row.url
                        )}
                      </td>
                      <td role="cell" data-label={t('col.rationale')}>{row.rationale}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="workspace-actions">
                <button type="button" className="ghost-button" onClick={() => setArtifact('report')}>
                  {t('evidence.continueReport')}
                </button>
                <a className="ghost-button" href="#handoff">
                  {t('evidence.prepareHandoff')}
                </a>
              </div>
              </>
            )
          ) : null}

          {artifact === 'delta' && delta.data ? (
            delta.data.length === 0 ? (
              <p className="muted">{t('runDetail.noDelta')}</p>
            ) : (
              <>
                <div className="filters" role="search" aria-label={t('runDetail.deltaFilters')}>
                  <SearchField label={t('search')} value={controls.get('dq')} onChange={(value) => controls.set('dq', value)} placeholder={t('runDetail.deltaPlaceholder')} />
                  <label>
                    <span className="label">{t('col.type')}</span>
                    <select value={controls.get('type')} onChange={(event) => controls.set('type', event.target.value)}>
                      <option value="">{t('runDetail.anyType')}</option>
                      {types.map((type) => (
                        <option key={type} value={type}>
                          {type}
                        </option>
                      ))}
                    </select>
                  </label>
                  <span className="count" role="status" aria-live="polite">
                    {t('count.of', { visible: deltaRows.length, total: delta.data.length })}
                  </span>
                  {deltaFiltered ? (
                    <button type="button" className="ghost-button" onClick={() => controls.clearKeys(DELTA_KEYS)}>
                      {t('clearFilters')}
                    </button>
                  ) : null}
                </div>
                {deltaRows.length === 0 ? <p className="muted">{t('runDetail.noDeltaMatch')}</p> : null}
              <table className="data-table" role="table">
                <thead role="rowgroup">
                  <tr role="row">
                    <th role="columnheader" scope="col">{t('col.type')}</th>
                    <th role="columnheader" scope="col">{t('col.value')}</th>
                  </tr>
                </thead>
                <tbody role="rowgroup">
                  {deltaRows.map((row) => (
                    <tr role="row" key={row.stix_id}>
                      <td role="cell" data-label={t('col.type')}>{row.stix_type}</td>
                      <td role="cell" data-label={t('col.value')} className="mono">{row.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </>
            )
          ) : null}

          {artifact === 'report' && report.data !== undefined ? <pre>{report.data}</pre> : null}
          {artifact === 'manifest' && manifest.data ? <pre>{JSON.stringify(manifest.data, null, 2)}</pre> : null}
        </div>
      </div>

      {run.data ? (
        <section id="handoff" className="handoff" aria-labelledby="handoff-title">
          <div>
            <h2 id="handoff-title" className="section-title">
              {t('handoff.title')}
            </h2>
            <p className="muted">{t('handoff.lede')}</p>
          </div>
          <div className="handoff-grid">
            <div className="handoff-block">
              <h3>{t('handoff.chainTitle')}</h3>
              <div className="handoff-actions">
                <button
                  type="button"
                  className="primary-action"
                  disabled={verification.isPending}
                  onClick={() => verification.mutate(run.data!.target_id)}
                >
                  {verification.isPending ? t('handoff.verifying') : t('handoff.verify')}
                </button>
              </div>
              {verification.error ? (
                <p className="state-card error" role="alert">
                  {t('handoff.chain.failed')}
                </p>
              ) : null}
              {verification.data ? (
                <div className={`state-card ${verification.data.ok ? 'ok' : 'error'}`} role={verification.data.ok ? 'status' : 'alert'}>
                  <p>{describeVerification(t, verification.data)}</p>
                  {verification.data.anchor_run_id !== null ? (
                    <small className="muted">{t('handoff.chain.anchor', { runId: verification.data.anchor_run_id })}</small>
                  ) : null}
                  {!verification.data.ok && verification.data.first_broken_run_id !== null ? (
                    <Link to={`/runs/${verification.data.first_broken_run_id}`}>
                      {t('handoff.chain.openRun', { runId: verification.data.first_broken_run_id })}
                    </Link>
                  ) : null}
                </div>
              ) : null}
            </div>

            <div className="handoff-block">
              <h3>{t('handoff.exportTitle')}</h3>
              <div className="handoff-actions">
                <button type="button" className="ghost-button" onClick={() => handleExport('bundle')}>
                  {t('handoff.bundle')}
                </button>
                <button type="button" className="ghost-button" onClick={() => handleExport('pdf')}>
                  {t('handoff.pdf')}
                </button>
                {/* The summary quotes the finding and the evidence counts: wait for both. */}
                <button type="button" className="ghost-button" onClick={handleCopySummary} disabled={finding.isLoading || evidence.isLoading}>
                  {t('handoff.copy')}
                </button>
              </div>
              {exportError ? (
                <p className="state-card error" role="alert">
                  {exportError}
                </p>
              ) : null}
              {copyState === 'copied' ? (
                <p className="state-card ok" role="status">
                  {t('handoff.copied')}
                </p>
              ) : null}
              {copyState === 'failed' ? (
                <>
                  <p className="state-card warning" role="status">
                    {t('handoff.copyFailed')}
                  </p>
                  <textarea className="handoff-summary" readOnly aria-label={t('handoff.summary.title')} value={summaryText} />
                </>
              ) : null}
            </div>

            <div className="handoff-block">
              <h3>{t('handoff.followUpTitle')}</h3>
              <div className="handoff-actions">
                <button
                  type="button"
                  className="ghost-button"
                  disabled={followUp.isPendingFor(run.data!.target_id) || runActive}
                  onClick={() => followUp.start(run.data!.target_id)}
                >
                  {followUp.isPendingFor(run.data!.target_id)
                    ? t('run.starting')
                    : runActive
                      ? t('run.running')
                      : t('handoff.followUp')}
                </button>
              </div>
              <RunNotice notice={followUp.notice} />
            </div>
          </div>

          <div className="handoff-block">
            <h3>{t('handoff.alertsTitle')}</h3>
            {alertCase.data ? (
              <p>
                <Link to={`/alerts?target=${encodeURIComponent(run.data.target_id)}&state=all`}>{t('handoff.alertCase', { id: alertCase.data.id })}</Link>{' '}
                <StatusPill label={alertCase.data.state} tone={alertCaseTone(alertCase.data.state)} />
              </p>
            ) : alertCase.isSuccess ? (
              <p className="muted">{t('handoff.noAlertCase')}</p>
            ) : null}
            {run.data.alerts.length === 0 ? (
              <p className="muted">{t('handoff.noAlerts')}</p>
            ) : (
              <table className="data-table" role="table">
                <thead role="rowgroup">
                  <tr role="row">
                    <th role="columnheader" scope="col">{t('col.channel')}</th>
                    <th role="columnheader" scope="col">{t('col.status')}</th>
                    <th role="columnheader" scope="col">{t('col.sentAt')}</th>
                    <th role="columnheader" scope="col">{t('col.error')}</th>
                  </tr>
                </thead>
                <tbody role="rowgroup">
                  {run.data.alerts.map((alert, index) => (
                    <tr role="row" key={alert.id ?? index}>
                      <td role="cell" data-label={t('col.channel')}>{alert.channel ? tv(alert.channel) : '—'}</td>
                      <td role="cell" data-label={t('col.status')}>{alert.status ? <StatusPill label={alert.status} tone={alertStatusTone(alert.status)} /> : '—'}</td>
                      <td role="cell" data-label={t('col.sentAt')}>{formatDateTime(alert.sent_at, locale)}</td>
                      <td role="cell" data-label={t('col.error')}>{alert.error ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>
      ) : null}
    </PageLayout>
  );
}
