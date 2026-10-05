import { useQuery } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { SearchField } from '../components/SearchField';
import { SortableHeader } from '../components/SortableHeader';
import { StatusPill } from '../components/StatusPill';
import { useListControls } from '../hooks/useListControls';
import { useLocale, type MessageKey } from '../i18n';
import { api, downloadArtifact } from '../lib/api';
import { formatDateTime, formatDuration, riskTone, runStatusTone } from '../lib/format';
import { distinct, filterDelta, filterEvidence, sortEvidence, type EvidenceSortKey } from '../lib/listing';
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
  const finding = useQuery({ queryKey: ['run', runId, 'finding'], queryFn: () => api.getRunFinding(runId), enabled: artifact === 'finding' });
  const evidence = useQuery({ queryKey: ['run', runId, 'evidence'], queryFn: () => api.getRunEvidence(runId), enabled: artifact === 'evidence' });
  const delta = useQuery({ queryKey: ['run', runId, 'delta'], queryFn: () => api.getRunDelta(runId), enabled: artifact === 'delta' });
  const report = useQuery({ queryKey: ['run', runId, 'report'], queryFn: () => api.getRunReport(runId), enabled: artifact === 'report' });
  const manifest = useQuery({ queryKey: ['run', runId, 'manifest'], queryFn: () => api.getRunManifest(runId), enabled: artifact === 'manifest' });

  const active = { finding, evidence, delta, report, manifest }[artifact];
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
          {active.error ? <ErrorState title={t('runDetail.noArtifact.title', { artifact: artifactName(artifact) })} description={t('runDetail.noArtifact.body')} /> : null}

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
              <table className="data-table">
                <thead>
                  <tr>
                    <SortableHeader label={t('col.category')} column="category" sort={controls.sort} onSort={controls.toggleSort} />
                    <SortableHeader label={t('col.relevance')} column="relevance" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
                    <SortableHeader label={t('col.confidence')} column="confidence" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
                    <SortableHeader label={t('col.source')} column="title" sort={controls.sort} onSort={controls.toggleSort} />
                    <th scope="col">{t('col.rationale')}</th>
                  </tr>
                </thead>
                <tbody>
                  {evidenceRows.map((row) => (
                    <tr key={row.id ?? row.url}>
                      <td>{row.category}</td>
                      <td>
                        <StatusPill label={row.relevance} tone={riskTone(row.relevance)} />
                      </td>
                      <td>{Number(row.confidence).toFixed(2)}</td>
                      <td>
                        {isHttpUrl(row.url) ? (
                          <a href={row.url} rel="noopener noreferrer nofollow" target="_blank">
                            {row.title || row.url}
                          </a>
                        ) : (
                          row.title || row.url
                        )}
                      </td>
                      <td>{row.rationale}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
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
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">{t('col.type')}</th>
                    <th scope="col">{t('col.value')}</th>
                  </tr>
                </thead>
                <tbody>
                  {deltaRows.map((row) => (
                    <tr key={row.stix_id}>
                      <td>{row.stix_type}</td>
                      <td className="mono">{row.value}</td>
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
    </PageLayout>
  );
}
