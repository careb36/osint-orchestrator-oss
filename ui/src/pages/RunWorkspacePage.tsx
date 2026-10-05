import { useQuery } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { SearchField } from '../components/SearchField';
import { SortableHeader } from '../components/SortableHeader';
import { StatusPill } from '../components/StatusPill';
import { useListControls } from '../hooks/useListControls';
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
  const title = run.data ? `Run #${run.data.id}` : 'Run detail';
  const backTo = targetId ? `/targets/${encodeURIComponent(targetId)}` : run.data ? `/targets/${encodeURIComponent(run.data.target_id)}` : '/runs';

  const handleDownload = async () => {
    setDownloadError(null);
    try {
      await downloadArtifact(runId, artifact);
    } catch {
      setDownloadError(`The ${artifact} could not be downloaded.`);
    }
  };

  return (
    <PageLayout
      title={title}
      subtitle={
        run.data
          ? `${run.data.target_id} · started ${formatDateTime(run.data.started_at)} · ${formatDuration(run.data.started_at, run.data.finished_at)}`
          : 'Loading run context…'
      }
      actions={<Link to={backTo}>Back</Link>}
    >
      {run.isLoading ? <LoadingState message="Loading run…" /> : null}
      {run.error ? <ErrorState description={`Run #${runId} could not be loaded.`} /> : null}

      {run.data ? (
        <div className="stats-grid">
          <div className="state-card">
            <span className="label">Status</span>
            <StatusPill label={run.data.status} tone={runStatusTone(run.data.status)} />
            {run.data.error ? <small className="error-text">{run.data.error}</small> : null}
          </div>
          <div className="state-card">
            <span className="label">Collectors</span>
            <strong>{run.data.collectors_run || '—'}</strong>
          </div>
          <div className="state-card">
            <span className="label">New observables</span>
            <strong>{run.data.new_observables}</strong>
          </div>
          <div className="state-card">
            <span className="label">Sealed</span>
            <strong>{run.data.manifest_sha256 ? 'Yes' : 'No'}</strong>
            {run.data.manifest_sha256 ? <small className="mono">{run.data.manifest_sha256.slice(0, 16)}…</small> : null}
          </div>
        </div>
      ) : null}

      <div className="workspace-shell">
        <div className="artifact-toolbar">
          <div className="artifact-tabs" role="tablist" aria-label="Run artefacts">
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
              {kind}
            </button>
            ))}
          </div>
          {/* Outside the tablist: every child of a tablist must be a tab. */}
          <button type="button" className="ghost-button" onClick={handleDownload} disabled={!run.data}>
            Download {artifact}
          </button>
        </div>
        {downloadError ? (
          <p className="state-card error" role="alert">
            {downloadError}
          </p>
        ) : null}

        <div id={`panel-${artifact}`} className="artifact-panel" role="tabpanel" aria-labelledby={`tab-${artifact}`}>
          {active.isLoading ? <LoadingState message={`Loading ${artifact}…`} /> : null}
          {active.error ? <ErrorState title={`No ${artifact} for this run`} description="The artefact is not available (the run may have failed before producing it)." /> : null}

          {artifact === 'finding' && finding.data ? (
            <div className="finding">
              <p>
                <span className="label">Risk level </span>
                <StatusPill label={finding.data.risk_level} tone={riskTone(finding.data.risk_level)} />
              </p>
              <h3>Summary</h3>
              <p>{finding.data.summary}</p>
              <h3>Justification</h3>
              <p>{finding.data.risk_justification}</p>
              {finding.data.new_since_last_run.length > 0 ? (
                <>
                  <h3>New since the previous run</h3>
                  <ul>
                    {finding.data.new_since_last_run.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </>
              ) : null}
              {finding.data.suggested_pivots.length > 0 ? (
                <>
                  <h3>Suggested pivots</h3>
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
              <p className="muted">No qualified evidence for this run.</p>
            ) : (
              <>
                <div className="filters" role="search" aria-label="Filter evidence">
                  <SearchField label="Search" value={controls.get('q')} onChange={(value) => controls.set('q', value)} placeholder="title, URL, rationale" />
                  <label>
                    <span className="label">Relevance</span>
                    <select value={controls.get('relevance')} onChange={(event) => controls.set('relevance', event.target.value)}>
                      <option value="">Any relevance</option>
                      {RELEVANCES.map((level) => (
                        <option key={level} value={level}>
                          {level}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span className="label">Category</span>
                    <select value={controls.get('category')} onChange={(event) => controls.set('category', event.target.value)}>
                      <option value="">Any category</option>
                      {categories.map((category) => (
                        <option key={category} value={category}>
                          {category}
                        </option>
                      ))}
                    </select>
                  </label>
                  <span className="count" role="status" aria-live="polite">
                    {evidenceRows.length} of {evidence.data.length}
                  </span>
                  {evidenceFiltered ? (
                    <button type="button" className="ghost-button" onClick={() => controls.clearKeys(EVIDENCE_KEYS)}>
                      Clear filters
                    </button>
                  ) : null}
                </div>
                {evidenceRows.length === 0 ? <p className="muted">No evidence matches the current filters.</p> : null}
              <table className="data-table">
                <thead>
                  <tr>
                    <SortableHeader label="Category" column="category" sort={controls.sort} onSort={controls.toggleSort} />
                    <SortableHeader label="Relevance" column="relevance" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
                    <SortableHeader label="Confidence" column="confidence" sort={controls.sort} onSort={controls.toggleSort} naturalDir="desc" />
                    <SortableHeader label="Source" column="title" sort={controls.sort} onSort={controls.toggleSort} />
                    <th scope="col">Rationale</th>
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
              <p className="muted">No net-new observables in this run.</p>
            ) : (
              <>
                <div className="filters" role="search" aria-label="Filter observables">
                  <SearchField label="Search" value={controls.get('dq')} onChange={(value) => controls.set('dq', value)} placeholder="value" />
                  <label>
                    <span className="label">Type</span>
                    <select value={controls.get('type')} onChange={(event) => controls.set('type', event.target.value)}>
                      <option value="">Any type</option>
                      {types.map((type) => (
                        <option key={type} value={type}>
                          {type}
                        </option>
                      ))}
                    </select>
                  </label>
                  <span className="count" role="status" aria-live="polite">
                    {deltaRows.length} of {delta.data.length}
                  </span>
                  {deltaFiltered ? (
                    <button type="button" className="ghost-button" onClick={() => controls.clearKeys(DELTA_KEYS)}>
                      Clear filters
                    </button>
                  ) : null}
                </div>
                {deltaRows.length === 0 ? <p className="muted">No observables match the current filters.</p> : null}
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">Type</th>
                    <th scope="col">Value</th>
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
