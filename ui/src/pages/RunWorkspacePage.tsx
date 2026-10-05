import { useQuery } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { StatusPill } from '../components/StatusPill';
import { api, downloadArtifact } from '../lib/api';
import { formatDateTime, formatDuration, riskTone, runStatusTone } from '../lib/format';
import type { ArtifactKind } from '../types';

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
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">Category</th>
                    <th scope="col">Relevance</th>
                    <th scope="col">Confidence</th>
                    <th scope="col">Source</th>
                    <th scope="col">Rationale</th>
                  </tr>
                </thead>
                <tbody>
                  {evidence.data.map((row) => (
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
            )
          ) : null}

          {artifact === 'delta' && delta.data ? (
            delta.data.length === 0 ? (
              <p className="muted">No net-new observables in this run.</p>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">Type</th>
                    <th scope="col">Value</th>
                  </tr>
                </thead>
                <tbody>
                  {delta.data.map((row) => (
                    <tr key={row.stix_id}>
                      <td>{row.stix_type}</td>
                      <td className="mono">{row.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          ) : null}

          {artifact === 'report' && report.data !== undefined ? <pre>{report.data}</pre> : null}
          {artifact === 'manifest' && manifest.data ? <pre>{JSON.stringify(manifest.data, null, 2)}</pre> : null}
        </div>
      </div>
    </PageLayout>
  );
}
