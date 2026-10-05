import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import type { ArtifactKind, RunDetail } from '../types';

const STORAGE_PREFIX = 'osint-run-workspace';

function readStoredArtifact(runId?: string): ArtifactKind {
  if (!runId) {
    return 'report';
  }

  try {
    const raw = window.sessionStorage.getItem(`${STORAGE_PREFIX}:${runId}`);
    const parsed = raw ? JSON.parse(raw) : null;
    if (parsed && ['report', 'finding', 'evidence', 'manifest'].includes(parsed.artifact)) {
      return parsed.artifact;
    }
  } catch {
    // Ignore storage issues and fall back to the default artifact.
  }

  return 'report';
}

function artifactUrl(runId: string, artifact: ArtifactKind) {
  const base = import.meta.env.VITE_API_BASE_URL ?? '/api';
  return `${base}/runs/${runId}/${artifact}`;
}

export function RunWorkspacePage() {
  const { runId, targetId } = useParams();
  const [selectedArtifact, setSelectedArtifact] = useState<ArtifactKind>(() => readStoredArtifact(runId));

  useEffect(() => {
    if (!runId) {
      return;
    }

    window.sessionStorage.setItem(`${STORAGE_PREFIX}:${runId}`, JSON.stringify({ artifact: selectedArtifact }));
  }, [runId, selectedArtifact]);

  const runQuery = useQuery({
    queryKey: ['run', runId],
    queryFn: () => api.getRun(runId ?? ''),
    enabled: Boolean(runId),
  });

  const run = runQuery.data as RunDetail | undefined;

  const reportQuery = useQuery({
    queryKey: ['run', runId, 'report'],
    queryFn: () => api.getRunReport(runId ?? ''),
    enabled: Boolean(runId),
    retry: false,
  });

  const findingQuery = useQuery({
    queryKey: ['run', runId, 'finding'],
    queryFn: () => api.getRunFinding(runId ?? ''),
    enabled: Boolean(runId),
    retry: false,
  });

  const evidenceQuery = useQuery({
    queryKey: ['run', runId, 'evidence'],
    queryFn: () => api.getRunEvidence(runId ?? ''),
    enabled: Boolean(runId),
    retry: false,
  });

  const manifestQuery = useQuery({
    queryKey: ['run', runId, 'manifest'],
    queryFn: () => api.getRunManifest(runId ?? ''),
    enabled: Boolean(runId),
    retry: false,
  });

  const artifactQueries = useMemo(
    () => ({
      report: reportQuery,
      finding: findingQuery,
      evidence: evidenceQuery,
      manifest: manifestQuery,
    }),
    [evidenceQuery, findingQuery, manifestQuery, reportQuery],
  );

  const fetchedArtifactQueries = Object.values(artifactQueries).filter((query) => query.isFetched);
  const degradedState =
    fetchedArtifactQueries.some((query) => query.error) && fetchedArtifactQueries.some((query) => query.data !== undefined);

  const activeArtifactQuery = artifactQueries[selectedArtifact];
  const panelTitle = selectedArtifact.charAt(0).toUpperCase() + selectedArtifact.slice(1);
  const activeTabId = `tab-${selectedArtifact}`;

  return (
    <section className="page">
      <div className="hero-card">
        <p className="eyebrow">Run workspace</p>
        <h1>{run ? `Run ${run.id}` : 'Run detail'}</h1>
        <p className="lede">
          {run ? `${run.status} • target ${run.targetId} • ${new Date(run.createdAt).toLocaleString()}` : 'Loading run context...'}
        </p>
        <div className="workspace-actions">
          <Link to={targetId ?? (run?.targetId ? `/targets/${run.targetId}` : '/runs')}>Back to context</Link>
          {runId ? (
            <a href={artifactUrl(runId, selectedArtifact)} download>
              Download {panelTitle}
            </a>
          ) : null}
        </div>
      </div>

      {degradedState ? (
        <div className="state-card warning" role="status">
          Workspace is degraded: some artifacts are temporarily unavailable while others remain accessible.
        </div>
      ) : null}

      <div className="workspace-shell">
        <div className="artifact-tabs" role="tablist" aria-label="Run artifacts">
          {(['report', 'finding', 'evidence', 'manifest'] as ArtifactKind[]).map((artifact) => (
            <button
              key={artifact}
              id={`tab-${artifact}`}
              type="button"
              role="tab"
              aria-selected={selectedArtifact === artifact}
              aria-controls={`panel-${artifact}`}
              className={selectedArtifact === artifact ? 'active' : ''}
              onClick={() => setSelectedArtifact(artifact)}
            >
              {artifact}
            </button>
          ))}
        </div>

        <div id={`panel-${selectedArtifact}`} className="artifact-panel" role="tabpanel" aria-labelledby={activeTabId}>
          {runQuery.isLoading ? <p>Loading run context...</p> : null}
          {runQuery.error ? <p role="alert">Unable to load run context.</p> : null}

          {!runQuery.isLoading && !runQuery.error && activeArtifactQuery?.isLoading ? (
            <p>Loading {panelTitle.toLowerCase()}...</p>
          ) : null}

          {!runQuery.isLoading && !runQuery.error && activeArtifactQuery?.error ? (
            <div className="state-card error" role="alert">
              <h2>{panelTitle} unavailable</h2>
              <p>The selected artifact could not be loaded from the backend.</p>
            </div>
          ) : null}

          {!runQuery.isLoading && !runQuery.error && activeArtifactQuery && !activeArtifactQuery.isLoading && !activeArtifactQuery.error ? (
            <>
              {selectedArtifact === 'report' ? <pre>{String(activeArtifactQuery.data ?? 'No report available.')}</pre> : null}
              {selectedArtifact === 'finding' ? <pre>{String(activeArtifactQuery.data ?? 'No finding available.')}</pre> : null}
              {selectedArtifact === 'evidence' ? (
                <ul className="list-card">
                  {Array.isArray(activeArtifactQuery.data) && activeArtifactQuery.data.length > 0 ? (
                    activeArtifactQuery.data.map((entry, index) => {
                      const source = String((entry as { source?: string })?.source ?? '');
                      const key = source || `evidence-${index}`;

                      return (
                        <li key={key}>
                          <div>
                            <strong>{source || `Evidence ${index + 1}`}</strong>
                            <small>{String((entry as { category?: string })?.category ?? 'general')}</small>
                          </div>
                          <span>{String((entry as { confidence?: unknown })?.confidence ?? 'n/a')}</span>
                        </li>
                      );
                    })
                  ) : (
                    <li>
                      <strong>No evidence rows</strong>
                    </li>
                  )}
                </ul>
              ) : null}
              {selectedArtifact === 'manifest' ? (
                <pre>{JSON.stringify(activeArtifactQuery.data ?? { status: 'no manifest available' }, null, 2)}</pre>
              ) : null}
            </>
          ) : null}
        </div>
      </div>
    </section>
  );
}
