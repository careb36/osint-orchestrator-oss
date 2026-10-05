import { useQuery } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import { api } from '../lib/api';

export function WorkspacePage() {
  const { runId = 'latest' } = useParams();
  const { data: health, isLoading: isLoadingHealth } = useQuery({
    queryKey: ['health'],
    queryFn: api.getHealth,
  });
  const { data: runs, isLoading: isLoadingRuns } = useQuery({
    queryKey: ['runs'],
    queryFn: api.getRuns,
  });

  const selectedRun = runs?.find((run) => run.id === runId) ?? runs?.[0];

  return (
    <section className="page">
      <div className="hero-card">
        <p className="eyebrow">Workspace</p>
        <h1>Run {selectedRun?.id ?? runId}</h1>
        <p className="lede">
          Health, run details and operator actions are grouped here for the current investigation.
        </p>
      </div>

      <div className="stats-grid">
        <div className="state-card">
          <span className="label">Target health</span>
          <strong>{isLoadingHealth ? 'Checking...' : health?.status ?? 'Unavailable'}</strong>
        </div>
        <div className="state-card">
          <span className="label">Run status</span>
          <strong>{selectedRun?.status ?? 'pending'}</strong>
        </div>
        <div className="state-card">
          <span className="label">Target</span>
          <strong>{selectedRun?.targetId ?? 'unknown'}</strong>
        </div>
      </div>

      <div className="list-card">
        <h2>Run workspace</h2>
        {isLoadingRuns ? <p>Loading run workspace...</p> : null}
        {selectedRun ? (
          <ul>
            <li>Run ID: {selectedRun.id}</li>
            <li>Target: {selectedRun.targetId}</li>
            <li>Status: {selectedRun.status}</li>
            <li>Created: {selectedRun.createdAt}</li>
          </ul>
        ) : (
          <p>No run selected. Return to <Link to="/runs">Runs</Link> to choose a workflow.</p>
        )}
      </div>
    </section>
  );
}
