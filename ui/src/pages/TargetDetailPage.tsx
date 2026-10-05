import { Link, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';

export function TargetDetailPage() {
  const { targetId } = useParams();
  const { data: runs, isLoading, error } = useQuery({
    queryKey: ['runs'],
    queryFn: api.getRuns,
    enabled: Boolean(targetId),
  });

  const targetRuns = runs?.filter((run) => run.targetId === targetId) ?? [];

  return (
    <section className="page">
      <div className="hero-card">
        <p className="eyebrow">Target workspace</p>
        <h1>{targetId ?? 'Target'}</h1>
        <p className="lede">Review the active investigation context, then open the run workspace to inspect evidence and exports.</p>
        <Link to="/targets">Back to targets</Link>
      </div>

      {isLoading ? <p>Loading target runs...</p> : null}
      {error ? <p role="alert">Unable to load target runs.</p> : null}
      {!isLoading && !error && targetRuns.length === 0 ? (
        <div className="state-card warning">
          <h2>No runs yet</h2>
          <p>This target has not produced a run in the current view.</p>
        </div>
      ) : null}

      {!isLoading && !error && targetRuns.length > 0 ? (
        <ul className="list-card">
          {targetRuns.map((run) => (
            <li key={run.id}>
              <div>
                <strong>{run.status}</strong>
                <small>{run.id}</small>
              </div>
              <div>
                <Link to={`/targets/${targetId}/runs/${run.id}`}>Open run</Link>
              </div>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
