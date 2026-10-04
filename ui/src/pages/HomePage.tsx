import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';

export function HomePage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['health'],
    queryFn: api.getHealth,
  });

  return (
    <section className="page">
      <div className="hero-card">
        <p className="eyebrow">Operations overview</p>
        <h1>OSINT Orchestrator</h1>
        <p className="lede">
          Monitor active targets, inspect the latest runs and keep the evidence chain visible to the team.
        </p>
      </div>

      <div className="stats-grid">
        <div className="state-card">
          <span className="label">API status</span>
          <strong>{isLoading ? 'Checking...' : data?.status ?? 'Unavailable'}</strong>
        </div>
        <div className="state-card">
          <span className="label">Current version</span>
          <strong>{data?.version ?? 'n/a'}</strong>
        </div>
        <div className="state-card">
          <span className="label">Operational mode</span>
          <strong>Discovery first</strong>
        </div>
      </div>

      {error ? (
        <div className="state-card warning" role="alert">
          <h2>API unavailable</h2>
          <p>Backend health was not reachable from the browser. Verify the local API is running.</p>
        </div>
      ) : null}
    </section>
  );
}
