import { useQuery } from '@tanstack/react-query';
import { ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { api } from '../lib/api';

export function HomePage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['health'],
    queryFn: api.getHealth,
  });

  if (isLoading) {
    return <PageLayout title="OSINT Orchestrator" eyebrow="Overview" subtitle="Checking the current operating state."><LoadingState message="Loading service health..." /></PageLayout>;
  }

  if (error) {
    return (
      <PageLayout title="OSINT Orchestrator" eyebrow="Overview" subtitle="The service health check could not be confirmed.">
        <ErrorState description="Backend health was not reachable from the browser. Verify the local API is running." />
      </PageLayout>
    );
  }

  return (
    <PageLayout
      title="OSINT Orchestrator"
      eyebrow="Overview"
      subtitle="Monitor active targets, inspect the latest runs and keep the evidence chain visible to the team."
    >
      <div className="hero-card">
        <p className="eyebrow">Operations overview</p>
        <h2>Situation snapshot</h2>
        <p className="lede">
          Monitor active targets, inspect the latest runs and keep the evidence chain visible to the team.
        </p>
      </div>

      <div className="stats-grid">
        <div className="state-card">
          <span className="label">API status</span>
          <strong>{data?.status ?? 'Unavailable'}</strong>
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
    </PageLayout>
  );
}
