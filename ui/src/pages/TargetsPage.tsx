import { useQuery } from '@tanstack/react-query';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';

export function TargetsPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['targets'],
    queryFn: api.getTargets,
  });

  if (isLoading) {
    return (
      <PageLayout title="Targets" subtitle="Review the active target set and coverage status.">
        <LoadingState message="Loading targets..." />
      </PageLayout>
    );
  }

  if (error) {
    return (
      <PageLayout title="Targets" subtitle="The target inventory is currently unavailable.">
        <ErrorState description="Unable to load targets." />
      </PageLayout>
    );
  }

  if (!data || data.length === 0) {
    return (
      <PageLayout title="Targets" subtitle="The target inventory for this operator workspace.">
        <EmptyState title="No targets configured" description="Add a target to start tracking collection and monitoring workloads." />
      </PageLayout>
    );
  }

  return (
    <PageLayout title="Targets" subtitle="The target inventory for this operator workspace.">
      <ul className="list-card">
        {data.map((target) => (
          <li key={target.id}>
            <div>
              <strong>{target.fqdn}</strong>
              <small>{target.id}</small>
            </div>
            <div>
              <span>{target.enabled ? 'Enabled' : 'Disabled'}</span>
              <Link to={`/targets/${target.id}`}>Open workspace</Link>
            </div>
          </li>
        ))}
      </ul>
    </PageLayout>
  );
}
