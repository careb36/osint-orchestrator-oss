import { useQuery } from '@tanstack/react-query';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';

export function RunsPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['runs'],
    queryFn: api.getRuns,
  });

  if (isLoading) {
    return (
      <PageLayout title="Runs" subtitle="Review recent execution history and current system activity.">
        <LoadingState message="Loading recent runs..." />
      </PageLayout>
    );
  }

  if (error) {
    return (
      <PageLayout title="Runs" subtitle="Recent execution history is unavailable.">
        <ErrorState description="Unable to load run history." />
      </PageLayout>
    );
  }

  if (!data || data.length === 0) {
    return (
      <PageLayout title="Runs" subtitle="Recent execution history and current activities.">
        <EmptyState title="No runs yet" description="There are no recent runs to display for the current operator workspace." />
      </PageLayout>
    );
  }

  return (
    <PageLayout title="Runs" subtitle="Recent execution history and current activities.">
      <ul className="list-card">
        {data.map((run) => (
          <li key={run.id}>
            <div>
              <strong>{run.targetId}</strong>
              <small>{run.id}</small>
            </div>
            <div>
              <span>{run.status}</span>
              <Link to={`/runs/${run.id}`}>Open workspace</Link>
            </div>
          </li>
        ))}
      </ul>
    </PageLayout>
  );
}
