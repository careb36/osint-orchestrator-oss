import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';

export function RunsPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['runs'],
    queryFn: api.getRuns,
  });

  return (
    <section className="page">
      <h1>Runs</h1>
      {isLoading ? <p>Loading recent runs...</p> : null}
      {error ? <p role="alert">Unable to load run history.</p> : null}
      {!isLoading && !error && data ? (
        <ul className="list-card">
          {data.map((run) => (
            <li key={run.id}>
              <div>
                <strong>{run.targetId}</strong>
                <small>{run.id}</small>
              </div>
              <span>{run.status}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
