import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';

export function TargetsPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['targets'],
    queryFn: api.getTargets,
  });

  return (
    <section className="page">
      <h1>Targets</h1>
      {isLoading ? <p>Loading targets...</p> : null}
      {error ? <p role="alert">Unable to load targets.</p> : null}
      {!isLoading && !error && data ? (
        <ul className="list-card">
          {data.map((target) => (
            <li key={target.id}>
              <div>
                <strong>{target.fqdn}</strong>
                <small>{target.id}</small>
              </div>
              <span>{target.enabled ? 'Enabled' : 'Disabled'}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
