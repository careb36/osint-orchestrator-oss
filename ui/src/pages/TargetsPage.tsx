import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { EmptyState, ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { StatusPill } from '../components/StatusPill';
import { api, ApiError } from '../lib/api';
import { formatDateTime, runStatusTone } from '../lib/format';
import type { RunSummary, TargetSummary } from '../types';

function enabledCollectors(target: TargetSummary): string[] {
  return Object.entries(target.collectors ?? {})
    .filter(([, cfg]) => cfg && cfg.enabled)
    .map(([name]) => name);
}

export function TargetsPage() {
  const queryClient = useQueryClient();
  const targets = useQuery({ queryKey: ['targets'], queryFn: () => api.getTargets() });
  const runs = useQuery({ queryKey: ['runs'], queryFn: () => api.getRuns() });
  const [notice, setNotice] = useState<{ tone: 'ok' | 'error'; text: string } | null>(null);

  const trigger = useMutation({
    mutationFn: (targetId: string) => api.triggerRun(targetId),
    onSuccess: (accepted) => {
      setNotice({ tone: 'ok', text: `Run #${accepted.run_id} accepted for ${accepted.target_id}.` });
      void queryClient.invalidateQueries({ queryKey: ['runs'] });
    },
    onError: (error) => {
      const message = error instanceof ApiError ? error.message : 'The run could not be started.';
      setNotice({ tone: 'error', text: message });
    },
  });

  if (targets.isLoading) {
    return (
      <PageLayout title="Targets" subtitle="Review the active target set and coverage status.">
        <LoadingState message="Loading targets…" />
      </PageLayout>
    );
  }

  if (targets.error) {
    return (
      <PageLayout title="Targets" subtitle="The target inventory is currently unavailable.">
        <ErrorState description="Unable to load targets." />
      </PageLayout>
    );
  }

  if (!targets.data || targets.data.length === 0) {
    return (
      <PageLayout title="Targets" subtitle="The target inventory for this operator workspace.">
        <EmptyState title="No targets configured" description="Add a target to targets.yaml and reload the scheduler to start tracking it." />
      </PageLayout>
    );
  }

  const lastRunByTarget = new Map<string, RunSummary>();
  for (const run of runs.data ?? []) {
    if (!lastRunByTarget.has(run.target_id)) {
      lastRunByTarget.set(run.target_id, run);
    }
  }

  return (
    <PageLayout title="Targets" subtitle="The target inventory for this operator workspace.">
      {notice ? (
        <p className={`state-card ${notice.tone === 'ok' ? 'ok' : 'error'}`} role="status">
          {notice.text}
        </p>
      ) : null}
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col">Target</th>
            <th scope="col">Enabled</th>
            <th scope="col">Collectors</th>
            <th scope="col">Last run</th>
            <th scope="col">Status</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {targets.data.map((target) => {
            const last = lastRunByTarget.get(target.id);
            const active = last ? last.status === 'pending' || last.status === 'running' : false;
            return (
              <tr key={target.id}>
                <td>
                  <Link to={`/targets/${encodeURIComponent(target.id)}`}>
                    <strong>{target.fqdn}</strong>
                  </Link>
                  <br />
                  <small>{target.id}</small>
                </td>
                <td>{target.enabled ? 'Yes' : 'No'}</td>
                <td>{enabledCollectors(target).join(', ') || '—'}</td>
                <td>{last ? <Link to={`/runs/${last.id}`}>#{last.id} · {formatDateTime(last.started_at)}</Link> : '—'}</td>
                <td>{last ? <StatusPill label={last.status} tone={runStatusTone(last.status)} /> : <span className="muted">no runs</span>}</td>
                <td>
                  <button
                    type="button"
                    className="ghost-button"
                    disabled={trigger.isPending || active}
                    onClick={() => trigger.mutate(target.id)}
                    aria-label={`Start run for ${target.id}`}
                  >
                    {active ? 'Running…' : 'Start run'}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </PageLayout>
  );
}
