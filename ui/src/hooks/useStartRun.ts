import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api, ApiError } from '../lib/api';

/** What happened on Start run; RunNotice renders it in the operator's language. */
export type RunNotice =
  | { tone: 'ok'; runId: number; targetId: string }
  | { tone: 'error'; status: number | null; detail: string | null };

/**
 * POST /targets/{id}/run with the operator-facing outcome as a notice. The
 * backend owns the rules (400 disabled target, 409 run already in progress,
 * 404 unknown target); the notice translates the status itself. The server's
 * `detail` is rendered in the target's own `language` for 400 and 409 and in
 * ORCHESTRATOR_LANGUAGE otherwise, neither of which need match the operator's
 * choice, so it is shown as an attributed secondary line, not as the message.
 */
export function useStartRun() {
  const queryClient = useQueryClient();
  const [notice, setNotice] = useState<RunNotice | null>(null);

  const mutation = useMutation({
    mutationFn: (targetId: string) => api.triggerRun(targetId),
    onSuccess: (accepted) => {
      setNotice({ tone: 'ok', runId: accepted.run_id, targetId: accepted.target_id });
      void queryClient.invalidateQueries({ queryKey: ['runs'] });
      void queryClient.invalidateQueries({ queryKey: ['risk-trends'] });
    },
    onError: (error) => {
      const apiError = error instanceof ApiError ? error : null;
      setNotice({ tone: 'error', status: apiError?.status ?? null, detail: apiError?.message ?? null });
    },
  });

  return { start: mutation.mutate, isPending: mutation.isPending, notice };
}
