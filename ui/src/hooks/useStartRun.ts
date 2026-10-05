import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api, ApiError } from '../lib/api';

/** What happened on Start run; RunNotice renders it in the operator's language. */
export type RunNotice =
  | { tone: 'ok'; runId: number; targetId: string }
  | { tone: 'error'; detail: string | null };

/**
 * POST /targets/{id}/run with the operator-facing outcome as a notice. The
 * backend owns the rules (disabled target, run already in progress); its
 * `detail`, already in the operator language, is what the notice shows on error.
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
      setNotice({ tone: 'error', detail: error instanceof ApiError ? error.message : null });
    },
  });

  return { start: mutation.mutate, isPending: mutation.isPending, notice };
}
