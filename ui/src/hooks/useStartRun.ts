import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api, ApiError } from '../lib/api';

export type RunNotice = { tone: 'ok' | 'error'; text: string };

/**
 * POST /targets/{id}/run with the operator-facing outcome as a notice. The
 * backend owns the rules (disabled target, run already in progress); its
 * `detail` is what the notice shows on error.
 */
export function useStartRun() {
  const queryClient = useQueryClient();
  const [notice, setNotice] = useState<RunNotice | null>(null);

  const mutation = useMutation({
    mutationFn: (targetId: string) => api.triggerRun(targetId),
    onSuccess: (accepted) => {
      setNotice({ tone: 'ok', text: `Run #${accepted.run_id} accepted for ${accepted.target_id}.` });
      void queryClient.invalidateQueries({ queryKey: ['runs'] });
      void queryClient.invalidateQueries({ queryKey: ['risk-trends'] });
    },
    onError: (error) => {
      const message = error instanceof ApiError ? error.message : 'The run could not be started.';
      setNotice({ tone: 'error', text: message });
    },
  });

  return { start: mutation.mutate, isPending: mutation.isPending, notice };
}
