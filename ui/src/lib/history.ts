import { parseApiDate } from './format';
import { isActiveStatus, RISK_RANK } from './overview';
import type { RunStatus, RunSummary } from '../types';

export type RunTransition = {
  /** The run of the same target that came before this one, null for the first. */
  previous: RunSummary | null;
  /** Set when the final status differs from the previous run's. */
  statusChange: { from: RunStatus; to: RunStatus } | null;
  /** Set when the synthesised risk differs from the last known level of the target. */
  riskChange: { from: string; to: string; direction: 'up' | 'down' } | null;
};

function chronological(a: RunSummary, b: RunSummary): number {
  return parseApiDate(a.started_at).getTime() - parseApiDate(b.started_at).getTime() || a.id - b.id;
}

/**
 * What changed from one run of a target to the next, keyed by run id.
 *
 * Runs are compared in start order within their target. A run still active
 * has no result yet, so it carries no change; a run without a finding (failed
 * early, synthesis off) does not reset the risk: the comparison uses the last
 * level the target was known to have.
 */
export function runTransitions(runs: RunSummary[]): Map<number, RunTransition> {
  const byTarget = new Map<string, RunSummary[]>();
  for (const run of runs) {
    const list = byTarget.get(run.target_id) ?? [];
    list.push(run);
    byTarget.set(run.target_id, list);
  }
  const transitions = new Map<number, RunTransition>();
  for (const list of byTarget.values()) {
    const ordered = [...list].sort(chronological);
    let previous: RunSummary | null = null;
    let lastRisk: string | null = null;
    for (const run of ordered) {
      const active = isActiveStatus(run.status);
      const statusChange = !active && previous && previous.status !== run.status ? { from: previous.status, to: run.status } : null;
      let riskChange: RunTransition['riskChange'] = null;
      if (!active && run.risk_level && lastRisk && run.risk_level !== lastRisk) {
        const direction = (RISK_RANK[run.risk_level] ?? 0) > (RISK_RANK[lastRisk] ?? 0) ? 'up' : 'down';
        riskChange = { from: lastRisk, to: run.risk_level, direction };
      }
      transitions.set(run.id, { previous, statusChange, riskChange });
      if (!active) {
        previous = run;
        if (run.risk_level) lastRisk = run.risk_level;
      }
    }
  }
  return transitions;
}
