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

/** A level the comparison can use: a finding without one says `unknown`, which is no information. */
function knownRisk(level: string | null | undefined): string | null {
  return level && level !== 'unknown' && level in RISK_RANK ? level : null;
}

function chronological(a: RunSummary, b: RunSummary): number {
  return parseApiDate(a.started_at).getTime() - parseApiDate(b.started_at).getTime() || a.id - b.id;
}

/**
 * What changed from one run of a target to the next, keyed by run id.
 *
 * Runs are compared in start order within their target. A run still active
 * has no result yet, so it carries no change; a run without a finding (failed
 * early, synthesis off) or whose finding says `unknown` does not reset the
 * risk: the comparison uses the last level the target was known to have, and
 * `unknown` is never ranked below `low`.
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
      const risk = active ? null : knownRisk(run.risk_level);
      if (risk && lastRisk && risk !== lastRisk) {
        const direction = RISK_RANK[risk] > RISK_RANK[lastRisk] ? 'up' : 'down';
        riskChange = { from: lastRisk, to: risk, direction };
      }
      transitions.set(run.id, { previous, statusChange, riskChange });
      if (!active) {
        previous = run;
        if (risk) lastRisk = risk;
      }
    }
  }
  return transitions;
}
