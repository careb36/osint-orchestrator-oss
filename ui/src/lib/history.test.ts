import { describe, expect, it } from 'vitest';
import type { RunSummary } from '../types';
import { runTransitions } from './history';

const run = (id: number, target: string, started: string, status: string, risk: string | null): RunSummary => ({
  id,
  target_id: target,
  started_at: started,
  finished_at: status === 'running' ? null : started,
  status,
  collectors_run: '',
  new_observables: 0,
  error: null,
  report_path: null,
  manifest_sha256: null,
  risk_level: risk,
});

describe('runTransitions', () => {
  it('compares each run with the previous one of the same target, in start order', () => {
    const runs = [
      run(3, 'a', '2026-10-03T00:00:00Z', 'success', 'high'),
      run(1, 'a', '2026-10-01T00:00:00Z', 'success', 'medium'),
      run(2, 'a', '2026-10-02T00:00:00Z', 'partial', 'medium'),
      run(9, 'b', '2026-10-02T00:00:00Z', 'success', 'low'),
    ];
    const t = runTransitions(runs);
    expect(t.get(1)).toEqual({ previous: null, statusChange: null, riskChange: null });
    expect(t.get(2)?.statusChange).toEqual({ from: 'success', to: 'partial' });
    expect(t.get(2)?.riskChange).toBeNull();
    expect(t.get(3)?.statusChange).toEqual({ from: 'partial', to: 'success' });
    expect(t.get(3)?.riskChange).toEqual({ from: 'medium', to: 'high', direction: 'up' });
    expect(t.get(9)?.previous).toBeNull(); // another target: its own history
  });

  it('keeps the last known risk across a run without a finding, and reports a decrease', () => {
    const runs = [
      run(1, 'a', '2026-10-01T00:00:00Z', 'success', 'critical'),
      run(2, 'a', '2026-10-02T00:00:00Z', 'failed', null),
      run(3, 'a', '2026-10-03T00:00:00Z', 'success', 'low'),
    ];
    const t = runTransitions(runs);
    expect(t.get(2)?.statusChange).toEqual({ from: 'success', to: 'failed' });
    expect(t.get(2)?.riskChange).toBeNull();
    expect(t.get(3)?.riskChange).toEqual({ from: 'critical', to: 'low', direction: 'down' });
    expect(t.get(3)?.previous?.id).toBe(2);
  });

  it('gives an active run no change and does not use it as a predecessor', () => {
    const runs = [
      run(1, 'a', '2026-10-01T00:00:00Z', 'success', 'low'),
      run(2, 'a', '2026-10-02T00:00:00Z', 'running', null),
      run(3, 'a', '2026-10-03T00:00:00Z', 'failed', null),
    ];
    const t = runTransitions(runs);
    expect(t.get(2)).toEqual({ previous: runs[0], statusChange: null, riskChange: null });
    expect(t.get(3)?.previous?.id).toBe(1);
    expect(t.get(3)?.statusChange).toEqual({ from: 'success', to: 'failed' });
  });
});
