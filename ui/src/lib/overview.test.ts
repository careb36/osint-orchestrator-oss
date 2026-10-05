import { buildTargetRows, computeKpis, median } from './overview';
import { sampleRuns, sampleTargets, sampleTrends } from '../test/mockApi';
import type { RunSummary, TargetSummary } from '../types';

const target = (id: string, enabled = true): TargetSummary => ({
  ...sampleTargets[0],
  id,
  fqdn: `${id}.example`,
  enabled,
});
const run = (id: number, target_id: string, status: RunSummary['status'], started: string, finished: string | null): RunSummary => ({
  ...sampleRuns[0],
  id,
  target_id,
  status,
  started_at: started,
  finished_at: finished,
});

describe('buildTargetRows', () => {
  it('orders by attention: active, high risk, failed, never run, rest, disabled', () => {
    const targets = [target('quiet'), target('never'), target('broken'), target('risky'), target('busy'), target('paused', false)];
    const runs = [
      run(1, 'quiet', 'success', '2026-10-01T06:00:00', '2026-10-01T06:05:00'),
      run(2, 'broken', 'failed', '2026-10-01T07:00:00', '2026-10-01T07:01:00'),
      run(3, 'risky', 'success', '2026-10-01T08:00:00', '2026-10-01T08:04:00'),
      run(4, 'busy', 'running', '2026-10-01T09:00:00', null),
      run(5, 'paused', 'success', '2026-09-01T09:00:00', '2026-09-01T09:02:00'),
    ];
    const trends = [{ ...sampleTrends[0], target_id: 'risky', latest_risk_level: 'high', peak_risk_level: 'critical' }];

    const rows = buildTargetRows(targets, runs, trends);
    expect(rows.map((row) => row.target.id)).toEqual(['busy', 'risky', 'broken', 'never', 'quiet', 'paused']);
    expect(rows[0].active).toBe(true);
    expect(rows[1].latestRisk).toBe('high');
    expect(rows[1].peakRisk).toBe('critical');
    expect(rows[3].lastRun).toBeNull();
  });

  it('picks the newest run per target even when the list is not sorted', () => {
    const runs = [
      run(1, 'a', 'failed', '2026-10-01T06:00:00', '2026-10-01T06:01:00'),
      run(2, 'a', 'success', '2026-10-02T06:00:00', '2026-10-02T06:01:00'),
    ];
    const [row] = buildTargetRows([target('a')], runs, []);
    expect(row.lastRun?.id).toBe(2);
    expect(row.attention).toBe(5);
  });
});

describe('computeKpis', () => {
  const now = new Date('2026-10-02T12:00:00Z');

  it('computes the counters from runs, targets and trends', () => {
    const targets = [target('a'), target('b'), target('c', false)];
    const runs = [
      run(1, 'a', 'success', '2026-10-02T06:00:00', '2026-10-02T06:04:00'),
      run(2, 'a', 'failed', '2026-09-30T06:00:00', '2026-09-30T06:02:00'),
      run(3, 'b', 'running', '2026-10-02T11:00:00', null),
      run(4, 'c', 'success', '2026-09-01T06:00:00', '2026-09-01T06:10:00'),
    ];
    const trends = [
      { ...sampleTrends[0], target_id: 'a', latest_risk_level: 'critical' },
      { ...sampleTrends[0], target_id: 'b', latest_risk_level: 'low' },
    ];
    const kpis = computeKpis(targets, runs, trends, now);
    expect(kpis.activeRuns).toBe(1);
    expect(kpis.runsLast24h).toBe(2);
    expect(kpis.terminalRuns).toBe(3);
    expect(kpis.successRate).toBeCloseTo(2 / 3);
    // Durations 4, 2 and 10 minutes → median 4.
    expect(kpis.medianRunMinutes).toBe(4);
    expect(kpis.targetsAtRisk).toBe(1);
    expect(kpis.enabledTargets).toBe(2);
    // "a" and "b" ran in the last 7 days (an active run counts); "c" is disabled.
    expect(kpis.coveredTargets).toBe(2);
  });

  it('returns nulls, not NaN, without terminal runs', () => {
    const kpis = computeKpis([target('a')], [run(1, 'a', 'pending', '2026-10-02T11:00:00', null)], [], now);
    expect(kpis.successRate).toBeNull();
    expect(kpis.medianRunMinutes).toBeNull();
    expect(kpis.activeRuns).toBe(1);
  });
});

describe('median', () => {
  it('handles odd, even and empty inputs', () => {
    expect(median([3, 1, 2])).toBe(2);
    expect(median([4, 1, 3, 2])).toBe(2.5);
    expect(median([])).toBeNull();
  });
});
