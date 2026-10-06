import { filterDelta, filterEvidence, filterRuns, filterTargets, matchesQuery, sortEvidence, sortRuns, sortTargets } from './listing';
import { buildTargetRows } from './overview';
import { sampleDelta, sampleEvidence, sampleRuns, sampleTargets, sampleTrends } from '../test/mockApi';
import type { RunSummary } from '../types';

const now = new Date('2026-10-02T12:00:00Z');
const run = (id: number, target_id: string, status: RunSummary['status'], started: string, finished: string | null, extra: Partial<RunSummary> = {}): RunSummary => ({
  ...sampleRuns[0],
  id,
  target_id,
  status,
  started_at: started,
  finished_at: finished,
  ...extra,
});

describe('matchesQuery', () => {
  it('matches every word, case-insensitively, across the fields', () => {
    expect(matchesQuery(['example-corp', 'Example.com'], 'EXAMPLE corp')).toBe(true);
    expect(matchesQuery(['example-corp', 'example.com'], 'corp other')).toBe(false);
    expect(matchesQuery([null, undefined, 'x'], '')).toBe(true);
  });
});

describe('targets', () => {
  const rows = buildTargetRows(sampleTargets, sampleRuns, sampleTrends);

  it('filters by query, enabled flag, last-run status and risk', () => {
    expect(filterTargets(rows, { query: 'spiderfoot', enabled: 'all', status: '', risk: '' }).map((r) => r.target.id)).toEqual(['example-corp']);
    expect(filterTargets(rows, { query: '', enabled: 'disabled', status: '', risk: '' }).map((r) => r.target.id)).toEqual(['paused-target']);
    expect(filterTargets(rows, { query: '', enabled: 'all', status: 'failed', risk: '' }).map((r) => r.target.id)).toEqual(['paused-target']);
    expect(filterTargets(rows, { query: '', enabled: 'all', status: 'never', risk: '' })).toEqual([]);
    expect(filterTargets(rows, { query: '', enabled: 'all', status: '', risk: 'high' }).map((r) => r.target.id)).toEqual(['example-corp']);
  });

  it('sorts by target name, last run, status and risk in both directions', () => {
    expect(sortTargets(rows, { key: 'target', dir: 'asc' }).map((r) => r.target.fqdn)).toEqual(['example.com', 'paused.example']);
    expect(sortTargets(rows, { key: 'target', dir: 'desc' }).map((r) => r.target.fqdn)).toEqual(['paused.example', 'example.com']);
    expect(sortTargets(rows, { key: 'lastRun', dir: 'desc' }).map((r) => r.target.id)).toEqual(['paused-target', 'example-corp']);
    expect(sortTargets(rows, { key: 'risk', dir: 'desc' }).map((r) => r.latestRisk)).toEqual(['high', 'unknown']);
    expect(sortTargets(rows, { key: 'status', dir: 'asc' }).map((r) => r.lastRun?.status)).toEqual(['failed', 'success']);
  });

  it('keeps unknown risk last whatever the direction', () => {
    for (const dir of ['asc', 'desc'] as const) {
      const sorted = sortTargets(rows, { key: 'risk', dir });
      expect(sorted[sorted.length - 1].latestRisk).toBe('unknown');
    }
  });

  it('keeps targets without a run last whatever the direction', () => {
    const withNever = buildTargetRows([...sampleTargets, { ...sampleTargets[0], id: 'fresh', fqdn: 'fresh.example' }], sampleRuns, []);
    for (const dir of ['asc', 'desc'] as const) {
      const sorted = sortTargets(withNever, { key: 'lastRun', dir });
      expect(sorted[sorted.length - 1].target.id).toBe('fresh');
    }
  });
});

describe('runs', () => {
  const runs = [
    run(1, 'a', 'success', '2026-10-02T06:00:00', '2026-10-02T06:04:00', { new_observables: 3 }),
    run(2, 'b', 'failed', '2026-09-30T06:00:00', '2026-09-30T06:01:00', { error: 'collector timeout', new_observables: 0 }),
    run(3, 'a', 'running', '2026-10-02T11:30:00', null, { new_observables: 0 }),
    run(4, 'c', 'partial', '2026-09-01T06:00:00', '2026-09-01T06:10:00', { new_observables: 7 }),
  ];

  it('filters by query, target, status and recency', () => {
    expect(filterRuns(runs, { query: 'timeout', target: '', status: '', since: '' }, now).map((r) => r.id)).toEqual([2]);
    expect(filterRuns(runs, { query: '', target: 'a', status: '', since: '' }, now).map((r) => r.id)).toEqual([1, 3]);
    expect(filterRuns(runs, { query: '', target: '', status: 'running', since: '' }, now).map((r) => r.id)).toEqual([3]);
    expect(filterRuns(runs, { query: '', target: '', status: '', since: '24h' }, now).map((r) => r.id)).toEqual([1, 3]);
    expect(filterRuns(runs, { query: '', target: '', status: '', since: '7d' }, now).map((r) => r.id)).toEqual([1, 2, 3]);
    expect(filterRuns(runs, { query: '#4', target: '', status: '', since: '' }, now)).toEqual([]);
    expect(filterRuns(runs, { query: '4', target: '', status: '', since: '' }, now).map((r) => r.id)).toEqual([4]);
    // An unknown window from a hand-edited link filters nothing (never NaN).
    expect(filterRuns(runs, { query: '', target: '', status: '', since: '7days' as never }, now)).toHaveLength(4);
  });

  it('sorts by start, duration (active runs use now), observables, status and target', () => {
    expect(sortRuns(runs, { key: 'started', dir: 'desc' }, now).map((r) => r.id)).toEqual([3, 1, 2, 4]);
    expect(sortRuns(runs, { key: 'duration', dir: 'desc' }, now).map((r) => r.id)).toEqual([3, 4, 1, 2]);
    expect(sortRuns(runs, { key: 'observables', dir: 'desc' }, now).map((r) => r.id)).toEqual([4, 1, 2, 3]);
    expect(sortRuns(runs, { key: 'status', dir: 'asc' }, now).map((r) => r.status)).toEqual(['running', 'failed', 'partial', 'success']);
    expect(sortRuns(runs, { key: 'target', dir: 'asc' }, now).map((r) => r.target_id)).toEqual(['a', 'a', 'b', 'c']);
  });

  it('sorts by risk level and keeps runs without a finding last either way', () => {
    const withRisk = [
      { ...runs[0], risk_level: 'medium' },
      { ...runs[1], risk_level: null },
      { ...runs[2], risk_level: 'critical' },
      { ...runs[3], risk_level: 'low' },
    ];
    expect(sortRuns(withRisk, { key: 'risk', dir: 'desc' }, now).map((r) => r.id)).toEqual([3, 1, 4, 2]);
    expect(sortRuns(withRisk, { key: 'risk', dir: 'asc' }, now).map((r) => r.id)).toEqual([4, 1, 3, 2]);
  });
});

describe('evidence and delta', () => {
  it('filters evidence by query, relevance and category, and sorts it', () => {
    expect(filterEvidence(sampleEvidence, { query: 'portal', relevance: '', category: '' }).map((r) => r.id)).toEqual([3]);
    expect(filterEvidence(sampleEvidence, { query: '', relevance: 'high', category: '' }).map((r) => r.id)).toEqual([1]);
    expect(filterEvidence(sampleEvidence, { query: '', relevance: '', category: 'news' }).map((r) => r.id)).toEqual([2]);
    expect(sortEvidence(sampleEvidence, { key: 'relevance', dir: 'desc' }).map((r) => r.relevance)).toEqual(['high', 'medium', 'low']);
    expect(sortEvidence(sampleEvidence, { key: 'confidence', dir: 'asc' }).map((r) => r.confidence)).toEqual([0.35, 0.6, 0.91]);
    expect(sortEvidence(sampleEvidence, { key: 'category', dir: 'asc' }).map((r) => r.category)).toEqual(['credential-leak', 'exposure', 'news']);
    const odd = [...sampleEvidence, { ...sampleEvidence[0], id: 9, relevance: 'weird' }];
    for (const dir of ['asc', 'desc'] as const) {
      const sorted = sortEvidence(odd, { key: 'relevance', dir });
      expect(sorted[sorted.length - 1].id).toBe(9);
    }
  });

  it('filters delta rows by type and value', () => {
    expect(filterDelta(sampleDelta, { query: '', type: 'url' }).map((r) => r.value)).toEqual(['https://paste.example/abc']);
    expect(filterDelta(sampleDelta, { query: 'vpn', type: '' }).map((r) => r.value)).toEqual(['vpn.example.com']);
    expect(filterDelta(sampleDelta, { query: 'vpn', type: 'url' })).toEqual([]);
  });
});
