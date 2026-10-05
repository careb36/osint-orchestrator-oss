import { formatDuration, parseApiDate } from './format';

describe('parseApiDate', () => {
  it('reads a naive API timestamp as UTC', () => {
    expect(parseApiDate('2026-10-01T06:00:00').toISOString()).toBe('2026-10-01T06:00:00.000Z');
    expect(parseApiDate('2026-10-01T06:00:00.250000').toISOString()).toBe('2026-10-01T06:00:00.250Z');
  });

  it('keeps an explicit offset', () => {
    expect(parseApiDate('2026-10-01T06:00:00Z').toISOString()).toBe('2026-10-01T06:00:00.000Z');
    expect(parseApiDate('2026-10-01T08:00:00+02:00').toISOString()).toBe('2026-10-01T06:00:00.000Z');
    expect(parseApiDate('2026-10-01T08:00:00+0200').toISOString()).toBe('2026-10-01T06:00:00.000Z');
  });

  it('leaves a date-only value alone', () => {
    expect(parseApiDate('2026-10-01').toISOString()).toBe('2026-10-01T00:00:00.000Z');
  });
});

describe('formatDuration', () => {
  it('works across naive and offset timestamps', () => {
    expect(formatDuration('2026-10-01T06:00:00', '2026-10-01T06:04:30')).toBe('4m 30s');
    expect(formatDuration('2026-10-01T06:00:00', '2026-10-01T08:00:30+02:00')).toBe('30s');
    expect(formatDuration('2026-10-01T06:00:00', null)).toBe('—');
  });
});
