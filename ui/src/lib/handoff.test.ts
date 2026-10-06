import { describe, expect, it } from 'vitest';
import { translate, translateValue } from '../i18n';
import type { MessageKey, Vars } from '../i18n';
import { sampleEvidence, sampleFinding, sampleRuns, sampleVerification } from '../test/mockApi';
import { buildHandoffSummary, describeVerification } from './handoff';

const t = (key: MessageKey, vars?: Vars) => translate('en', key, vars);
const tv = (value: string) => translateValue('en', value);

describe('handoff helpers', () => {
  it('describes an intact chain with its sealed and unsealed counts', () => {
    expect(describeVerification(t, sampleVerification)).toBe('Chain intact: 1 sealed run verified.');
    expect(describeVerification(t, { ...sampleVerification, checked: 3, unsealed: 1 })).toBe(
      'Chain intact: 3 sealed runs verified. 1 unsealed run not counted.',
    );
  });

  it('describes a broken chain with the run and the operator-language message', () => {
    const broken = { ...sampleVerification, ok: false, first_broken_run_id: 41, reason: 'signature', message: 'Manifest signature does not match the configured key' };
    expect(describeVerification(t, broken)).toBe('Chain broken at run #41: Manifest signature does not match the configured key');
    expect(describeVerification(t, { ...broken, first_broken_run_id: null, message: undefined })).toBe('Chain broken: signature');
  });

  it('builds a plain-text summary from the run records only', () => {
    const text = buildHandoffSummary(t, tv, 'en', {
      run: sampleRuns[0],
      finding: sampleFinding,
      evidence: sampleEvidence,
      verification: sampleVerification,
      href: 'https://console.example/console/runs/42',
    });
    const lines = text.split('\n');
    expect(lines[0]).toBe('Handoff summary');
    expect(lines).toContain('Target: example-corp');
    expect(lines).toContain('Run: #42 · success');
    expect(lines).toContain('Risk level: high');
    expect(lines).toContain('New observables: 3');
    expect(lines).toContain('Qualified evidence: 1 high · 1 medium · 1 low');
    expect(lines).toContain(`Sealed manifest: ${'a'.repeat(64)}`);
    expect(lines).toContain('Evidence chain: Chain intact: 1 sealed run verified.');
    expect(lines).toContain('Dashboard: https://console.example/console/runs/42');
    // The unsealed, unsynthesised, unverified run states each have words, not blanks.
    const bare = buildHandoffSummary(t, tv, 'en', { run: sampleRuns[1], finding: null, evidence: undefined, verification: null, href: 'x' });
    expect(bare).toContain('Risk level: no synthesis');
    expect(bare).toContain('Sealed manifest: not sealed');
    expect(bare).toContain('Evidence chain: not verified in this session');
    expect(bare).not.toContain('Qualified evidence');
  });
});
