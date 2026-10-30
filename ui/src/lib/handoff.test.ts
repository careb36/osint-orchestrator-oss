import { describe, expect, it } from 'vitest';
import { translate, translateValue } from '../i18n';
import type { MessageKey, Vars } from '../i18n';
import { sampleEvidence, sampleFinding, sampleRuns, sampleVerification } from '../test/mockApi';
import { buildHandoffSummary, describeReason, describeVerification } from './handoff';

const t = (key: MessageKey, vars?: Vars) => translate('en', key, vars);
const tv = (value: string) => translateValue('en', value);
const tEs = (key: MessageKey, vars?: Vars) => translate('es', key, vars);

describe('handoff helpers', () => {
  it('describes an intact chain with its sealed and unsealed counts', () => {
    expect(describeVerification(t, sampleVerification)).toBe('Chain intact: 1 sealed run verified.');
    expect(describeVerification(t, { ...sampleVerification, checked: 3, unsealed: 1 })).toBe(
      'Chain intact: 3 sealed runs verified. 1 unsealed run not counted.',
    );
  });

  it('agrees in number in Spanish', () => {
    expect(describeVerification(tEs, sampleVerification)).toBe('Cadena intacta: 1 ejecución sellada verificada.');
    expect(describeVerification(tEs, { ...sampleVerification, checked: 2, unsealed: 1 })).toBe(
      'Cadena intacta: 2 ejecuciones selladas verificadas. 1 ejecución sin sellar no se cuenta.',
    );
  });

  it('translates the broken reason in the operator language from its stable id, not the server text', () => {
    const broken = { ...sampleVerification, ok: false, first_broken_run_id: 41, reason: 'artefact_hash', detail: 'report.md', message: 'El hash del artefacto no coincide' };
    expect(describeVerification(t, broken)).toBe("Chain broken at run #41: Artefact hash mismatch for 'report.md'");
    expect(describeReason(tEs, broken)).toBe("El hash del artefacto 'report.md' no coincide");
    // A reason this build does not know falls back to what the server said.
    expect(describeVerification(t, { ...broken, reason: 'new_reason', message: 'Server says so' })).toBe('Chain broken at run #41: Server says so');
    expect(describeVerification(t, { ...broken, first_broken_run_id: null, reason: 'signature', message: undefined })).toBe(
      'Chain broken: The manifest was modified after the run (its hash does not match the recorded one)',
    );
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
