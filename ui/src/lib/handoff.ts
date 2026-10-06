import type { Locale, MessageKey, Vars } from '../i18n';
import type { ChainVerification, EvidenceRow, Finding, RunSummary } from '../types';
import { formatDateTime, formatDuration } from './format';

type Translate = (key: MessageKey, vars?: Vars) => string;
type TranslateValue = (value: string) => string;

export type HandoffInput = {
  run: RunSummary;
  finding: Finding | null | undefined;
  evidence: EvidenceRow[] | undefined;
  verification: ChainVerification | null | undefined;
  /** Where the run can be opened again (the current page URL). */
  href: string;
};

/** Operator-language sentence for a chain verification result. */
export function describeVerification(t: Translate, result: ChainVerification): string {
  if (result.ok) {
    const runs = result.checked === 1 ? t('target.run') : t('target.runs');
    let text = t('handoff.chain.ok', { checked: result.checked, runs });
    if (result.unsealed > 0) {
      const unsealedRuns = result.unsealed === 1 ? t('target.run') : t('target.runs');
      text += ` ${t('handoff.chain.unsealed', { count: result.unsealed, runs: unsealedRuns })}`;
    }
    return text;
  }
  const message = result.message ?? result.reason ?? '';
  return result.first_broken_run_id === null
    ? t('handoff.chain.brokenNoRun', { message })
    : t('handoff.chain.broken', { runId: result.first_broken_run_id, message });
}

/**
 * Plain-text summary an analyst pastes into a ticket or an e-mail when handing
 * a run over. Everything in it comes from the run's own records; the chain
 * line reflects the verification made in this session, or says it was not.
 */
export function buildHandoffSummary(t: Translate, tv: TranslateValue, locale: Locale, input: HandoffInput): string {
  const { run, finding, evidence, verification, href } = input;
  const lines = [
    t('handoff.summary.title'),
    `${t('handoff.summary.target')}: ${run.target_id}`,
    `${t('handoff.summary.run')}: #${run.id} · ${tv(run.status)}`,
    `${t('handoff.summary.started')}: ${formatDateTime(run.started_at, locale)}`,
    `${t('handoff.summary.finished')}: ${formatDateTime(run.finished_at, locale)} (${t('handoff.summary.duration')} ${formatDuration(run.started_at, run.finished_at)})`,
    `${t('handoff.summary.risk')}: ${finding ? tv(finding.risk_level) : t('handoff.summary.noSynthesis')}`,
    `${t('handoff.summary.newObservables')}: ${run.new_observables}`,
  ];
  if (evidence) {
    const count = (level: string) => evidence.filter((row) => row.relevance === level).length;
    lines.push(
      `${t('handoff.summary.evidence')}: ${t('handoff.summary.evidenceCounts', { high: count('high'), medium: count('medium'), low: count('low') })}`,
    );
  }
  lines.push(`${t('handoff.summary.sealed')}: ${run.manifest_sha256 ?? t('handoff.summary.unsealed')}`);
  lines.push(
    `${t('handoff.summary.chain')}: ${verification ? describeVerification(t, verification) : t('handoff.summary.chainUnverified')}`,
  );
  lines.push(`${t('handoff.summary.link')}: ${href}`);
  return lines.join('\n');
}
