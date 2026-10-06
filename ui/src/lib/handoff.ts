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

const REASON_KEYS: Record<string, MessageKey> = {
  artefact_hash: 'chain.reason.artefact_hash',
  artefact_missing: 'chain.reason.artefact_missing',
  manifest_missing: 'chain.reason.manifest_missing',
  signature: 'chain.reason.signature',
  signature_key: 'chain.reason.signature_key',
  chain_link: 'chain.reason.chain_link',
  unsupported_version: 'chain.reason.unsupported_version',
};

/**
 * Why the chain broke, in the operator's language. The API's `message` is
 * rendered in the server's configured language, which need not match the
 * dashboard's, so the stable `reason` id is translated here; an id this
 * build does not know falls back to the server text.
 */
export function describeReason(t: Translate, result: ChainVerification): string {
  const key = result.reason ? REASON_KEYS[result.reason] : undefined;
  if (key) {
    return t(key, { name: result.detail ?? '', runId: result.first_broken_run_id ?? '' });
  }
  return result.message ?? result.reason ?? '';
}

/** Operator-language sentence for a chain verification result. */
export function describeVerification(t: Translate, result: ChainVerification): string {
  if (result.ok) {
    let text = result.checked === 1 ? t('handoff.chain.okOne') : t('handoff.chain.okMany', { checked: result.checked });
    if (result.unsealed > 0) {
      text += ` ${result.unsealed === 1 ? t('handoff.chain.unsealedOne') : t('handoff.chain.unsealedMany', { count: result.unsealed })}`;
    }
    return text;
  }
  const message = describeReason(t, result);
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
