import { useLocale, type MessageKey } from '../i18n';
import type { RunSummary } from '../types';

export function StageSummary({ run }: { run: RunSummary }) {
  const { t } = useLocale();
  const stages = ['collection', 'qualification', 'synthesis', 'report', 'integrity'] as const;
  const known = ['ok', 'failed', 'incomplete', 'unavailable', 'skipped', 'not_recorded'];
  return <section className="state-card" aria-label={t('stages.title')}>
    <h2>{t('stages.title')}</h2>
    <dl>{stages.map((stage) => {
      const value = run[`${stage}_status`] ?? 'not_recorded';
      return <div key={stage}><dt>{t(`stages.${stage}`)}</dt><dd>{t(`stages.${known.includes(value) ? value : 'not_recorded'}` as MessageKey)}</dd></div>;
    })}</dl>
    {run.evidence_collected != null ? <p>{t('stages.count', { qualified: run.evidence_qualified ?? 0, collected: run.evidence_collected })}</p> : null}
    <p>{t('stages.notice')}</p>
  </section>;
}
