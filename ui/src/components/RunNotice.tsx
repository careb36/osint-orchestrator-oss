import type { RunNotice as Notice } from '../hooks/useStartRun';
import { useLocale } from '../i18n';

/** Outcome of a Start-run click: success politely, failure as an alert. */
export function RunNotice({ notice }: { notice: Notice | null }) {
  const { t } = useLocale();
  if (!notice) return null;
  const text = notice.tone === 'ok' ? t('run.accepted', { runId: notice.runId, targetId: notice.targetId }) : (notice.detail ?? t('run.failed'));
  return (
    <p className={`state-card ${notice.tone === 'ok' ? 'ok' : 'error'}`} role={notice.tone === 'ok' ? 'status' : 'alert'}>
      {text}
    </p>
  );
}
