import type { RunNotice as Notice } from '../hooks/useStartRun';
import { useLocale, type MessageKey } from '../i18n';

const STATUS_KEYS: Record<number, MessageKey> = {
  400: 'run.failed.disabled',
  401: 'run.failed.unauthorized',
  404: 'run.failed.notFound',
  409: 'run.failed.inProgress',
};

/** Outcome of a Start-run click: success politely, failure as an alert. */
export function RunNotice({ notice }: { notice: Notice | null }) {
  const { t } = useLocale();
  if (!notice) return null;
  if (notice.tone === 'ok') {
    return (
      <p className="state-card ok" role="status">
        {t('run.accepted', { runId: notice.runId, targetId: notice.targetId })}
      </p>
    );
  }
  const key = notice.status === null ? 'run.failed' : STATUS_KEYS[notice.status];
  const text = key ? t(key) : t('run.failed.status', { status: notice.status ?? '' });
  return (
    <p className="state-card error" role="alert">
      {text}
      {notice.detail ? (
        <>
          <br />
          <small className="muted">{t('run.serverDetail', { detail: notice.detail })}</small>
        </>
      ) : null}
    </p>
  );
}
