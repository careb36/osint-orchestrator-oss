import type { RunNotice as Notice } from '../hooks/useStartRun';

/** Outcome of a Start-run click: success politely, failure as an alert. */
export function RunNotice({ notice }: { notice: Notice | null }) {
  if (!notice) return null;
  return (
    <p className={`state-card ${notice.tone === 'ok' ? 'ok' : 'error'}`} role={notice.tone === 'ok' ? 'status' : 'alert'}>
      {notice.text}
    </p>
  );
}
