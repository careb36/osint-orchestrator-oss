import type { ReactNode } from 'react';
import { useLocale } from '../i18n';
import type { RunTransition } from '../lib/history';

/** What changed from the previous run of the target: status, risk, or nothing. */
export function RunChange({ transition }: { transition: RunTransition | undefined }) {
  const { t, tv } = useLocale();
  if (!transition) return <span className="muted">—</span>;
  if (!transition.previous) return <span className="muted">{t('history.first')}</span>;
  const parts: ReactNode[] = [];
  if (transition.statusChange) {
    parts.push(
      <span key="status" className="change">
        {t('history.status', { from: tv(transition.statusChange.from), to: tv(transition.statusChange.to) })}
      </span>,
    );
  }
  if (transition.riskChange) {
    const { from, to, direction } = transition.riskChange;
    parts.push(
      <span key="risk" className={`change change-${direction}`}>
        {t(direction === 'up' ? 'history.riskUp' : 'history.riskDown', { from: tv(from), to: tv(to) })}
      </span>,
    );
  }
  if (parts.length === 0) return <span className="muted">{t('history.none')}</span>;
  return <span className="changes">{parts}</span>;
}
