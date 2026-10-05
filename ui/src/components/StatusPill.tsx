import { useLocale } from '../i18n';
import type { Tone } from '../lib/format';

/** A persisted identifier (status, risk, relevance) shown with its display label. */
export function StatusPill({ label, tone }: { label: string; tone: Tone }) {
  const { tv } = useLocale();
  return (
    <span className={`status-pill ${tone}`.trim()} data-value={label}>
      {tv(label)}
    </span>
  );
}
