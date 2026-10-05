import type { UnavailableReason } from '../auth';
import type { MessageKey, Vars } from '../i18n';

type T = (key: MessageKey, vars?: Vars) => string;

/** Operator prose for an unreachable API; the raw cause never reaches the page. */
export function describeUnavailable(t: T, reason: UnavailableReason): string {
  return reason.kind === 'network' ? t('unavailable.bodyNetwork') : t('unavailable.bodyWithStatus', { status: reason.status });
}
