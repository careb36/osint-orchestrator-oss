import { Link } from 'react-router-dom';
import { useLocale } from '../i18n';

/**
 * Default error-boundary fallback with a visible way out: render the view
 * again (the error may have been transient) or go back to the overview.
 */
export function ErrorFallback({ onRetry }: { onRetry?: () => void }) {
  const { t } = useLocale();
  return (
    <div className="state-card error" role="alert">
      <h2>{t('error.title')}</h2>
      <p>{t('error.body')}</p>
      <div className="handoff-actions">
        {onRetry ? (
          <button type="button" className="primary-action" onClick={onRetry}>
            {t('error.retry')}
          </button>
        ) : null}
        <Link className="ghost-button" to="/">
          {t('error.backHome')}
        </Link>
      </div>
    </div>
  );
}
