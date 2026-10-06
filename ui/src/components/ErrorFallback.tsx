import { Link } from 'react-router-dom';
import { useLocale } from '../i18n';

type ErrorFallbackProps = {
  /**
   * `view`: one routed view crashed and the shell still works, so the way out
   * is to render the view again or to open another one. `app`: the shell
   * itself crashed; nothing around the message works, only a reload does.
   */
  scope?: 'view' | 'app';
  onRetry?: () => void;
};

/** Default error-boundary fallback with a visible way out. */
export function ErrorFallback({ scope = 'view', onRetry }: ErrorFallbackProps) {
  const { t } = useLocale();
  return (
    <div className="state-card error" role="alert">
      <h2>{t('error.title')}</h2>
      <p>{scope === 'app' ? t('error.appBody') : t('error.body')}</p>
      <div className="workspace-actions">
        {scope === 'app' ? (
          <button type="button" className="primary-action" onClick={() => window.location.reload()}>
            {t('error.reload')}
          </button>
        ) : (
          <>
            {onRetry ? (
              <button type="button" className="primary-action" onClick={onRetry}>
                {t('error.retry')}
              </button>
            ) : null}
            <Link className="ghost-button" to="/">
              {t('error.backHome')}
            </Link>
          </>
        )}
      </div>
    </div>
  );
}
