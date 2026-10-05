import { useLocale } from '../i18n';

/** Default error-boundary fallback; a function component so it can read the locale. */
export function ErrorFallback() {
  const { t } = useLocale();
  return (
    <div className="state-card error" role="alert">
      <h2>{t('error.title')}</h2>
      <p>{t('error.body')}</p>
    </div>
  );
}
