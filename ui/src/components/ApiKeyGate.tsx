import { type FormEvent, useState } from 'react';
import { useApiKey } from '../auth';
import { useLocale } from '../i18n';
import { isKeyRemembered } from '../lib/api';

/** Asks for the operator's API key; shown while the API answers 401. */
export function ApiKeyGate() {
  const { submitKey } = useApiKey();
  const { t } = useLocale();
  const [key, setKey] = useState('');
  // Pre-tick when the last key was remembered on this browser: clearApiKey()
  // keeps that preference, so a rejected or forgotten key leaves it in place.
  const [remember, setRemember] = useState(() => isKeyRemembered());
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const result = await submitKey(key, remember);
    setBusy(false);
    if (!result.ok) {
      if (result.reason === 'empty') setError(t('gate.empty'));
      else if (result.reason === 'rejected') setError(t('gate.rejected'));
      else if (result.reason === 'unavailable') setError(t('gate.unvalidated', { reason: t('unavailable.bodyWithStatus', { status: result.status }) }));
      else setError(t('gate.unknownError'));
    }
  };

  return (
    <section className="page">
      <div className="hero-card">
        <p className="eyebrow">{t('gate.eyebrow')}</p>
        <h1>{t('gate.title')}</h1>
        <p className="lede">{t('gate.lede', { setting: 'ORCHESTRATOR_API_KEY' })}</p>
      </div>

      <form className="state-card key-form" onSubmit={handleSubmit} aria-labelledby="api-key-title">
        <h2 id="api-key-title">{t('gate.formTitle')}</h2>
        <label>
          <span className="label">{t('gate.keyLabel')}</span>
          <input
            type="password"
            value={key}
            onChange={(event) => setKey(event.target.value)}
            autoComplete="off"
            autoFocus
            required
            aria-describedby="api-key-help"
          />
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={remember} onChange={(event) => setRemember(event.target.checked)} />
          <span>{t('gate.remember')}</span>
        </label>
        <p id="api-key-help" className="helper-text">
          {t('gate.help')}
        </p>
        {error ? (
          <p className="state-card warning" role="alert">
            {error}
          </p>
        ) : null}
        <button type="submit" className="primary-action" disabled={busy}>
          {busy ? t('gate.checking') : t('gate.submit')}
        </button>
      </form>
    </section>
  );
}
