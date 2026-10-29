import { type FormEvent, useState } from 'react';
import { useApiKey } from '../auth';
import { useLocale } from '../i18n';
import { isKeyRemembered } from '../lib/api';
import { describeUnavailable } from '../lib/unavailable';

/** Asks for the operator's API key; shown while the API answers 401. */
export function ApiKeyGate() {
  const { submitKey, personal } = useApiKey();
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
      else if (result.reason === 'unavailable') setError(t('gate.unvalidated', { reason: describeUnavailable(t, result.cause) }));
      else setError(t('gate.unknownError'));
    }
  };

  if (personal) return <PersonalLogin />;
  return (
    <section className="page">
      <div className="hero-card">
        <p className="eyebrow">{t('gate.eyebrow')}</p>
        <h1>{t('gate.title')}</h1>
        <p className="lede">
          {t('gate.lede.before')}
          <code>ORCHESTRATOR_API_KEY</code>
          {t('gate.lede.after')}
        </p>
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

function PersonalLogin() {
  const { t } = useLocale();
  const { submitCredentials } = useApiKey();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setFailed(false);
    const ok = await submitCredentials(username, password);
    setPassword(''); setBusy(false); setFailed(!ok);
  };
  return <section className="page"><h1>{t('personal.login')}</h1><form className="state-card key-form" onSubmit={submit}>
    <label>{t('personal.username')}<input autoComplete="username" required value={username} onChange={(e) => setUsername(e.target.value)} /></label>
    <label>{t('personal.password')}<input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
    {failed ? <p role="alert">{t('personal.failed')}</p> : null}
    <button type="submit" disabled={busy}>{t('personal.login')}</button>
    <p>{t('personal.recovery')}</p>
  </form></section>;
}
