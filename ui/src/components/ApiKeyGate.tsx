import { type FormEvent, useState } from 'react';
import { useApiKey } from '../auth';

/** Asks for the operator's API key; shown while the API answers 401. */
export function ApiKeyGate() {
  const { submitKey } = useApiKey();
  const [key, setKey] = useState('');
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const result = await submitKey(key, remember);
    setBusy(false);
    if (!result.ok) {
      setError(result.message ?? 'Unable to use this key.');
    }
  };

  return (
    <section className="page">
      <div className="hero-card">
        <p className="eyebrow">Operator access</p>
        <h1>API key required</h1>
        <p className="lede">
          This dashboard reads the orchestrator API with the operator key (<code>ORCHESTRATOR_API_KEY</code>).
          The key stays in this browser tab; tick &ldquo;remember&rdquo; to keep it on this device.
        </p>
      </div>

      <form className="state-card key-form" onSubmit={handleSubmit} aria-labelledby="api-key-title">
        <h2 id="api-key-title">Enter the API key</h2>
        <label>
          <span className="label">API key</span>
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
          <span>Remember on this browser</span>
        </label>
        <p id="api-key-help" className="helper-text">
          Without &ldquo;remember&rdquo; the key is forgotten when the tab closes.
        </p>
        {error ? (
          <p className="state-card warning" role="alert">
            {error}
          </p>
        ) : null}
        <button type="submit" className="primary-action" disabled={busy}>
          {busy ? 'Checking…' : 'Use key'}
        </button>
      </form>
    </section>
  );
}
