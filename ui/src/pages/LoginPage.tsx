import { FormEvent, useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { DEMO_USERS, useAuth } from '../auth';

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { signIn, isAuthenticated, legacyApiKey, setLegacyApiKey, session } = useAuth();
  const [username, setUsername] = useState('operator');
  const [password, setPassword] = useState('operator');
  const [apiKey, setApiKey] = useState(legacyApiKey ?? '');
  const [error, setError] = useState<string | null>(null);

  if (isAuthenticated) {
    const nextPath = typeof location.state === 'string' ? location.state : '/';
    return <Navigate to={nextPath} replace />;
  }

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    const result = signIn(username, password);
    if (!result.ok) {
      setError(result.message ?? 'Unable to sign in.');
      return;
    }

    if (apiKey.trim()) {
      setLegacyApiKey(apiKey);
    }
    const redirectTarget = typeof location.state === 'string' ? location.state : '/';
    navigate(redirectTarget, { replace: true });
  };

  return (
    <section className="page">
      <div className="hero-card">
        <p className="eyebrow">Operator access</p>
        <h1>Sign in</h1>
        <p className="lede">Session-based access is required for protected views. Legacy API-key mode remains available in browser session storage during transition.</p>
      </div>

      <form className="state-card" onSubmit={handleSubmit}>
        <label>
          <span className="label">Username</span>
          <input
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
          />
        </label>

        <label>
          <span className="label">Password</span>
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
          />
        </label>

        <label>
          <span className="label">Legacy API key (optional)</span>
          <input
            type="password"
            value={apiKey}
            onChange={(event) => setApiKey(event.target.value)}
            placeholder="km5..."
            autoComplete="off"
          />
        </label>

        <div className="demo-list">
          <strong>Demo accounts</strong>
          <ul>
            {Object.entries(DEMO_USERS).map(([name, data]) => (
              <li key={name}>
                {name} / {data.password} ({data.role})
              </li>
            ))}
          </ul>
        </div>

        {error ? (
          <p className="state-card warning" role="alert">
            {error}
          </p>
        ) : null}

        <button type="submit" className="primary-action">
          Continue
        </button>

        {session ? <p className="helper-text">Signed in as {session.displayName}</p> : null}
      </form>
    </section>
  );
}
