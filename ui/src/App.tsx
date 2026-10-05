import { useEffect } from 'react';
import { NavLink, Route, Routes } from 'react-router-dom';
import { useApiKey } from './auth';
import { ApiKeyGate } from './components/ApiKeyGate';
import { AppErrorBoundary } from './components/ErrorBoundary';
import { ErrorState, LoadingState } from './components/PageState';
import { trackUiTelemetry } from './lib/telemetry';
import { HomePage } from './pages/HomePage';
import { NotFoundPage } from './pages/NotFoundPage';
import { RunWorkspacePage } from './pages/RunWorkspacePage';
import { RunsPage } from './pages/RunsPage';
import { TargetDetailPage } from './pages/TargetDetailPage';
import { TargetsPage } from './pages/TargetsPage';
import { APP_ROUTES } from './routes';

function AppShell() {
  const { mode, hasKey, unavailableReason, forgetKey, retry } = useApiKey();

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <header className="topbar">
        <div className="brand-block">
          <span className="brand-mark" aria-hidden="true">
            OS
          </span>
          <div>
            <p className="brand-title">OSINT Orchestrator</p>
            <p className="brand-subtitle">Operator dashboard</p>
          </div>
        </div>

        <nav className="nav" aria-label="Main navigation">
          {APP_ROUTES.filter((route) => route.showInNav).map((route) => (
            <NavLink key={route.path} to={route.path} end={route.path === '/'}>
              {route.label}
            </NavLink>
          ))}
        </nav>

        {hasKey ? (
          <div className="toolbar">
            <button className="ghost-button" type="button" onClick={forgetKey}>
              Forget key
            </button>
          </div>
        ) : null}
      </header>

      <main id="main-content" className="content">
        {mode === 'checking' ? <LoadingState message="Checking API access…" /> : null}
        {mode === 'locked' ? <ApiKeyGate /> : null}
        {mode === 'unavailable' ? (
          <ErrorState
            title="API unavailable"
            description={unavailableReason ?? 'The orchestrator API could not be reached.'}
            action={
              <button type="button" className="primary-action" onClick={retry}>
                Retry
              </button>
            }
          />
        ) : null}
        {mode === 'open' || mode === 'ready' ? (
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/targets" element={<TargetsPage />} />
            <Route path="/targets/:targetId" element={<TargetDetailPage />} />
            <Route path="/targets/:targetId/runs/:runId" element={<RunWorkspacePage />} />
            <Route path="/runs" element={<RunsPage />} />
            <Route path="/runs/:runId" element={<RunWorkspacePage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        ) : null}
      </main>
    </div>
  );
}

export default function App() {
  useEffect(() => {
    trackUiTelemetry('app_loaded', { path: window.location.pathname });
  }, []);

  return (
    <AppErrorBoundary>
      <AppShell />
    </AppErrorBoundary>
  );
}
