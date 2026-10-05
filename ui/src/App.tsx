import { useEffect } from 'react';
import { NavLink, Route, Routes } from 'react-router-dom';
import { useApiKey } from './auth';
import { ApiKeyGate } from './components/ApiKeyGate';
import { AppErrorBoundary } from './components/ErrorBoundary';
import { ErrorState, LoadingState } from './components/PageState';
import { locales, useLocale, type MessageKey } from './i18n';
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
  const { locale, setLocale, t } = useLocale();

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        {t('skipToContent')}
      </a>
      <header className="topbar">
        <div className="brand-block">
          <span className="brand-mark" aria-hidden="true">
            OS
          </span>
          <div>
            <p className="brand-title">{t('appTitle')}</p>
            <p className="brand-subtitle">{t('appSubtitle')}</p>
          </div>
        </div>

        <nav className="nav" aria-label={t('mainNavigation')}>
          {APP_ROUTES.filter((route) => route.showInNav).map((route) => (
            <NavLink key={route.path} to={route.path} end={route.path === '/'}>
              {t(route.labelKey as MessageKey)}
            </NavLink>
          ))}
        </nav>

        <div className="toolbar">
          <div className="lang-switch" role="group" aria-label={t('languageSwitcher')}>
            {locales.map((candidate) => (
              <button
                key={candidate}
                type="button"
                lang={candidate}
                aria-pressed={locale === candidate}
                onClick={() => setLocale(candidate)}
              >
                {t(`locale.${candidate}` as MessageKey)}
              </button>
            ))}
          </div>
          {hasKey ? (
            <button className="ghost-button" type="button" onClick={forgetKey}>
              {t('forgetKey')}
            </button>
          ) : null}
        </div>
      </header>

      <main id="main-content" className="content">
        {mode === 'checking' ? <LoadingState message={t('checkingAccess')} /> : null}
        {mode === 'locked' ? <ApiKeyGate /> : null}
        {mode === 'unavailable' ? (
          <ErrorState
            title={t('unavailable.title')}
            description={unavailableReason ? t('unavailable.bodyWithStatus', { status: unavailableReason }) : t('unavailable.body')}
            action={
              <button type="button" className="primary-action" onClick={retry}>
                {t('retry')}
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
