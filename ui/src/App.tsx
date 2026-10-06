import { lazy, Suspense, useEffect, type ReactNode } from 'react';
import { NavLink, Route, Routes, useLocation } from 'react-router-dom';
import { useApiKey } from './auth';
import { ApiKeyGate } from './components/ApiKeyGate';
import { AppErrorBoundary } from './components/ErrorBoundary';
import { ErrorFallback } from './components/ErrorFallback';
import { ErrorState, LoadingState } from './components/PageState';
import { locales, useLocale, type MessageKey } from './i18n';
import { describeUnavailable } from './lib/unavailable';
import { trackUiTelemetry } from './lib/telemetry';
import { APP_ROUTES } from './routes';

// One chunk per view: the shell and the overview load first, the rest when
// a view is opened (vite.config.ts splits the vendor libraries separately).
const HomePage = lazy(() => import('./pages/HomePage').then((m) => ({ default: m.HomePage })));
const TargetsPage = lazy(() => import('./pages/TargetsPage').then((m) => ({ default: m.TargetsPage })));
const TargetDetailPage = lazy(() => import('./pages/TargetDetailPage').then((m) => ({ default: m.TargetDetailPage })));
const RunsPage = lazy(() => import('./pages/RunsPage').then((m) => ({ default: m.RunsPage })));
const RunWorkspacePage = lazy(() => import('./pages/RunWorkspacePage').then((m) => ({ default: m.RunWorkspacePage })));
const NotFoundPage = lazy(() => import('./pages/NotFoundPage').then((m) => ({ default: m.NotFoundPage })));

/**
 * A crash inside one view shows the fallback in place of that view only; the
 * shell, the navigation and the language switch keep working, and moving to
 * another route (the key) renders views again.
 */
function ViewBoundary({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  const { t } = useLocale();
  return (
    <AppErrorBoundary resetKey={pathname}>
      <Suspense fallback={<LoadingState message={t('loadingView')} />}>{children}</Suspense>
    </AppErrorBoundary>
  );
}

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
            description={unavailableReason ? describeUnavailable(t, unavailableReason) : t('unavailable.body')}
            action={
              <button type="button" className="primary-action" onClick={retry}>
                {t('retry')}
              </button>
            }
          />
        ) : null}
        {mode === 'open' || mode === 'ready' ? (
          <ViewBoundary>
            <Routes>
              <Route path="/" element={<HomePage />} />
              <Route path="/targets" element={<TargetsPage />} />
              <Route path="/targets/:targetId" element={<TargetDetailPage />} />
              <Route path="/targets/:targetId/runs/:runId" element={<RunWorkspacePage />} />
              <Route path="/runs" element={<RunsPage />} />
              <Route path="/runs/:runId" element={<RunWorkspacePage />} />
              <Route path="*" element={<NotFoundPage />} />
            </Routes>
          </ViewBoundary>
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
    // The shell's own boundary: when it fires nothing around it works, so its
    // fallback offers a reload, not a route change.
    <AppErrorBoundary fallback={<ErrorFallback scope="app" />}>
      <AppShell />
    </AppErrorBoundary>
  );
}
