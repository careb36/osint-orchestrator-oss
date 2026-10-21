import { lazy, Suspense, useEffect, type ReactNode } from 'react';
import { NavLink, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useApiKey } from './auth';
import { ApiKeyGate } from './components/ApiKeyGate';
import { AppErrorBoundary } from './components/ErrorBoundary';
import { ErrorFallback } from './components/ErrorFallback';
import { ErrorState, LoadingState } from './components/PageState';
import { locales, useLocale, type MessageKey } from './i18n';
import { api } from './lib/api';
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
const AlertsPage = lazy(() => import('./pages/AlertsPage').then((m) => ({ default: m.AlertsPage })));
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

/**
 * One page instance per run: keyed by the route param so the tab, the handoff
 * verification, the copied summary and the follow-up notice never carry over
 * when a link inside the page (the first broken run) changes the run.
 */
function RunWorkspaceRoute() {
  const { runId = '' } = useParams();
  return <RunWorkspacePage key={runId} />;
}

/** Rail icon per top-level route: telemetry over decoration, stroke inherits the link colour. */
const RAIL_ICONS: Record<string, ReactNode> = {
  '/': (
    <svg viewBox="0 0 20 20" width="17" height="17" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      <rect x="3" y="3" width="6" height="6" rx="1.2" />
      <rect x="11" y="3" width="6" height="6" rx="1.2" />
      <rect x="3" y="11" width="6" height="6" rx="1.2" />
      <rect x="11" y="11" width="6" height="6" rx="1.2" />
    </svg>
  ),
  '/targets': (
    <svg viewBox="0 0 20 20" width="17" height="17" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      <circle cx="10" cy="10" r="6.5" />
      <circle cx="10" cy="10" r="2.4" />
      <path d="M10 1.5v2.6M10 15.9v2.6M1.5 10h2.6M15.9 10h2.6" strokeLinecap="round" />
    </svg>
  ),
  '/runs': (
    <svg viewBox="0 0 20 20" width="17" height="17" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      <circle cx="10" cy="10" r="7" />
      <path d="M8.3 7.1l4.4 2.9-4.4 2.9z" fill="currentColor" stroke="none" />
    </svg>
  ),
  '/alerts': (
    <svg viewBox="0 0 20 20" width="17" height="17" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      <path d="M10 3.1 17.2 15.6H2.8z" strokeLinejoin="round" />
      <path d="M10 7.8v3.3" strokeLinecap="round" />
      <circle cx="10" cy="13.3" r="0.9" fill="currentColor" stroke="none" />
    </svg>
  ),
};

/**
 * Live platform state in the topbar, read from the open /health endpoint:
 * the same checks the overview renders, condensed to one telemetry dot.
 */
function SystemStatusChip() {
  const { t } = useLocale();
  // Polled, not read once: the shell stays mounted across navigation and
  // focus refetching is off (main.tsx), so without an interval the dot
  // would keep its first answer for the whole session. Same cache entry as
  // the overview's health cards (HomePage), so both change together.
  const health = useQuery({ queryKey: ['health'], queryFn: api.getHealth, staleTime: 30_000, refetchInterval: 30_000 });
  // A failed probe wins over the last cached answer: an API that stopped
  // answering is offline, whatever it said before.
  const status = health.isError ? 'offline' : health.data?.status;
  const tone = status === 'ok' ? 'ok' : status === 'degraded' ? 'warning' : status === 'offline' ? 'error' : 'muted';
  const label =
    status === 'ok'
      ? t('system.ok')
      : status === 'degraded'
        ? t('system.degraded')
        : status === 'offline'
          ? t('system.offline')
          : t('system.checking');
  return (
    // A polite live region: the poll may change the label while the operator
    // works elsewhere, and a screen reader should hear it without losing focus.
    <span className={`system-chip ${tone}`.trim()} aria-live="polite" aria-atomic="true">
      <span className="system-dot" aria-hidden="true" />
      {label}
    </span>
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
            <svg viewBox="0 0 48 48" width="36" height="36" fill="none" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <linearGradient id="osint-bg" x1="0" y1="0" x2="48" y2="48" gradientUnits="userSpaceOnUse">
                  <stop offset="0%" stopColor="#0c1930" />
                  <stop offset="100%" stopColor="#070e1c" />
                </linearGradient>
                <linearGradient id="osint-ring" x1="6" y1="6" x2="42" y2="42" gradientUnits="userSpaceOnUse">
                  <stop offset="0%" stopColor="#38bdf8" />
                  <stop offset="55%" stopColor="#6366f1" />
                  <stop offset="100%" stopColor="#a855f7" />
                </linearGradient>
                <linearGradient id="osint-sweep" x1="24" y1="24" x2="39" y2="11" gradientUnits="userSpaceOnUse">
                  <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.38" />
                  <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
                </linearGradient>
              </defs>
              <rect x="1.5" y="1.5" width="45" height="45" rx="12" fill="url(#osint-bg)" stroke="url(#osint-ring)" strokeWidth="2" />
              <path d="M24 24L36.5 11.5A17.5 17.5 0 0 1 41.5 24H24Z" fill="url(#osint-sweep)" />
              <circle cx="24" cy="24" r="15.5" stroke="url(#osint-ring)" strokeWidth="1.75" strokeDasharray="58 14 18 10" strokeLinecap="round" />
              <circle cx="24" cy="24" r="9.5" stroke="#38bdf8" strokeOpacity="0.32" strokeWidth="1.2" />
              <path d="M24 5.5V9M24 39V42.5M5.5 24H9M39 24H42.5" stroke="#38bdf8" strokeOpacity="0.55" strokeWidth="1.5" strokeLinecap="round" />
              <path d="M15 16L24 24M35 13L24 24M14 33L24 24M34 33L24 24" stroke="#7dd3fc" strokeOpacity="0.65" strokeWidth="1.5" strokeLinecap="round" />
              <circle cx="15" cy="16" r="2.4" fill="#38bdf8" />
              <circle cx="35" cy="13" r="2.6" fill="#a855f7" />
              <circle cx="14" cy="33" r="2.2" fill="#6366f1" />
              <circle cx="34" cy="33" r="2.4" fill="#38bdf8" />
              <circle cx="24" cy="24" r="4.6" fill="#38bdf8" fillOpacity="0.25" />
              <circle cx="24" cy="24" r="2.8" fill="#f8fafc" stroke="#38bdf8" strokeWidth="1.4" />
            </svg>
          </span>
          <div>
            <p className="brand-title">{t('appTitle')}</p>
            <p className="brand-subtitle">{t('appSubtitle')}</p>
          </div>
        </div>

        <SystemStatusChip />

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

      <div className="workbench">
        <nav className="rail" aria-label={t('mainNavigation')}>
          <p className="rail-title">{t('rail.title')}</p>
          {APP_ROUTES.filter((route) => route.showInNav).map((route) => (
            <NavLink key={route.path} to={route.path} end={route.path === '/'} className="rail-link">
              <span className="rail-icon">{RAIL_ICONS[route.path]}</span>
              <span className="rail-label">{t(route.labelKey as MessageKey)}</span>
            </NavLink>
          ))}
        </nav>

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
                <Route path="/targets/:targetId/runs/:runId" element={<RunWorkspaceRoute />} />
                <Route path="/runs" element={<RunsPage />} />
                <Route path="/runs/:runId" element={<RunWorkspaceRoute />} />
                <Route path="/alerts" element={<AlertsPage />} />
                <Route path="*" element={<NotFoundPage />} />
              </Routes>
            </ViewBoundary>
          ) : null}
        </main>
      </div>
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
