import { NavLink, Route, Routes } from 'react-router-dom';
import { AppErrorBoundary } from './components/ErrorBoundary';
import { HomePage } from './pages/HomePage';
import { NotFoundPage } from './pages/NotFoundPage';
import { RunsPage } from './pages/RunsPage';
import { TargetsPage } from './pages/TargetsPage';
import { APP_ROUTES, QUICK_ACTIONS } from './routes';

function AppShell() {
  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-block">
          <span className="brand-mark">OS</span>
          <div>
            <p className="brand-title">OSINT Orchestrator</p>
            <p className="brand-subtitle">Control centre</p>
          </div>
        </div>

        <nav className="nav" aria-label="Main navigation">
          {APP_ROUTES.filter((route) => route.showInNav).map((route) => (
            <NavLink key={route.path} to={route.path} end={route.path === '/'}>
              {route.label}
            </NavLink>
          ))}
        </nav>
      </header>

      <div className="shell-toolbar" aria-label="Quick actions">
        {QUICK_ACTIONS.map((action) => (
          <NavLink key={action.to} className="action-chip" to={action.to}>
            {action.label}
          </NavLink>
        ))}
      </div>

      <main className="content">
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/targets" element={<TargetsPage />} />
          <Route path="/runs" element={<RunsPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <AppErrorBoundary>
      <AppShell />
    </AppErrorBoundary>
  );
}
