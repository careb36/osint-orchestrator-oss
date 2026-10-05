import { type ReactNode } from 'react';
import { Navigate, NavLink, Route, Routes, useLocation } from 'react-router-dom';
import { useAuth } from './auth';
import { AppErrorBoundary } from './components/ErrorBoundary';
import { LoginPage } from './pages/LoginPage';
import { HomePage } from './pages/HomePage';
import { NotFoundPage } from './pages/NotFoundPage';
import { RunWorkspacePage } from './pages/RunWorkspacePage';
import { RunsPage } from './pages/RunsPage';
import { TargetDetailPage } from './pages/TargetDetailPage';
import { TargetsPage } from './pages/TargetsPage';
import { QUICK_ACTIONS } from './routes';

function ProtectedRoute({ children }: { children: ReactNode }) {
  const { session, canAccess } = useAuth();
  const location = useLocation();

  if (!session) {
    return <Navigate to="/login" replace state={location.pathname} />;
  }

  if (!canAccess(location.pathname)) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}

function AppShell() {
  const { session, signOut } = useAuth();
  const navItems = [
    { to: '/', label: 'Overview', roles: ['viewer', 'operator', 'admin'] },
    { to: '/targets', label: 'Targets', roles: ['operator', 'admin'] },
    { to: '/runs', label: 'Runs', roles: ['operator', 'admin'] },
  ].filter(({ roles }) => session && roles.includes(session.role));

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

        {session ? (
          <div className="toolbar">
            <div className="session-chip" aria-live="polite">
              <span>{session.displayName}</span>
              <small>{session.role}</small>
            </div>
            <button className="ghost-button" type="button" onClick={signOut}>
              Sign out
            </button>
          </div>
        ) : null}

        <nav className="nav" aria-label="Main navigation">
          {navItems.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.to === '/'}>
              {item.label}
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
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={<ProtectedRoute><HomePage /></ProtectedRoute>} />
          <Route path="/targets" element={<ProtectedRoute><TargetsPage /></ProtectedRoute>} />
          <Route path="/targets/:targetId" element={<ProtectedRoute><TargetDetailPage /></ProtectedRoute>} />
          <Route path="/targets/:targetId/runs/:runId" element={<ProtectedRoute><RunWorkspacePage /></ProtectedRoute>} />
          <Route path="/runs" element={<ProtectedRoute><RunsPage /></ProtectedRoute>} />
          <Route path="/runs/:runId" element={<ProtectedRoute><RunWorkspacePage /></ProtectedRoute>} />
          <Route path="*" element={<ProtectedRoute><NotFoundPage /></ProtectedRoute>} />
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
