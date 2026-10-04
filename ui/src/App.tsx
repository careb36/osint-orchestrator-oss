import { NavLink, Route, Routes } from 'react-router-dom';
import { AppErrorBoundary } from './components/ErrorBoundary';
import { HomePage } from './pages/HomePage';
import { NotFoundPage } from './pages/NotFoundPage';
import { RunsPage } from './pages/RunsPage';
import { TargetsPage } from './pages/TargetsPage';

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
          <NavLink to="/" end>Overview</NavLink>
          <NavLink to="/targets">Targets</NavLink>
          <NavLink to="/runs">Runs</NavLink>
        </nav>
      </header>

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
