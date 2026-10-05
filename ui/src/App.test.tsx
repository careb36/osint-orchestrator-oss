import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import App from './App';
import { AuthProvider } from './auth';
import { AppErrorBoundary } from './components/ErrorBoundary';

const renderWithProviders = (ui: React.ReactElement, initialEntries = ['/']) => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={initialEntries}>
        <AuthProvider>{ui}</AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
};

describe('App shell', () => {
  beforeEach(() => {
    window.sessionStorage.clear();
  });

  it('redirects unauthenticated users to the login screen', () => {
    renderWithProviders(<App />, ['/targets']);

    expect(screen.getByRole('heading', { name: /sign in/i })).toBeInTheDocument();
    expect(screen.getByText(/legacy api-key/i)).toBeInTheDocument();
  });

  it('shows role-aware navigation for an operator', () => {
    window.sessionStorage.setItem(
      'osint-operator-session',
      JSON.stringify({ username: 'operator', role: 'operator', displayName: 'Operator' }),
    );

    renderWithProviders(<App />);

    expect(screen.getByRole('link', { name: /overview/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /targets/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /runs/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /workspace/i })).toBeInTheDocument();
  });

  it('keeps the legacy API key in session storage for compatibility', () => {
    window.sessionStorage.setItem('osint-operator-api-key', 'legacy-key');

    renderWithProviders(<App />);

    expect(window.sessionStorage.getItem('osint-operator-api-key')).toBe('legacy-key');
  });

  it('blocks viewer access to protected routes', () => {
    window.sessionStorage.setItem(
      'osint-operator-session',
      JSON.stringify({ username: 'viewer', role: 'viewer', displayName: 'Viewer' }),
    );

    renderWithProviders(<App />, ['/targets']);

    expect(screen.getByRole('heading', { name: /osint orchestrator/i })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /targets/i })).not.toBeInTheDocument();
  });

  it('renders the run workspace navigation path for a run detail route', () => {
    window.sessionStorage.setItem(
      'osint-operator-session',
      JSON.stringify({ username: 'operator', role: 'operator', displayName: 'Operator' }),
    );

    renderWithProviders(<App />, ['/runs/run-42']);

    expect(screen.getByRole('heading', { name: /run detail/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /report/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /finding/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /evidence/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /manifest/i })).toBeInTheDocument();
  });

  it('renders the target workspace route with run context', () => {
    window.sessionStorage.setItem(
      'osint-operator-session',
      JSON.stringify({ username: 'operator', role: 'operator', displayName: 'Operator' }),
    );

    renderWithProviders(<App />, ['/targets/target-7']);

    expect(screen.getByRole('heading', { name: /target-7/i })).toBeInTheDocument();
    expect(screen.getByText(/review the active investigation context/i)).toBeInTheDocument();
  });

  it('renders the global error boundary fallback for broken children', () => {
    const BrokenComponent = () => {
      throw new Error('Boom');
    };

    renderWithProviders(
      <AppErrorBoundary fallback={<div role="alert">Oops</div>}>
        <BrokenComponent />
      </AppErrorBoundary>,
    );

    expect(screen.getByRole('alert')).toHaveTextContent(/oops/i);
  });

  it('renders the not found route within the shell', () => {
    renderWithProviders(
      <Routes>
        <Route path="/" element={<div>home</div>} />
        <Route path="*" element={<div>Page not found</div>} />
      </Routes>,
      ['/missing'],
    );

    expect(screen.getByText(/page not found/i)).toBeInTheDocument();
  });
});
