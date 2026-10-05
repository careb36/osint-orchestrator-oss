import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { AppErrorBoundary } from './components/ErrorBoundary';
import App from './App';
import { APP_ROUTES } from './routes';

const renderWithProviders = (ui: React.ReactElement, initialEntry = '/') => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialEntry]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
};

describe('App shell', () => {
  it('renders the main navigation and heading', () => {
    renderWithProviders(<App />);

    expect(screen.getByRole('link', { name: /^overview$/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /^targets$/i })).toBeInTheDocument();
    expect(screen.getByText(/osint orchestrator/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /review runs/i })).toBeInTheDocument();
  });

  it('exposes the unified route map for contributors', () => {
    expect(APP_ROUTES.map((route) => route.path)).toEqual(['/', '/targets', '/runs']);
    expect(APP_ROUTES.every((route) => route.label.length > 0)).toBe(true);
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
      '/missing',
    );

    expect(screen.getByText(/page not found/i)).toBeInTheDocument();
  });
});
