import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { AppErrorBoundary } from './components/ErrorBoundary';
import App from './App';

const renderWithProviders = (ui: React.ReactElement) => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
};

describe('App shell', () => {
  it('renders the main navigation and heading', () => {
    renderWithProviders(<App />);

    expect(screen.getByRole('link', { name: /overview/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /targets/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /osint orchestrator/i })).toBeInTheDocument();
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
});
