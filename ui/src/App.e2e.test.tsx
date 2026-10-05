import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App';

const renderApp = () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
};

describe('production smoke flow', () => {
  it('navigates from overview to run history to the workspace view', async () => {
    const user = userEvent.setup();
    renderApp();

    const nav = screen.getByRole('navigation', { name: /main navigation/i });

    expect(screen.getByRole('heading', { name: /osint orchestrator/i })).toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: /workspace/i })).toBeInTheDocument();

    await user.click(within(nav).getByRole('link', { name: /workspace/i }));
    expect(screen.getByText(/run workspace/i)).toBeInTheDocument();

    const runsLink = within(nav).getByRole('link', { name: /runs/i });
    await user.click(runsLink);
    expect(screen.getByRole('heading', { name: /^runs$/i })).toBeInTheDocument();
  });
});
