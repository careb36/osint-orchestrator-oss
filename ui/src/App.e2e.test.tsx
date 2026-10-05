import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import App from './App';
import { ApiKeyProvider } from './auth';
import { LocaleProvider } from './i18n';
import { installFetchMock } from './test/mockApi';

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
        <LocaleProvider initialLocale="en">
          <ApiKeyProvider>
            <App />
          </ApiKeyProvider>
        </LocaleProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
};

describe('operator smoke flow', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('walks from the overview to a target, its runs and a run detail', async () => {
    installFetchMock();
    const user = userEvent.setup();
    renderApp();

    await screen.findByRole('heading', { name: /^overview$/i });
    const nav = screen.getByRole('navigation', { name: /main navigation/i });

    await user.click(within(nav).getByRole('link', { name: /targets/i }));
    expect(await screen.findByRole('heading', { name: /^targets$/i })).toBeInTheDocument();

    await user.click(await screen.findByRole('link', { name: 'example.com' }));
    expect(await screen.findByRole('heading', { name: 'example.com' })).toBeInTheDocument();

    await user.click(within(nav).getByRole('link', { name: /runs/i }));
    expect(await screen.findByRole('heading', { name: /^runs$/i })).toBeInTheDocument();

    await user.click(await screen.findByRole('link', { name: /#42/ }));
    expect(await screen.findByRole('heading', { name: /run #42/i })).toBeInTheDocument();
  });
});
