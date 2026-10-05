import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import App from './App';
import { ApiKeyProvider } from './auth';
import { API_KEY_STORAGE_KEY } from './lib/api';
import { installFetchMock } from './test/mockApi';

const renderApp = (initialEntries = ['/']) => {
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
        <ApiKeyProvider>
          <App />
        </ApiKeyProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
};

describe('App shell', () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    window.localStorage.clear();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('renders the overview without a key when the API is open', async () => {
    installFetchMock();
    renderApp();

    expect(await screen.findByRole('heading', { name: /^overview$/i })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /api key required/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /forget key/i })).not.toBeInTheDocument();
  });

  it('asks for the API key when the API answers 401', async () => {
    installFetchMock({ requireKey: 'test-key' });
    renderApp(['/targets']);

    expect(await screen.findByRole('heading', { name: /api key required/i })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /^targets$/i })).not.toBeInTheDocument();
  });

  it('rejects a wrong key and accepts the right one', async () => {
    installFetchMock({ requireKey: 'test-key' });
    const user = userEvent.setup();
    renderApp(['/targets']);

    const input = await screen.findByLabelText(/^api key$/i);
    await user.type(input, 'wrong-key');
    await user.click(screen.getByRole('button', { name: /use key/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/rejected/i);

    await user.clear(input);
    await user.type(input, 'test-key');
    await user.click(screen.getByRole('button', { name: /use key/i }));

    expect(await screen.findByRole('heading', { name: /^targets$/i })).toBeInTheDocument();
    expect(window.sessionStorage.getItem(API_KEY_STORAGE_KEY)).toBe('test-key');
    expect(window.localStorage.getItem(API_KEY_STORAGE_KEY)).toBeNull();
  });

  it('remembers the key on this browser when asked to', async () => {
    installFetchMock({ requireKey: 'test-key' });
    const user = userEvent.setup();
    renderApp();

    await user.type(await screen.findByLabelText(/^api key$/i), 'test-key');
    await user.click(screen.getByRole('checkbox', { name: /remember/i }));
    await user.click(screen.getByRole('button', { name: /use key/i }));

    await screen.findByRole('heading', { name: /^overview$/i });
    expect(window.localStorage.getItem(API_KEY_STORAGE_KEY)).toBe('test-key');
  });

  it('uses a stored key and sends it on every request', async () => {
    window.sessionStorage.setItem(API_KEY_STORAGE_KEY, 'test-key');
    const fetchMock = installFetchMock({ requireKey: 'test-key' });
    renderApp(['/targets']);

    expect(await screen.findByRole('heading', { name: /^targets$/i })).toBeInTheDocument();
    expect(await screen.findByText('example-corp')).toBeInTheDocument();
    for (const call of fetchMock.mock.calls) {
      const headers = new Headers((call[1] as RequestInit | undefined)?.headers);
      expect(headers.get('X-API-Key')).toBe('test-key');
    }
  });

  it('does not accept a key the API could not validate', async () => {
    installFetchMock({
      requireKey: 'test-key',
      routes: [{ pattern: /^\/targets$/, status: 500, body: { detail: 'boom' } }],
    });
    const user = userEvent.setup();
    renderApp();

    // The 500 route sits behind the key check, so the first probe still sees 401.
    await user.type(await screen.findByLabelText(/^api key$/i), 'test-key');
    await user.click(screen.getByRole('button', { name: /use key/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/could not validate.*status 500/i);
    expect(window.sessionStorage.getItem(API_KEY_STORAGE_KEY)).toBeNull();
  });

  it('shows the API as unavailable, not as open, when it does not answer 2xx or 401', async () => {
    const fetchMock = installFetchMock({
      routes: [{ pattern: /^\/targets$/, status: 503, body: { detail: 'maintenance' } }],
    });
    const user = userEvent.setup();
    renderApp();

    expect(await screen.findByRole('heading', { name: /api unavailable/i })).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent(/status 503/);
    expect(screen.queryByRole('heading', { name: /^overview$/i })).not.toBeInTheDocument();

    // Recovery: the next probe succeeds and the dashboard renders.
    fetchMock.mockImplementation(async () => new Response(JSON.stringify([]), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    await user.click(screen.getByRole('button', { name: /retry/i }));
    expect(await screen.findByRole('heading', { name: /^overview$/i })).toBeInTheDocument();
  });

  it('forgets the key and locks the dashboard again', async () => {
    window.sessionStorage.setItem(API_KEY_STORAGE_KEY, 'test-key');
    installFetchMock({ requireKey: 'test-key' });
    const user = userEvent.setup();
    renderApp();

    await screen.findByRole('heading', { name: /^overview$/i });
    await user.click(screen.getByRole('button', { name: /forget key/i }));

    expect(await screen.findByRole('heading', { name: /api key required/i })).toBeInTheDocument();
    expect(window.sessionStorage.getItem(API_KEY_STORAGE_KEY)).toBeNull();
  });

  it('keeps the remember preference after the key is forgotten', async () => {
    installFetchMock({ requireKey: 'test-key' });
    const user = userEvent.setup();
    renderApp();

    await user.type(await screen.findByLabelText(/^api key$/i), 'test-key');
    await user.click(screen.getByRole('checkbox', { name: /remember/i }));
    await user.click(screen.getByRole('button', { name: /use key/i }));
    await screen.findByRole('heading', { name: /^overview$/i });

    await user.click(screen.getByRole('button', { name: /forget key/i }));
    await screen.findByRole('heading', { name: /api key required/i });
    expect(window.localStorage.getItem(API_KEY_STORAGE_KEY)).toBeNull();
    expect(screen.getByRole('checkbox', { name: /remember/i })).toBeChecked();

    // Submitting without "remember" clears the preference.
    await user.click(screen.getByRole('checkbox', { name: /remember/i }));
    await user.type(screen.getByLabelText(/^api key$/i), 'test-key');
    await user.click(screen.getByRole('button', { name: /use key/i }));
    await screen.findByRole('heading', { name: /^overview$/i });
    await user.click(screen.getByRole('button', { name: /forget key/i }));
    await screen.findByRole('heading', { name: /api key required/i });
    expect(screen.getByRole('checkbox', { name: /remember/i })).not.toBeChecked();
  });

  it('locks when a stored key stops being accepted', async () => {
    window.sessionStorage.setItem(API_KEY_STORAGE_KEY, 'stale-key');
    installFetchMock({ requireKey: 'test-key' });
    renderApp();

    expect(await screen.findByRole('heading', { name: /api key required/i })).toBeInTheDocument();
    await waitFor(() => expect(window.sessionStorage.getItem(API_KEY_STORAGE_KEY)).toBeNull());
  });

  it('shows the three top-level sections in the navigation', async () => {
    installFetchMock();
    renderApp();

    const nav = screen.getByRole('navigation', { name: /main navigation/i });
    expect(within(nav).getByRole('link', { name: /overview/i })).toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: /targets/i })).toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: /runs/i })).toBeInTheDocument();
    expect(within(nav).queryByRole('link', { name: /workspace/i })).not.toBeInTheDocument();
  });

  it('renders the not-found page for unknown routes', async () => {
    installFetchMock();
    renderApp(['/does-not-exist']);

    expect(await screen.findByRole('heading', { name: /page not found/i })).toBeInTheDocument();
  });

  it('renders a run detail with its tabs', async () => {
    installFetchMock();
    renderApp(['/runs/42']);

    expect(await screen.findByRole('heading', { name: /run #42/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /finding/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /report/i })).toBeInTheDocument();
  });
});
