import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import App from './App';
import { ApiKeyProvider } from './auth';
import { LOCALE_STORAGE_KEY, LocaleProvider, type Locale } from './i18n';
import { API_KEY_STORAGE_KEY } from './lib/api';
import { uiTelemetry } from './lib/telemetry';
import { installFetchMock, sampleHealth, sampleRuns } from './test/mockApi';

// The assertions below read the English catalogue; Spanish is the default
// for operators and has its own tests at the end of this file.
const newQueryClient = () =>
  new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

const renderApp = (initialEntries = ['/'], locale: Locale = 'en', queryClient = newQueryClient()) => {
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={initialEntries}>
        <LocaleProvider initialLocale={locale}>
          <ApiKeyProvider>
            <App />
          </ApiKeyProvider>
        </LocaleProvider>
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

  it('shows a switched-off OpenCTI sink as disabled, not as a fault', async () => {
    installFetchMock();
    renderApp();

    await screen.findByRole('heading', { name: /^overview$/i });
    const card = (await screen.findByText('opencti')).closest('article');
    expect(card).toHaveAttribute('data-status', 'disabled');
    expect(card).toHaveClass('muted');
    expect(card).not.toHaveClass('warning');
    expect(within(card as HTMLElement).getByText(/^disabled$/i)).toBeInTheDocument();
  });

  it('lets an operator acknowledge and resolve an alert case once named', async () => {
    installFetchMock();
    const user = userEvent.setup();
    renderApp(['/alerts']);

    expect(await screen.findByRole('heading', { name: /^alerts$/i })).toBeInTheDocument();
    // Default filter: open cases only; #8 is acknowledged and hidden.
    const table = await screen.findByRole('table');
    expect(within(table).getByText('#7')).toBeInTheDocument();
    expect(within(table).queryByText('#8')).not.toBeInTheDocument();

    const acknowledge = within(table).getByRole('button', { name: /acknowledge/i });
    expect(acknowledge).toBeDisabled(); // no name yet
    await user.type(screen.getByRole('textbox', { name: /your name/i }), 'Rebeca');
    expect(acknowledge).toBeEnabled();
    await user.click(acknowledge);

    // The acknowledged case leaves the open list (now empty); the all-states view shows it handled.
    expect(await screen.findByRole('heading', { name: /no alert cases/i })).toBeInTheDocument();
    await user.selectOptions(screen.getByRole('combobox', { name: /state/i }), 'all');
    const row = (await screen.findByText('#7')).closest('tr') as HTMLElement;
    expect(row).toHaveAttribute('data-state', 'acknowledged');
    expect(within(row).getByText(/by tester/i)).toBeInTheDocument();

    await user.click(within(row).getByRole('button', { name: /resolve/i }));
    await waitFor(() => expect((screen.getByText('#7').closest('tr') as HTMLElement).dataset.state).toBe('resolved'));
    expect(within(screen.getByText('#7').closest('tr') as HTMLElement).queryByRole('button')).not.toBeInTheDocument();
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

  it('describes a request without any answer in prose, never as a raw token', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch');
      }),
    );
    renderApp(['/'], 'es');

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/no obtuvo respuesta/i);
    expect(alert.textContent).not.toMatch(/network/i);
  });

  it('records the operator language in the first telemetry event', async () => {
    installFetchMock();
    uiTelemetry.length = 0;
    renderApp(['/'], 'es');
    await screen.findByRole('heading', { name: /cifras clave/i });
    const loaded = uiTelemetry.find((entry) => entry.event === 'app_loaded');
    expect(loaded?.language).toBe('es');
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

  it('renders the overview with KPIs, targets by attention and recent findings', async () => {
    installFetchMock();
    renderApp();

    const kpis = within((await screen.findByRole('heading', { name: /key figures/i })).closest('section') as HTMLElement);
    // KPI cards computed from the mocked runs, targets and trends.
    const figure = (term: RegExp) => kpis.getByText(term, { selector: 'dt' }).nextElementSibling;
    expect(figure(/^active runs/i)).toHaveTextContent('0');
    expect(figure(/^success rate/i)).toHaveTextContent('50%');
    expect(figure(/^median run time/i)).toHaveTextContent('2.5 min');
    expect(figure(/^targets at risk/i)).toHaveTextContent('1');

    // example-corp has a high latest risk, so it leads the attention table.
    const rows = within(screen.getAllByRole('table')[0]).getAllByRole('row').slice(1);
    expect(rows[0]).toHaveTextContent('example.com');
    expect(rows[0]).toHaveTextContent('high');
    expect(rows[1]).toHaveTextContent('paused.example');

    // The disabled target cannot be started from the overview.
    expect(screen.getByRole('button', { name: /start run for paused-target/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /start run for example-corp/i })).toBeEnabled();

    // The finding of run 42 is listed; run 43 has none (404) and is skipped.
    expect(await screen.findByText(/outdated login portal/i)).toBeInTheDocument();
    expect(screen.getByText(/2 new since last run/i)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /nothing running/i })).toBeInTheDocument();
  });

  it('translates a rejected run by its status and keeps the server detail', async () => {
    installFetchMock({
      routes: [{ pattern: /^\/targets\/example-corp\/run$/, status: 409, body: { detail: 'Ya hay una corrida en curso para example-corp' } }],
    });
    const user = userEvent.setup();
    renderApp(['/targets']);

    await screen.findByRole('table');
    await user.click(screen.getByRole('button', { name: /start run for example-corp/i }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/a run is already in progress/i);
    expect(alert).toHaveTextContent(/server detail: ya hay una corrida en curso/i);
  });

  it('falls back to a generic sentence with the code for a status outside the map', async () => {
    installFetchMock({
      routes: [{ pattern: /^\/targets\/example-corp\/run$/, status: 429, body: { detail: 'Too many runs' } }],
    });
    const user = userEvent.setup();
    renderApp(['/targets']);

    await screen.findByRole('table');
    await user.click(screen.getByRole('button', { name: /start run for example-corp/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/could not be started \(status 429\)/i);
  });

  it('starts a run from the overview and reports the accepted run', async () => {
    const fetchMock = installFetchMock({
      routes: [{ pattern: /^\/targets\/example-corp\/run$/, body: { run_id: 99, status: 'pending', target_id: 'example-corp' } }],
    });
    const user = userEvent.setup();
    renderApp();

    await screen.findByRole('heading', { name: /key figures/i });
    await user.click(screen.getByRole('button', { name: /start run for example-corp/i }));

    expect(await screen.findByRole('status')).toHaveTextContent(/run #99 accepted for example-corp/i);
    const post = fetchMock.mock.calls.find(([, init]) => (init as RequestInit | undefined)?.method === 'POST');
    expect(String(post?.[0])).toMatch(/\/targets\/example-corp\/run$/);
    expect(new Headers((post?.[1] as RequestInit).headers).get('Accept-Language')).toBe('en');
  });

  it('shows empty states on the overview when nothing has run yet', async () => {
    installFetchMock({
      routes: [
        { pattern: /^\/runs(\?.*)?$/, body: [] },
        { pattern: /^\/analytics\/risk-trends$/, body: [] },
      ],
    });
    renderApp();

    const kpis = within((await screen.findByRole('heading', { name: /key figures/i })).closest('section') as HTMLElement);
    expect(kpis.getByText(/^success rate/i, { selector: 'dt' }).nextElementSibling).toHaveTextContent('—');
    expect(screen.getByRole('heading', { name: /nothing running/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /^no runs yet$/i })).toBeInTheDocument();
    expect(screen.getAllByText(/never/i).length).toBeGreaterThan(0);
  });

  it('does not claim "no runs yet" when the run history failed to load', async () => {
    installFetchMock({ routes: [{ pattern: /^\/runs(\?.*)?$/, status: 500, body: { detail: 'db locked' } }] });
    renderApp();

    await screen.findByRole('heading', { name: /key figures/i });
    expect(screen.getAllByText(/run history is unavailable/i).length).toBeGreaterThan(0);
    expect(screen.queryByRole('heading', { name: /^no runs yet$/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /nothing running/i })).not.toBeInTheDocument();
  });

  it('searches, filters and sorts targets and keeps the state in the URL', async () => {
    installFetchMock();
    const user = userEvent.setup();
    renderApp(['/targets']);

    await screen.findByRole('table');
    const rowsOf = () => within(screen.getByRole('table')).getAllByRole('row').slice(1);
    expect(rowsOf()).toHaveLength(2);
    expect(screen.getByRole('status')).toHaveTextContent('2 of 2');

    // Search narrows by collector name.
    await user.type(screen.getByRole('searchbox', { name: /search/i }), 'spiderfoot');
    expect(rowsOf()).toHaveLength(1);
    expect(rowsOf()[0]).toHaveTextContent('example.com');
    expect(screen.getByRole('status')).toHaveTextContent('1 of 2');
    expect(screen.getByRole('button', { name: /clear filters/i })).toBeInTheDocument();

    // Clearing restores the full table.
    await user.click(screen.getByRole('button', { name: /clear filters/i }));
    expect(rowsOf()).toHaveLength(2);

    // A filter with no match shows the empty state with a way out.
    await user.selectOptions(screen.getByRole('combobox', { name: /last run/i }), 'never');
    expect(screen.getByRole('heading', { name: /no targets match/i })).toBeInTheDocument();
    // Both the toolbar and the empty state offer the way out.
    await user.click(screen.getAllByRole('button', { name: /clear filters/i })[0]);

    // Sorting by target name flips on a second click; aria-sort follows.
    const targetHeader = screen.getByRole('columnheader', { name: /^target/i });
    await user.click(within(targetHeader).getByRole('button'));
    expect(targetHeader).toHaveAttribute('aria-sort', 'ascending');
    expect(rowsOf()[0]).toHaveTextContent('example.com');
    await user.click(within(targetHeader).getByRole('button'));
    expect(targetHeader).toHaveAttribute('aria-sort', 'descending');
    expect(rowsOf()[0]).toHaveTextContent('paused.example');
  });

  it('restores target filters from the URL query string', async () => {
    installFetchMock();
    renderApp(['/targets?enabled=disabled&sort=target:desc']);

    const rows = within(await screen.findByRole('table')).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent('paused.example');
    expect(screen.getByRole('combobox', { name: /enabled/i })).toHaveValue('disabled');
    expect(screen.getByRole('columnheader', { name: /^target/i })).toHaveAttribute('aria-sort', 'descending');
  });

  it('degrades an unknown filter value in the URL to the plain view', async () => {
    installFetchMock();
    renderApp(['/targets?enabled=sometimes&status=exploded&sort=bogus:desc']);

    const rows = within(await screen.findByRole('table')).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(2);
    expect(screen.getByRole('combobox', { name: /enabled/i })).toHaveValue('all');
    expect(screen.getByRole('combobox', { name: /last run/i })).toHaveValue('');
    expect(screen.queryByRole('button', { name: /clear filters/i })).not.toBeInTheDocument();
    // The unknown sort column is dropped with its direction: default attention
    // order (the high-risk target first), and no header claims a sort.
    expect(rows[0]).toHaveTextContent('example.com');
    for (const header of screen.getAllByRole('columnheader')) {
      expect(header.getAttribute('aria-sort') ?? 'none').toBe('none');
    }
  });

  it('treats an unknown time window on the runs view as no window', async () => {
    installFetchMock();
    renderApp(['/runs?since=7days']);

    const rows = within(await screen.findByRole('table')).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(2);
    expect(screen.getByRole('combobox', { name: /started/i })).toHaveValue('');
  });

  it('searches runs by error text and filters them by status', async () => {
    installFetchMock();
    const user = userEvent.setup();
    renderApp(['/runs']);

    await screen.findByRole('table');
    const rowsOf = () => within(screen.getByRole('table')).getAllByRole('row').slice(1);
    expect(rowsOf()).toHaveLength(2);

    await user.type(screen.getByRole('searchbox', { name: /search/i }), 'timeout');
    expect(rowsOf()).toHaveLength(1);
    expect(rowsOf()[0]).toHaveTextContent('#43');

    await user.selectOptions(screen.getByRole('combobox', { name: /status/i }), 'success');
    expect(screen.getByRole('heading', { name: /no runs match/i })).toBeInTheDocument();
    await user.click(screen.getAllByRole('button', { name: /clear filters/i })[0]);
    expect(rowsOf()).toHaveLength(2);

    // Default order is newest first; sorting by observables puts run 42 (3) first.
    expect(rowsOf()[0]).toHaveTextContent('#43');
    await user.click(within(screen.getByRole('columnheader', { name: /new observables/i })).getByRole('button'));
    expect(rowsOf()[0]).toHaveTextContent('#42');
  });

  it('filters and sorts the evidence of a run', async () => {
    installFetchMock();
    const user = userEvent.setup();
    renderApp(['/runs/42']);

    await screen.findByRole('heading', { name: /run #42/i });
    await user.click(screen.getByRole('tab', { name: /evidence/i }));
    const table = await within(screen.getByRole('tabpanel')).findByRole('table');
    const rowsOf = () => within(table).getAllByRole('row').slice(1);
    // The fast route that qualified the rows is named once above the table.
    expect(screen.getByTestId('evidence-qualified-by')).toHaveTextContent('Qualified by nebius · test-model');
    // Default: relevance descending.
    expect(rowsOf().map((row) => row.textContent)).toEqual([
      expect.stringContaining('Leaked credential pair'),
      expect.stringContaining('Forum thread'),
      expect.stringContaining('Regional outage'),
    ]);

    await user.selectOptions(screen.getByRole('combobox', { name: /relevance/i }), 'low');
    expect(rowsOf()).toHaveLength(1);
    expect(rowsOf()[0]).toHaveTextContent('Regional outage');
    await user.click(screen.getByRole('button', { name: /clear filters/i }));

    await user.type(screen.getByRole('searchbox', { name: /search/i }), 'portal');
    expect(rowsOf()).toHaveLength(1);
    expect(rowsOf()[0]).toHaveTextContent('Forum thread');

    // The observables tab has its own keys: the evidence term does not leak
    // into it, and its Clear filters button appears only for its own keys.
    await user.click(screen.getByRole('tab', { name: /delta/i }));
    const deltaTable = await within(screen.getByRole('tabpanel')).findByRole('table');
    expect(within(deltaTable).getAllByRole('row').slice(1)).toHaveLength(3);
    expect(screen.getByRole('searchbox', { name: /search/i })).toHaveValue('');
    expect(screen.queryByRole('button', { name: /clear filters/i })).not.toBeInTheDocument();

    // Search and type set together: one click clears both (no lost update).
    await user.type(screen.getByRole('searchbox', { name: /search/i }), 'paste');
    await user.selectOptions(screen.getByRole('combobox', { name: /type/i }), 'url');
    expect(within(deltaTable).getAllByRole('row').slice(1)).toHaveLength(1);
    await user.click(screen.getByRole('button', { name: /clear filters/i }));
    expect(within(deltaTable).getAllByRole('row').slice(1)).toHaveLength(3);
    expect(screen.getByRole('searchbox', { name: /search/i })).toHaveValue('');
    expect(screen.getByRole('combobox', { name: /type/i })).toHaveValue('');

    // Back on Evidence its own term is still there and its own button clears only its keys.
    await user.click(screen.getByRole('tab', { name: /evidence/i }));
    expect(screen.getByRole('searchbox', { name: /search/i })).toHaveValue('portal');
    await user.click(screen.getByRole('button', { name: /clear filters/i }));
    expect(screen.getByRole('searchbox', { name: /search/i })).toHaveValue('');
    expect(screen.queryByRole('button', { name: /clear filters/i })).not.toBeInTheDocument();
  });

  it('shows the risk trend and a start-run action on the target detail', async () => {
    installFetchMock();
    renderApp(['/targets/example-corp']);

    await screen.findByRole('heading', { name: 'example.com' });
    expect(screen.getByText(/peak high over 1 run$/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /start run/i })).toBeEnabled();
  });

  it('shows the classification and where the synthesis runs on the target detail', async () => {
    installFetchMock();
    renderApp(['/targets/example-corp']);

    await screen.findByRole('heading', { name: 'example.com' });
    expect(screen.getByText('restricted')).toBeInTheDocument();
    expect(screen.getByText(/local model only, never the cloud/i)).toBeInTheDocument();
    expect(screen.getByText('Local model (Ollama)')).toBeInTheDocument();
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

  it('shows the risk of each run and what changed since the previous run of the target', async () => {
    const history = [
      { ...sampleRuns[0], id: 40, started_at: '2026-09-29T06:00:00Z', finished_at: '2026-09-29T06:03:00Z', status: 'partial', risk_level: 'medium' },
      { ...sampleRuns[0], id: 41, started_at: '2026-09-30T06:00:00Z', finished_at: '2026-09-30T06:02:00Z', status: 'failed', risk_level: null, error: 'collector timeout' },
      sampleRuns[0], // #42, success, high
    ];
    installFetchMock({ routes: [{ pattern: /^\/runs(\?.*)?$/, body: history }] });
    const user = userEvent.setup();
    renderApp(['/runs']);

    const table = await screen.findByRole('table');
    const rowOf = (id: string) => within(table).getAllByRole('row').find((row) => within(row).queryByRole('link', { name: id }))!;
    expect(rowOf('#40')).toHaveTextContent('first run');
    expect(rowOf('#41')).toHaveTextContent('status partial → failed');
    expect(rowOf('#41')).not.toHaveTextContent(/risk (up|down)/);
    expect(rowOf('#42')).toHaveTextContent('status failed → success');
    expect(rowOf('#42')).toHaveTextContent('risk up medium → high');
    expect(within(rowOf('#42')).getByText('high')).toBeInTheDocument();

    // Sorting by risk puts the run with the highest level first and the ones without a finding last.
    await user.click(within(screen.getByRole('columnheader', { name: /^risk/i })).getByRole('button'));
    const ids = within(table).getAllByRole('row').slice(1).map((row) => within(row).getAllByRole('link')[0].textContent);
    expect(ids).toEqual(['#42', '#40', '#41']);
  });

  it('draws the run history of a target oldest first with risk and change columns', async () => {
    const history = [
      sampleRuns[0],
      { ...sampleRuns[0], id: 41, started_at: '2026-09-30T06:00:00Z', finished_at: '2026-09-30T06:02:00Z', status: 'success', risk_level: 'critical' },
    ];
    installFetchMock({ routes: [{ pattern: /^\/runs\?target_id=example-corp$/, body: history }] });
    renderApp(['/targets/example-corp']);

    await screen.findByRole('heading', { name: 'example.com' });
    const timeline = screen.getByRole('list', { name: /run history, oldest first/i });
    const items = within(timeline).getAllByRole('link');
    expect(items.map((item) => item.getAttribute('aria-label'))).toEqual([
      'Run #41: success, risk critical',
      'Run #42: success, risk high',
    ]);
    expect(items[1]).toHaveAttribute('href', '/targets/example-corp/runs/42');
    const table = screen.getByRole('table');
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows[0]).toHaveTextContent('#42');
    expect(rows[0]).toHaveTextContent('risk down critical → high');
    expect(rows[1]).toHaveTextContent('first run');
  });

  it('verifies the evidence chain from the run detail and shows the outcome', async () => {
    const fetchMock = installFetchMock();
    const user = userEvent.setup();
    renderApp(['/runs/42']);
    await screen.findByRole('heading', { name: /run #42/i });

    await user.click(screen.getByRole('button', { name: /verify evidence chain/i }));
    expect(await screen.findByRole('status')).toHaveTextContent('Chain intact: 1 sealed run verified.');
    const verifyCall = fetchMock.mock.calls.find(([input]) => String(input).includes('/targets/example-corp/chain/verify'));
    expect(verifyCall).toBeDefined();
  });

  it('shows a broken chain as an alert with a link to the first broken run', async () => {
    installFetchMock({
      routes: [
        {
          pattern: /^\/targets\/[^/]+\/chain\/verify$/,
          body: { ok: false, checked: 2, unsealed: 0, first_broken_run_id: 41, reason: 'artefact_hash', detail: 'report.md', anchor_run_id: null, anchor_previous_manifest_sha256: null, message: "Artifact hash mismatch for 'report.md'" },
        },
      ],
    });
    const user = userEvent.setup();
    renderApp(['/runs/42']);
    await screen.findByRole('heading', { name: /run #42/i });

    await user.click(screen.getByRole('button', { name: /verify evidence chain/i }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent("Chain broken at run #41: Artefact hash mismatch for 'report.md'");
    expect(within(alert).getByRole('link', { name: /open run #41/i })).toHaveAttribute('href', '/runs/41');

    // Following the link opens another run: the verdict belongs to the old page and is gone.
    await user.click(within(alert).getByRole('link', { name: /open run #41/i }));
    await waitFor(() => expect(screen.queryByText(/chain broken/i)).not.toBeInTheDocument());
    expect(screen.getByRole('button', { name: /verify evidence chain/i })).toBeEnabled();
  });

  it('exports the signed bundle and the PDF through the API with the key header', async () => {
    window.sessionStorage.setItem(API_KEY_STORAGE_KEY, 'test-key');
    const fetchMock = installFetchMock({ requireKey: 'test-key' });
    const createObjectURL = vi.fn(() => 'blob:run-42');
    const revokeObjectURL = vi.fn();
    Object.defineProperty(URL, 'createObjectURL', { value: createObjectURL, configurable: true });
    Object.defineProperty(URL, 'revokeObjectURL', { value: revokeObjectURL, configurable: true });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    const download = vi.fn();
    const downloadProperty = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'download');
    Object.defineProperty(HTMLAnchorElement.prototype, 'download', { set: download, get: () => '', configurable: true });
    try {
      const user = userEvent.setup();
      renderApp(['/runs/42']);
      await screen.findByRole('heading', { name: /run #42/i });

      await user.click(screen.getByRole('button', { name: /download signed bundle/i }));
      await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
      await user.click(screen.getByRole('button', { name: /download pdf report/i }));
      await waitFor(() => expect(click).toHaveBeenCalledTimes(2));

      // The server names the bundle after the run and the target; the PDF route sends no name, so the fallback applies.
      expect(download.mock.calls.map(([name]) => name)).toEqual(['run-42-example-corp.zip', 'run-42-report.pdf']);
      const paths = fetchMock.mock.calls.map(([input]) => String(input));
      expect(paths).toContain('/runs/42/bundle');
      expect(paths).toContain('/runs/42/report.pdf');
      const bundleCall = fetchMock.mock.calls.find(([input]) => String(input) === '/runs/42/bundle')!;
      expect(new Headers((bundleCall[1] as RequestInit | undefined)?.headers).get('X-API-Key')).toBe('test-key');
      expect(createObjectURL).toHaveBeenCalledTimes(2);
    } finally {
      click.mockRestore();
      if (downloadProperty) Object.defineProperty(HTMLAnchorElement.prototype, 'download', downloadProperty);
    }
  });

  it('shows a run without a finding as a state, not as an error', async () => {
    installFetchMock();
    renderApp(['/runs/43']);
    await screen.findByRole('heading', { name: /run #/i });
    expect(await screen.findByRole('heading', { name: /no synthesis for this run/i })).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('reports an export the API refused', async () => {
    installFetchMock({ routes: [{ pattern: /^\/runs\/\d+\/report\.pdf$/, status: 404, body: { detail: 'Run 42 has no PDF report' } }] });
    const user = userEvent.setup();
    renderApp(['/runs/42']);
    await screen.findByRole('heading', { name: /run #42/i });

    await user.click(screen.getByRole('button', { name: /download pdf report/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The PDF report could not be downloaded.');
  });

  it('copies a handoff summary built from the run, its finding and the verification', async () => {
    installFetchMock();
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    renderApp(['/runs/42']);
    await screen.findByRole('heading', { name: /run #42/i });

    await user.click(screen.getByRole('button', { name: /verify evidence chain/i }));
    await screen.findByText('Chain intact: 1 sealed run verified.');
    await user.click(screen.getByRole('button', { name: /copy handoff summary/i }));
    expect(await screen.findByText('Handoff summary copied to the clipboard.')).toBeInTheDocument();
    expect(writeText).toHaveBeenCalledTimes(1);
    const text = writeText.mock.calls[0][0] as string;
    expect(text).toContain('Target: example-corp');
    expect(text).toContain('Risk level: high');
    expect(text).toContain('Evidence chain: Chain intact: 1 sealed run verified.');
  });

  it('shows the summary for manual copying when the clipboard is unavailable', async () => {
    installFetchMock();
    const user = userEvent.setup();
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
    renderApp(['/runs/42']);
    await screen.findByRole('heading', { name: /run #42/i });

    await user.click(screen.getByRole('button', { name: /copy handoff summary/i }));
    expect(await screen.findByText(/clipboard is not available/i)).toBeInTheDocument();
    const summary = screen.getByRole('textbox', { name: /handoff summary/i }) as HTMLTextAreaElement;
    expect(summary.value).toContain('Target: example-corp');
    expect(summary.value).toContain('Evidence chain: not verified in this session');
  });

  it('starts a follow-up run from the run detail and lists the alerts dispatched', async () => {
    installFetchMock({
      routes: [{ pattern: /^\/targets\/example-corp\/run$/, body: { run_id: 99, status: 'accepted', target_id: 'example-corp' } }],
    });
    const user = userEvent.setup();
    renderApp(['/runs/42']);
    await screen.findByRole('heading', { name: /run #42/i });

    const alerts = screen.getByRole('heading', { name: /alerts dispatched/i }).parentElement!;
    expect(within(alerts).getByRole('table')).toHaveTextContent('webhook');
    expect(within(alerts).getByRole('table')).toHaveTextContent('sent');
    expect(within(alerts).getByRole('table').querySelector('.status-pill')).toHaveTextContent('sent');

    await user.click(screen.getByRole('button', { name: /start follow-up run/i }));
    expect(await screen.findByRole('status')).toHaveTextContent(/run #99/i);
  });

  it('leads from the evidence review to the report', async () => {
    installFetchMock();
    const user = userEvent.setup();
    renderApp(['/runs/42']);
    await screen.findByRole('heading', { name: /run #42/i });

    await user.click(screen.getByRole('tab', { name: /evidence/i }));
    await within(screen.getByRole('tabpanel')).findByRole('table');
    expect(screen.getByRole('link', { name: /prepare handoff/i })).toHaveAttribute('href', '#handoff');
    await user.click(screen.getByRole('button', { name: /continue to the report/i }));
    expect(screen.getByRole('tab', { name: /report/i })).toHaveAttribute('aria-selected', 'true');
  });

  it('renders in Spanish and switches language on demand', async () => {
    installFetchMock();
    const user = userEvent.setup();
    renderApp(['/'], 'es');

    expect(await screen.findByRole('heading', { name: /cifras clave/i })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe('es');
    const nav = screen.getByRole('navigation', { name: /navegación principal/i });
    expect(within(nav).getByRole('link', { name: /objetivos/i })).toBeInTheDocument();
    // Persisted identifiers keep their value in the data and get a Spanish label.
    const highPill = screen.getAllByText('alto')[0];
    expect(highPill).toHaveAttribute('data-value', 'high');

    const switcher = screen.getByRole('group', { name: /idioma/i });
    expect(within(switcher).getByRole('button', { name: 'Español' })).toHaveAttribute('aria-pressed', 'true');
    await user.click(within(switcher).getByRole('button', { name: 'English' }));

    expect(await screen.findByRole('heading', { name: /key figures/i })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe('en');
    expect(window.localStorage.getItem(LOCALE_STORAGE_KEY)).toBe('en');
    expect(within(switcher).getByRole('button', { name: 'English' })).toHaveAttribute('aria-pressed', 'true');
  });

  it('shows the key gate and its errors in Spanish', async () => {
    installFetchMock({ requireKey: 'test-key' });
    const user = userEvent.setup();
    renderApp(['/'], 'es');

    expect(await screen.findByRole('heading', { name: /se requiere la clave de api/i })).toBeInTheDocument();
    await user.type(screen.getByLabelText(/^clave de api$/i), 'wrong-key');
    await user.click(screen.getByRole('button', { name: /usar clave/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/la api rechazó esta clave/i);
  });
});

describe('System status chip', () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    window.localStorage.clear();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('reports a healthy platform', async () => {
    installFetchMock();
    renderApp();
    expect(await within(screen.getByRole('banner')).findByText('System OK')).toBeInTheDocument();
  });

  it('shows offline when the first /health probe fails', async () => {
    installFetchMock({ routes: [{ pattern: /^\/health$/, status: 503, body: { detail: 'down' } }] });
    renderApp();
    expect(await within(screen.getByRole('banner')).findByText('Offline')).toBeInTheDocument();
  });

  it('lets a failed poll win over the last healthy answer', async () => {
    installFetchMock({ routes: [{ pattern: /^\/health$/, status: 503, body: { detail: 'down' } }] });
    const queryClient = newQueryClient();
    // A healthy answer older than staleTime: the mount refetches and fails,
    // and the cached data must not keep the chip green.
    queryClient.setQueryData(['health'], sampleHealth, { updatedAt: Date.now() - 60_000 });
    renderApp(['/'], 'en', queryClient);
    expect(await within(screen.getByRole('banner')).findByText('Offline')).toBeInTheDocument();
  });
});
