import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import App from './App';
import { ApiKeyProvider } from './auth';
import { LocaleProvider } from './i18n';
import { uiTelemetry } from './lib/telemetry';
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
    vi.restoreAllMocks();
  });

  it('walks the analyst path from the overview to a run, its evidence, report and manifest without a runtime error', async () => {
    // The DoD asks for no uncaught runtime error on the typical investigation
    // path: anything React or the boundary reports lands in console.error, and
    // every caught UI error lands in the telemetry ring.
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    uiTelemetry.length = 0;
    installFetchMock();
    const user = userEvent.setup();
    renderApp();

    await screen.findByRole('heading', { name: /^overview$/i });
    await screen.findByText(/outdated login portal/i);
    const nav = screen.getByRole('navigation', { name: /main navigation/i });

    await user.click(within(nav).getByRole('link', { name: /targets/i }));
    expect(await screen.findByRole('heading', { name: /^targets$/i })).toBeInTheDocument();

    await user.click(await screen.findByRole('link', { name: 'example.com' }));
    expect(await screen.findByRole('heading', { name: 'example.com' })).toBeInTheDocument();
    await screen.findByRole('table');

    await user.click(within(nav).getByRole('link', { name: /runs/i }));
    expect(await screen.findByRole('heading', { name: /^runs$/i })).toBeInTheDocument();

    await user.click(await screen.findByRole('link', { name: /#42/ }));
    expect(await screen.findByRole('heading', { name: /run #42/i })).toBeInTheDocument();
    await screen.findByText(/leaked credentials/i); // the finding tab

    await user.click(screen.getByRole('tab', { name: /evidence/i }));
    await within(screen.getByRole('tabpanel')).findByRole('table');
    await user.type(screen.getByRole('searchbox', { name: /search/i }), 'portal');
    expect(within(screen.getByRole('tabpanel')).getAllByRole('row')).toHaveLength(2); // header + one match

    await user.click(screen.getByRole('tab', { name: /report/i }));
    expect(await screen.findByText(/two new subdomains/i)).toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: /manifest/i }));
    expect(await screen.findByText(/hmac-sha256:test/)).toBeInTheDocument();

    await user.click(screen.getByRole('link', { name: /^back$/i }));
    expect(await screen.findByRole('heading', { name: 'example.com' })).toBeInTheDocument();

    // Triage: the run's open case is acknowledged from the Alerts view.
    await user.click(within(nav).getByRole('link', { name: /alerts/i }));
    expect(await screen.findByRole('heading', { name: /^alerts$/i })).toBeInTheDocument();
    // The view renders its loading layout under the same heading first; the
    // name field only exists once the alert cases have loaded, so wait for it.
    await user.type(await screen.findByRole('textbox', { name: /your name/i }), 'analyst');
    await user.click(within(await screen.findByRole('table')).getByRole('button', { name: /acknowledge/i }));
    await waitFor(() => expect(screen.queryByText('#7')).not.toBeInTheDocument());

    expect(errors).not.toHaveBeenCalled();
    expect(uiTelemetry.filter((entry) => entry.event === 'ui_error' || entry.event === 'error_boundary_triggered')).toEqual([]);
  });
});
