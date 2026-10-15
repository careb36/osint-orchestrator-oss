import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { MemoryRouter } from 'react-router-dom';
import App from './App';
import { ApiKeyProvider } from './auth';
import { LocaleProvider, type Locale } from './i18n';
import { installFetchMock } from './test/mockApi';

// jsdom has no layout engine, so colour contrast cannot be computed; every
// other WCAG 2.1 A/AA rule axe ships runs here.
const AXE_OPTIONS: axe.RunOptions = {
  runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'] },
  rules: { 'color-contrast': { enabled: false } },
};

const renderApp = (initialEntries: string[], locale: Locale = 'es') => {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
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

async function expectNoViolations() {
  const results = await axe.run(document.body, AXE_OPTIONS);
  const summary = results.violations.map((v) => `${v.id}: ${v.help}\n  ${v.nodes.map((n) => n.target.join(' ')).join('\n  ')}`);
  expect(summary, summary.join('\n')).toEqual([]);
}

describe('accessibility (axe)', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('overview', async () => {
    installFetchMock();
    renderApp(['/']);
    await screen.findByRole('heading', { name: /cifras clave/i });
    await screen.findByText(/outdated login portal/i);
    await expectNoViolations();
  });

  it('targets with filters', async () => {
    installFetchMock();
    renderApp(['/targets?enabled=enabled']);
    await screen.findByRole('table');
    await expectNoViolations();
  });

  it('alerts', async () => {
    installFetchMock();
    renderApp(['/alerts?state=all']);
    await screen.findByRole('table');
    await expectNoViolations();
  });

  it('runs', async () => {
    installFetchMock();
    renderApp(['/runs'], 'en');
    await screen.findByRole('table');
    await expectNoViolations();
  });

  it('target detail', async () => {
    installFetchMock();
    renderApp(['/targets/example-corp']);
    await screen.findByRole('heading', { name: 'example.com' });
    await screen.findByRole('table');
    await expectNoViolations();
  });

  it('run detail with the evidence tab and a verified handoff', async () => {
    installFetchMock();
    const user = userEvent.setup();
    renderApp(['/runs/42']);
    await screen.findByRole('heading', { name: /corrida #42/i });
    await user.click(screen.getByRole('tab', { name: /evidencia/i }));
    await screen.findAllByRole('table');
    await user.click(screen.getByRole('button', { name: /verificar cadena de evidencia/i }));
    await screen.findByText(/cadena intacta/i);
    await expectNoViolations();
  });

  it('API key gate', async () => {
    installFetchMock({ requireKey: 'test-key' });
    renderApp(['/']);
    await screen.findByRole('heading', { name: /se requiere la clave de api/i });
    await expectNoViolations();
  });

  it('not found', async () => {
    installFetchMock();
    renderApp(['/nope']);
    await screen.findByRole('heading', { name: /página no encontrada/i });
    await expectNoViolations();
  });
});
