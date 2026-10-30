import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';
import App from './App';
import { ApiKeyProvider } from './auth';
import { LocaleProvider } from './i18n';
import { APP_ROUTES } from './routes';
import { sampleHealth, sampleRuns, sampleTargets } from './test/mockApi';

const respond = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const actor = { id: 1, username: 'test-user', display_name: 'Test Accountant', role: 'accountant', active: true };

/**
 * Personal mode: the only mode in which every navigation entry renders, because
 * `/cases` and `/account` are personal-only. Rendering the rail without it
 * would leave the two conditional entries untested, which is exactly how they
 * shipped without icons.
 */
function renderRail({ personal }: { personal: boolean }) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input), 'http://test.local');
      if (url.pathname === '/auth/status') return respond({ personal_access: personal });
      if (url.pathname === '/auth/me') return personal ? respond(actor) : respond({}, 401);
      if (url.pathname === '/health') return respond(sampleHealth);
      if (url.pathname === '/targets') return respond(sampleTargets);
      if (url.pathname === '/runs') return respond(sampleRuns);
      if (url.pathname === '/risk-trends') return respond([]);
      return respond({}, 404);
    }),
  );
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
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
  return screen.findByRole('navigation', { name: /main navigation/i });
}

describe('navigation rail', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('gives every link a glyph, so the icon column is continuous', async () => {
    const rail = await renderRail({ personal: true });

    const links = [...rail.querySelectorAll('a')];
    expect(links).toHaveLength(6);
    // Law of Similarity and Law of Uniform Connectedness: six links that are the
    // same kind of thing must look like it. Two of them rendered an empty
    // `.rail-icon` while the other four carried an SVG, so their labels started
    // 17px left of the rest and the rail read as two groups.
    const withoutGlyph = links.filter((link) => !link.querySelector('.rail-icon svg')).map((link) => link.getAttribute('href'));
    expect(withoutGlyph, `rail entries with no icon: ${withoutGlyph.join(', ')}`).toEqual([]);
  });

  it('leads with the landing route and closes with the personal ones', async () => {
    const rail = await renderRail({ personal: true });

    // Serial Position Effect: the first and last slots are the ones an operator
    // remembers. `/cases` used to occupy the first slot, pushing the landing
    // route to second place, against the order of the route map in
    // ui/docs/routes.md. The labels are the English catalogue's.
    const order = [...rail.querySelectorAll('a')].map((link) => link.textContent);
    expect(order).toEqual(['Overview', 'Targets', 'Runs', 'Alerts', 'Dossiers', 'My account']);
  });

  it('matches the route map in ui/docs/routes.md, in order', async () => {
    // The document is what a contributor reads before adding a route, so the
    // two must not drift. Parsing it here rather than restating the paths is
    // the point: a check that compared APP_ROUTES with itself could not fail.
    const [docPath, doc] = Object.entries(
      import.meta.glob('../docs/routes.md', { query: '?raw', import: 'default', eager: true }) as Record<string, string>,
    )[0];
    expect(doc, `cannot read the route map at ${docPath}`).toBeTypeOf('string');

    const documented = doc
      .split('\n')
      .filter((line) => line.startsWith('| `'))
      .map((line) => line.split('|').map((cell) => cell.trim()))
      // ['', path, view, navigation, notes, '']
      .map(([, path, , navigation]) => ({
        path: path.replace(/`/g, ''),
        inNav: navigation !== 'No',
        personalOnly: navigation === 'Personal accounts',
      }))
      .filter((row) => row.inNav);

    const declared = APP_ROUTES.filter((route) => route.showInNav).map((route) => ({
      path: route.path,
      personalOnly: Boolean(route.personalOnly),
    }));
    expect(declared).toEqual(documented.map(({ path, personalOnly }) => ({ path, personalOnly })));

    const rail = await renderRail({ personal: true });
    expect([...rail.querySelectorAll('a')].map((link) => link.getAttribute('href'))).toEqual(
      documented.map((row) => row.path),
    );
  });

  it('hides the personal destinations without a personal account', async () => {
    const rail = await renderRail({ personal: false });

    const rendered = [...rail.querySelectorAll('a')].map((link) => link.getAttribute('href'));
    expect(rendered).toEqual(['/', '/targets', '/runs', '/alerts']);
  });
});
