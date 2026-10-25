import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import App from './App';
import { ApiKeyProvider } from './auth';
import { LocaleProvider } from './i18n';
import { sampleEvidence, sampleHealth, sampleRunDetail } from './test/mockApi';
import type { Dossier, DossierDetail } from './types';

function setup({ authenticated = true, admin = false, path = '/cases/1' } = {}) {
  const actor = { id: 1, username: 'test-user', display_name: 'Test Accountant', role: admin ? 'admin' : 'accountant', active: true };
  let loggedIn = authenticated;
  const dossier: Dossier = { id: 1, title: 'Client review', entity_name: 'Example Company', entity_type: 'company', identifier: 'TEST-1', country: 'Test jurisdiction', purpose: 'Test due diligence', state: 'in_review', revision: 1, owner_id: 1 };
  const detail: DossierDetail = { case: dossier, runs: [{ ...sampleRunDetail, collection_status: 'ok', qualification_status: 'ok', synthesis_status: 'ok', report_status: 'ok', integrity_status: 'ok', evidence_collected: 1, evidence_qualified: 1 }], evidence: [{ ...sampleEvidence[0], id: 1 }], reviews: [], events: [], reports: [] };
  const respond = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://test.local');
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    if (url.pathname === '/auth/status') return respond({ personal_access: true });
    if (url.pathname === '/health') return respond(sampleHealth);
    if (url.pathname === '/auth/me') return loggedIn ? respond(actor) : respond({}, 401);
    if (url.pathname === '/auth/login') { loggedIn = true; return respond(actor); }
    if (url.pathname === '/auth/logout') { loggedIn = false; return respond({ ok: true }); }
    if (!loggedIn) return respond({}, 401);
    if (url.pathname === '/cases/1/reviews') { detail.reviews = [{ ...body, actor_id: 1 }]; detail.case = { ...detail.case, revision: 2 }; return respond({ revision: 2 }); }
    if (url.pathname === '/cases/1/finalize') { detail.case = { ...detail.case, revision: 3, state: 'finalized' }; detail.reports = [{ version: 1, created_at: '2026-10-25T00:00:00Z' }]; return respond({ version: 1 }, 201); }
    if (url.pathname === '/cases/1') {
      if (init?.method === 'POST') { expect(Object.keys(body).sort()).toEqual(['country', 'entity_name', 'entity_type', 'identifier', 'purpose', 'revision', 'title']); return respond({ revision: 2 }); }
      return respond(detail);
    }
    if (url.pathname === '/cases') return respond([dossier]);
    return respond([]);
  });
  vi.stubGlobal('fetch', fetchMock);
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={[path]}><LocaleProvider initialLocale="en"><ApiKeyProvider><App /></ApiKeyProvider></LocaleProvider></MemoryRouter></QueryClientProvider>);
  return { fetchMock, user: userEvent.setup() };
}

beforeEach(() => { window.localStorage.clear(); window.sessionStorage.clear(); });
afterEach(() => vi.unstubAllGlobals());

it('uses personal sign-in without storing passwords or API keys in browser storage', async () => {
  const { user, fetchMock } = setup({ authenticated: false, path: '/cases' });
  await user.type(await screen.findByLabelText('Username'), 'test-user');
  await user.type(screen.getByLabelText('Password'), 'test-user-password');
  await user.click(screen.getByRole('button', { name: 'Sign in' }));
  await screen.findByRole('heading', { name: 'Compliance dossiers' });
  expect(window.localStorage.length).toBeLessThanOrEqual(1); // locale preference only
  expect(window.sessionStorage.length).toBe(0);
  const login = fetchMock.mock.calls.find(([url]) => String(url) === '/auth/login');
  expect(new Headers(login?.[1]?.headers).get('X-Requested-With')).toBe('XMLHttpRequest');
  await user.click(screen.getByRole('button', { name: /sign out/i }));
  expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
});

it('records an evidence decision before issuing a professional report', async () => {
  const { user, fetchMock } = setup();
  await screen.findByRole('heading', { name: 'Client review' });
  await user.selectOptions(screen.getByLabelText('Professional decision'), 'dismissed');
  await user.type(screen.getByLabelText('Reason (at least 10 characters)'), 'Identifier differs: this is a fictitious homonym.');
  await user.click(screen.getByRole('button', { name: 'Record decision' }));
  await screen.findByText('Decision recorded in the history');
  await user.type(screen.getByLabelText('Professional conclusion'), 'Evidence reviewed and the homonym was dismissed with supporting identifiers.');
  await user.selectOptions(screen.getByLabelText('Risk determined by the professional'), 'medium');
  await user.click(screen.getByRole('checkbox'));
  await user.click(screen.getByRole('button', { name: 'Finalize and issue report' }));
  expect(await screen.findByRole('button', { name: 'Download final PDF' })).toBeInTheDocument();
  const finalized = fetchMock.mock.calls.find(([url]) => String(url).endsWith('/finalize'));
  expect(JSON.parse(String(finalized?.[1]?.body))).toMatchObject({ revision: 2, risk_level: 'medium', acknowledge_limitations: true });
});

it('keeps professional approval unavailable to the administrator', async () => {
  setup({ admin: true });
  await screen.findByRole('heading', { name: 'Client review' });
  expect(screen.getByText(/must be recorded by an accountant account/i)).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Finalize and issue report' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Record decision' })).toBeDisabled();
});

it('edits only dossier fields and the expected revision', async () => {
  const { user, fetchMock } = setup();
  await screen.findByRole('heading', { name: 'Client review' });
  await user.click(screen.getByText('Save dossier', { selector: 'summary' }));
  await user.clear(screen.getByLabelText('Legal name / full name'));
  await user.type(screen.getByLabelText('Legal name / full name'), 'Corrected Example Company');
  await user.click(screen.getByRole('button', { name: 'Save dossier' }));
  await waitFor(() => expect(fetchMock.mock.calls.some(([url, options]) => String(url) === '/cases/1' && options?.method === 'POST')).toBe(true));
});
