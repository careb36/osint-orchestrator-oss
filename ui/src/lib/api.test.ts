import { api, ApiError } from './api';
import { currentLocale, setCurrentLocale } from './locale';
import { uiTelemetry } from './telemetry';

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

describe('api.request telemetry', () => {
  beforeEach(() => {
    uiTelemetry.length = 0;
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('does not log an api_error for an expected 404 on an optional artefact', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(404, { detail: 'No finding for this run' })));

    await expect(api.getRunFinding(42, { optional: true })).rejects.toBeInstanceOf(ApiError);
    expect(uiTelemetry.filter((entry) => entry.event === 'api_error')).toHaveLength(0);
  });

  it('still logs an api_error for a 404 that was not expected, and for other statuses', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(404, { detail: 'No finding for this run' })));
    await expect(api.getRunFinding(42)).rejects.toBeInstanceOf(ApiError);

    vi.stubGlobal('fetch', vi.fn(async () => json(500, { detail: 'boom' })));
    await expect(api.getRunFinding(42, { optional: true })).rejects.toMatchObject({ status: 500 });

    expect(uiTelemetry.filter((entry) => entry.event === 'api_error').map((entry) => entry.detail.status)).toEqual([404, 500]);
  });

});

describe('api.request language', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    setCurrentLocale(null);
  });

  it('sends Accept-Language from the resolved locale and omits it before one is chosen', async () => {
    const fetchMock = vi.fn(async () => json(200, []));
    vi.stubGlobal('fetch', fetchMock);

    expect(currentLocale()).toBeNull();
    await api.getTargets();
    expect(new Headers((fetchMock.mock.calls[0][1] as RequestInit).headers).has('Accept-Language')).toBe(false);

    setCurrentLocale('es');
    await api.getTargets();
    expect(new Headers((fetchMock.mock.calls[1][1] as RequestInit).headers).get('Accept-Language')).toBe('es');
  });
});
