import { useQuery } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useApiKey } from '../auth';
import { ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { useLocale } from '../i18n';
import { api, ApiError } from '../lib/api';
import type { DossierBody } from '../types';

export function CaseForm({ initial, submit, busy }: { initial?: DossierBody; submit: (data: DossierBody) => Promise<void>; busy: boolean }) {
  const { t } = useLocale();
  const [form, setForm] = useState<DossierBody>(() => ({ title: initial?.title ?? '', entity_name: initial?.entity_name ?? '', entity_type: initial?.entity_type ?? 'company', identifier: initial?.identifier ?? '', country: initial?.country ?? '', purpose: initial?.purpose ?? '' }));
  const fields = ['title', 'entity_name', 'identifier', 'country', 'purpose'] as const;
  const send = (event: FormEvent) => { event.preventDefault(); void submit(form); };
  return <form className="state-card case-form" onSubmit={send}>
    {fields.map((field) => <label key={field}>{t(field === 'title' ? 'cases.titleField' : `cases.${field}`)}<input required={field !== 'identifier'} maxLength={field === 'purpose' ? 2000 : field === 'title' ? 160 : field === 'entity_name' ? 200 : 100} value={form[field]} onChange={(e) => setForm({ ...form, [field]: e.target.value })} /></label>)}
    <label>{t('cases.entity_type')}<select value={form.entity_type} onChange={(e) => setForm({ ...form, entity_type: e.target.value as DossierBody['entity_type'] })}><option value="company">{t('cases.company')}</option><option value="person">{t('cases.person')}</option></select></label>
    <button type="submit" disabled={busy}>{t('cases.save')}</button>
  </form>;
}

export function DossiersPage() {
  const { t } = useLocale();
  const { user } = useApiKey();
  const navigate = useNavigate();
  const [offset, setOffset] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const cases = useQuery({ queryKey: ['cases', offset], queryFn: () => api.getCases(offset), enabled: !!user, refetchInterval: 30_000 });
  const submit = async (body: DossierBody) => {
    setBusy(true); setError('');
    try { const row = await api.createCase(body); navigate(`/cases/${row.id}`); }
    catch (e) { setError(e instanceof ApiError ? e.message : t('cases.failed')); }
    finally { setBusy(false); }
  };
  if (!user) return <ErrorState description={t('personal.required')} />;
  return <PageLayout title={t('cases.title')} subtitle={t('cases.lede')}>
    <h2>{t('cases.new')}</h2><CaseForm submit={submit} busy={busy} />
    {error ? <p role="alert">{error}</p> : null}
    <h2>{t('cases.list')}</h2>
    {cases.isLoading ? <LoadingState message={t('cases.loading')} /> : null}
    {cases.error ? <ErrorState description={t('cases.failed')} /> : null}
    {cases.data?.length === 0 ? <p>{t('cases.empty')}</p> : null}
    <ul>{cases.data?.map((row) => <li key={row.id}><Link to={`/cases/${row.id}`}>{row.title} · {row.entity_name}</Link> · {row.state === 'finalized' ? t('cases.finalized') : t('cases.in_review')}</li>)}</ul>
    <button type="button" disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 100))}>{t('cases.previous')}</button>
    <button type="button" disabled={cases.data?.length !== 100} onClick={() => setOffset(offset + 100)}>{t('cases.next')}</button>
  </PageLayout>;
}
