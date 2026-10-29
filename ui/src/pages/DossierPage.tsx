import { useQuery } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useApiKey } from '../auth';
import { ErrorState, LoadingState, PageLayout } from '../components/PageState';
import { StageSummary } from '../components/StageSummary';
import { useLocale, type MessageKey } from '../i18n';
import { api, ApiError, downloadDossierPdf } from '../lib/api';
import { formatDateTime } from '../lib/format';
import { CaseForm } from './DossiersPage';
import type { EvidenceRow } from '../types';

function isHttpUrl(value: string) {
  try { return ['http:', 'https:'].includes(new URL(value).protocol); } catch { return false; }
}

function EvidenceDecision({ item, current, submit, disabled }: { item: EvidenceRow; current?: { decision: string; reason: string }; submit: (decision: string, reason: string) => Promise<void>; disabled: boolean }) {
  const { t } = useLocale();
  const [decision, setDecision] = useState(current?.decision ?? 'confirmed');
  const [reason, setReason] = useState(current?.reason ?? '');
  return <form className="state-card case-form" onSubmit={(e) => { e.preventDefault(); void submit(decision, reason); }}>
    <h3>{item.title}</h3>
    {isHttpUrl(item.url) ? <a href={item.url} target="_blank" rel="noopener noreferrer">{item.url}</a> : <p>{item.url}</p>}
    <p>{t('cases.automated')}: {item.rationale}</p>
    <label>{t('cases.decision')}<select disabled={disabled} value={decision} onChange={(e) => setDecision(e.target.value)}><option value="confirmed">{t('cases.confirmed')}</option><option value="dismissed">{t('cases.dismissed')}</option></select></label>
    <label>{t('cases.reason')}<textarea required minLength={10} maxLength={2000} disabled={disabled} value={reason} onChange={(e) => setReason(e.target.value)} /></label>
    {current ? <p>{t('cases.reviewed')}</p> : <p>{t('cases.pending')}</p>}
    <button type="submit" disabled={disabled}>{t('cases.saveDecision')}</button>
  </form>;
}

export function DossierPage() {
  const { caseId = '' } = useParams();
  const { t, tv, locale } = useLocale();
  const { user } = useApiKey();
  const query = useQuery({ queryKey: ['case', caseId], queryFn: () => api.getCase(caseId), enabled: !!user });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [runId, setRunId] = useState('');
  const [conclusion, setConclusion] = useState('');
  const [risk, setRisk] = useState('unknown');
  const [ack, setAck] = useState(false);
  const [reopenReason, setReopenReason] = useState('');
  const act = async (operation: () => Promise<unknown>) => {
    setBusy(true); setError('');
    try { await operation(); await query.refetch(); }
    catch (e) { setError(e instanceof ApiError ? e.message : t('cases.failed')); if (e instanceof ApiError && e.status === 409) await query.refetch(); }
    finally { setBusy(false); }
  };
  if (!user) return <ErrorState description={t('personal.required')} />;
  if (query.isLoading) return <LoadingState message={t('cases.loading')} />;
  if (!query.data || query.error) return <ErrorState description={t('cases.failed')} />;
  const data = query.data;
  const dossier = data.case;
  const finalized = dossier.state === 'finalized';
  const canReview = user.role === 'accountant';
  const submitFinal = (e: FormEvent) => { e.preventDefault(); if (ack) void act(() => api.finalizeCase(caseId, dossier.revision, risk, conclusion)); };
  const eventKeys: Record<string, MessageKey> = { created: 'cases.created', source_attached: 'cases.attached', evidence_reviewed: 'cases.reviewEvent', finalized: 'cases.finalized', reopened: 'cases.reopened' };
  return <PageLayout title={dossier.title} subtitle={`${dossier.entity_name} · ${dossier.identifier} · ${dossier.country}`} actions={<Link to="/cases">{t('back')}</Link>}>
    <p>{dossier.purpose}</p><p>{finalized ? t('cases.finalized') : t('cases.in_review')}</p>
    {error ? <p className="state-card error" role="alert">{error}</p> : null}
    {!finalized ? <details><summary>{t('cases.save')}</summary><CaseForm key={dossier.revision} initial={dossier} busy={busy} submit={async (body) => { await act(() => api.updateCase(caseId, dossier.revision, body)); }} /></details> : null}
    <h2>{t('cases.sources')}</h2>
    {data.runs.map((run) => <div key={run.id}><Link to={`/runs/${run.id}`}>#{run.id} · {run.target_id}</Link><StageSummary run={run} /></div>)}
    {!finalized ? <form className="state-card case-form" onSubmit={(e) => { e.preventDefault(); void act(() => api.attachSource(caseId, dossier.revision, Number(runId))); }}>
      <Link to="/runs">{t('cases.findRun')}</Link>
      <label>{t('cases.runNumber')}<input type="number" min="1" required value={runId} onChange={(e) => setRunId(e.target.value)} /></label>
      <button type="submit" disabled={busy}>{t('cases.attach')}</button>
    </form> : null}
    <h2>{t('cases.evidence')}</h2>
    <p>{t('cases.identityCheck')}</p>
    {data.evidence.length === 0 ? <p>{t('cases.noEvidence')}</p> : null}
    {data.evidence.map((item) => <EvidenceDecision key={item.id} item={item} current={data.reviews.find((r) => r.evidence_id === item.id)} disabled={busy || finalized || !canReview} submit={(decision, reason) => act(() => api.reviewEvidence(caseId, dossier.revision, item.id!, decision, reason))} />)}
    {!canReview ? <p>{t('cases.professionalOnly')}</p> : null}
    {!finalized && canReview ? <form className="state-card case-form" onSubmit={submitFinal}>
      <h2>{t('cases.conclusion')}</h2>
      <label>{t('cases.risk')}<select value={risk} onChange={(e) => setRisk(e.target.value)}>{['unknown', 'low', 'medium', 'high', 'critical'].map((r) => <option key={r} value={r}>{tv(r)}</option>)}</select></label>
      <label>{t('cases.conclusion')}<textarea required minLength={20} maxLength={8000} value={conclusion} onChange={(e) => setConclusion(e.target.value)} /></label>
      <label><input type="checkbox" required checked={ack} onChange={(e) => setAck(e.target.checked)} />{t('cases.limits')}</label>
      <p>{t('cases.finalCheck')}</p><button type="submit" disabled={busy || !ack}>{t('cases.issue')}</button>
    </form> : null}
    <h2>{t('cases.versions')}</h2>
    {data.reports.map((report) => <p key={report.version}>{t('cases.version', { version: report.version })} · {formatDateTime(report.created_at, locale)} <button type="button" disabled={busy} onClick={() => void act(() => downloadDossierPdf(caseId, report.version))}>{t('cases.download')}</button></p>)}
    {finalized && canReview ? <form className="state-card case-form" onSubmit={(e) => { e.preventDefault(); void act(() => api.reopenCase(caseId, dossier.revision, reopenReason)); }}>
      <label>{t('cases.reopenReason')}<textarea required minLength={10} maxLength={2000} value={reopenReason} onChange={(e) => setReopenReason(e.target.value)} /></label><button type="submit" disabled={busy}>{t('cases.reopen')}</button>
    </form> : null}
    <h2>{t('cases.history')}</h2>
    <ol>{data.events.map((event) => <li key={event.id}>{formatDateTime(event.created_at, locale)} · {event.actor_name} · {t(eventKeys[event.action] ?? 'cases.updated')}{typeof event.details.reason === 'string' ? <p>{event.details.reason}</p> : null}</li>)}</ol>
  </PageLayout>;
}
