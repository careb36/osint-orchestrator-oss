import { useQuery } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useApiKey } from '../auth';
import { ErrorState, PageLayout } from '../components/PageState';
import { useLocale } from '../i18n';
import type { PersonalUser } from '../types';
import { api, ApiError } from '../lib/api';

export function AccountsPage() {
  const { t } = useLocale();
  const { user, forgetKey } = useApiKey();
  const users = useQuery({ queryKey: ['accounts'], queryFn: api.getAccounts, enabled: user?.role === 'admin' });
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [current, setCurrent] = useState('');
  const [replacement, setReplacement] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const act = async (operation: () => Promise<unknown>) => {
    setBusy(true); setError('');
    try { await operation(); setPassword(''); setReplacement(''); await users.refetch(); }
    catch (e) { setError(e instanceof ApiError ? e.message : t('cases.failed')); }
    finally { setBusy(false); }
  };
  const create = (e: FormEvent) => { e.preventDefault(); void act(() => api.createAccount({ username, display_name: displayName, password, role: 'accountant' })); };
  if (!user) return <ErrorState description={t('personal.required')} />;
  return <PageLayout title={t('personal.account')}>
    <p>{user.display_name} · {user.username}</p>
    {error ? <p role="alert">{error}</p> : null}
    <form className="state-card case-form" onSubmit={(e) => { e.preventDefault(); void act(async () => { await api.changePassword(current, replacement); forgetKey(); }); }}>
      <h2>{t('personal.changePassword')}</h2>
      <label>{t('personal.currentPassword')}<input type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} /></label>
      <label>{t('personal.newPassword')}<input type="password" autoComplete="new-password" minLength={12} maxLength={128} required value={replacement} onChange={(e) => setReplacement(e.target.value)} /></label>
      <button type="submit" disabled={busy}>{t('personal.changePassword')}</button>
    </form>
    {user.role === 'admin' ? <>
      <h2>{t('personal.manage')}</h2>
      <form className="state-card case-form" onSubmit={create}>
        <label>{t('personal.username')}<input required minLength={3} maxLength={64} value={username} onChange={(e) => setUsername(e.target.value)} /></label>
        <label>{t('personal.name')}<input required maxLength={80} value={displayName} onChange={(e) => setDisplayName(e.target.value)} /></label>
        <label>{t('personal.newPassword')}<input type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        <button type="submit" disabled={busy}>{t('personal.create')}</button>
      </form>
      {users.error ? <ErrorState description={t('cases.failed')} /> : null}
      <ul>{users.data?.map((row) => <li key={row.id}>{row.display_name} · {row.username} · {row.active ? t('yes') : t('no')}{row.role !== 'admin' ? <button type="button" disabled={busy} onClick={() => void act(() => api.updateAccount(row.id, !row.active))}>{row.active ? t('personal.disable') : t('personal.enable')}</button> : null}</li>)}</ul>
      <p>{t('personal.resetHelp')}</p>{users.data?.filter((row) => row.role !== 'admin').map((row) => <ResetAccount key={row.id} user={row} busy={busy} reset={(password) => act(() => api.updateAccount(row.id, row.active, password))} />)}
    </> : null}
  </PageLayout>;
}

function ResetAccount({ user, busy, reset }: { user: PersonalUser; busy: boolean; reset: (password: string) => Promise<void> }) {
  const { t } = useLocale();
  const [password, setPassword] = useState('');
  return <form className="state-card case-form" onSubmit={(e) => { e.preventDefault(); void reset(password).then(() => setPassword('')); }}>
    <label>{user.display_name} · {t('personal.newPassword')}<input type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={password} onChange={(e) => setPassword(e.target.value)} /></label>
    <button type="submit" disabled={busy}>{t('personal.reset')}</button>
  </form>;
}
