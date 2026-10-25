/* eslint-disable react-refresh/only-export-components */
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import type { PersonalUser } from './types';
import { useQueryClient } from '@tanstack/react-query';
import { api, ApiError, clearApiKey, readApiKey, storeApiKey, UNAUTHORIZED_EVENT } from './lib/api';

/**
 * ADR-012 personal sessions with a legacy API-key path for automation/dev.
 * Passwords and session tokens are never persisted by frontend code; the
 * server supplies HttpOnly cookies. Access discovery fails closed on errors.
 * `open` is available only before personal accounts are provisioned.
 */
export type AccessMode = 'checking' | 'open' | 'locked' | 'ready' | 'unavailable';

type ApiKeyContextValue = {
  mode: AccessMode;
  personal: boolean;
  user: PersonalUser | null;
  submitCredentials: (username: string, password: string) => Promise<boolean>;
  hasKey: boolean;
  /** Why the API is `unavailable`: an HTTP status, or no answer at all. */
  unavailableReason: UnavailableReason | null;
  /** Validate the key against the API and store it on success. */
  submitKey: (key: string, remember: boolean) => Promise<SubmitResult>;
  forgetKey: () => void;
  /** Probe the API again (after `unavailable`). */
  retry: () => void;
};

const ApiKeyContext = createContext<ApiKeyContextValue | undefined>(undefined);

/** Machine-readable cause the components translate; never shown as is. */
export type UnavailableReason = { kind: 'status'; status: number } | { kind: 'network' };

type ProbeResult = ({ mode: 'ready' | 'open' | 'locked' } | { mode: 'unavailable'; reason: UnavailableReason }) & { personal?: boolean; user?: PersonalUser };

/** Outcome of submitKey; `reason` is a catalogue-neutral code the gate translates. */
export type SubmitResult =
  | { ok: true }
  | { ok: false; reason: 'empty' }
  | { ok: false; reason: 'rejected' }
  | { ok: false; reason: 'unavailable'; cause: UnavailableReason };

/** Only a 2xx proves the key (or its absence) is accepted; only a 401 proves it is not. */
async function probe(key: string | null): Promise<ProbeResult> {
  try {
    await api.getTargets({ apiKey: key, quiet: true });
    return { mode: key ? 'ready' : 'open' };
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      return { mode: 'locked' };
    }
    const reason: UnavailableReason =
      error instanceof ApiError && error.status ? { kind: 'status', status: error.status } : { kind: 'network' };
    return { mode: 'unavailable', reason };
  }
}

async function discover(key: string | null): Promise<ProbeResult> {
  try {
    if ((await api.getAccess()).personal_access) {
      clearApiKey();
      try { return { mode: 'ready', personal: true, user: await api.getMe() }; }
      catch (error) {
        if (error instanceof ApiError && error.status === 401) return { mode: 'locked', personal: true };
        throw error;
      }
    }
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 404)) {
      return { mode: 'unavailable', reason: error instanceof ApiError && error.status ? { kind: 'status', status: error.status } : { kind: 'network' } };
    }
  }
  return probe(key);
}

export function ApiKeyProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [personal, setPersonal] = useState(false);
  const [user, setUser] = useState<PersonalUser | null>(null);
  const [mode, setMode] = useState<AccessMode>('checking');
  const [hasKey, setHasKey] = useState<boolean>(() => Boolean(readApiKey()));
  const [unavailableReason, setUnavailableReason] = useState<UnavailableReason | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setMode('checking');
    discover(readApiKey()).then((result) => {
      if (cancelled) {
        return;
      }
      if (result.mode === 'locked') {
        clearApiKey();
        setHasKey(false);
      }
      setPersonal(result.personal ?? false);
      setUser(result.user ?? null);
      setUnavailableReason(result.mode === 'unavailable' ? result.reason : null);
      setMode(result.mode);
    });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  useEffect(() => {
    const onUnauthorized = () => {
      clearApiKey();
      setHasKey(false);
      setUser(null);
      setMode('locked');
    };
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  const submitKey = useCallback(async (key: string, remember: boolean): Promise<SubmitResult> => {
    const candidate = key.trim();
    if (!candidate) {
      return { ok: false, reason: 'empty' };
    }
    const result = await probe(candidate);
    if (result.mode === 'locked') {
      return { ok: false, reason: 'rejected' };
    }
    if (result.mode === 'unavailable') {
      return { ok: false, reason: 'unavailable', cause: result.reason };
    }
    storeApiKey(candidate, remember);
    setHasKey(true);
    setMode('ready');
    return { ok: true };
  }, []);

  const submitCredentials = useCallback(async (username: string, password: string) => {
    try {
      const account = await api.login(username, password);
      clearApiKey(); queryClient.clear(); setUser(account); setPersonal(true); setHasKey(false); setMode('ready');
      return true;
    } catch { return false; }
  }, [queryClient]);

  const forgetKey = useCallback(() => {
    const clear = () => { clearApiKey(); setHasKey(false); setUser(null); queryClient.clear(); setMode('locked'); };
    if (personal) void api.logout().then(clear).catch(() => { setMode('unavailable'); setUnavailableReason({ kind: 'network' }); });
    else clear();
  }, [personal, queryClient]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  const value = useMemo(
    () => ({ mode, hasKey, unavailableReason, submitKey, forgetKey, retry, personal, user, submitCredentials }),
    [mode, hasKey, unavailableReason, submitKey, forgetKey, retry, personal, user, submitCredentials],
  );

  return <ApiKeyContext.Provider value={value}>{children}</ApiKeyContext.Provider>;
}

export function useApiKey() {
  const context = useContext(ApiKeyContext);
  if (!context) {
    throw new Error('useApiKey must be used within ApiKeyProvider');
  }
  return context;
}
