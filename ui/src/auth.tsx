/* eslint-disable react-refresh/only-export-components */
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, ApiError, clearApiKey, readApiKey, storeApiKey, UNAUTHORIZED_EVENT } from './lib/api';

/**
 * Access to the dashboard follows ADR-005: a static API key, the same one
 * every API client uses. There are no users or roles in the backend, so
 * there are none here either.
 *
 * - `checking`:    probing whether the API needs a key.
 * - `open`:        the API answers without a key (ORCHESTRATOR_API_KEY empty).
 * - `locked`:      a key is required and none (or a wrong one) is stored.
 * - `ready`:       the stored key is accepted.
 * - `unavailable`: the API did not answer 2xx or 401; nothing can be told
 *                  about the key, so the shell shows the error and a retry.
 */
export type AccessMode = 'checking' | 'open' | 'locked' | 'ready' | 'unavailable';

type ApiKeyContextValue = {
  mode: AccessMode;
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

type ProbeResult = { mode: 'ready' | 'open' | 'locked' } | { mode: 'unavailable'; reason: UnavailableReason };

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

export function ApiKeyProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<AccessMode>('checking');
  const [hasKey, setHasKey] = useState<boolean>(() => Boolean(readApiKey()));
  const [unavailableReason, setUnavailableReason] = useState<UnavailableReason | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setMode('checking');
    probe(readApiKey()).then((result) => {
      if (cancelled) {
        return;
      }
      if (result.mode === 'locked') {
        clearApiKey();
        setHasKey(false);
      }
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

  const forgetKey = useCallback(() => {
    clearApiKey();
    setHasKey(false);
    setMode('locked');
  }, []);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  const value = useMemo(
    () => ({ mode, hasKey, unavailableReason, submitKey, forgetKey, retry }),
    [mode, hasKey, unavailableReason, submitKey, forgetKey, retry],
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
