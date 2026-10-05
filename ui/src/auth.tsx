/* eslint-disable react-refresh/only-export-components */
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, ApiError, clearApiKey, readApiKey, storeApiKey, UNAUTHORIZED_EVENT } from './lib/api';

/**
 * Access to the dashboard follows ADR-005: a static API key, the same one
 * every API client uses. There are no users or roles in the backend, so
 * there are none here either.
 *
 * - `checking`: probing whether the API needs a key.
 * - `open`:     the API answers without a key (ORCHESTRATOR_API_KEY empty).
 * - `locked`:   a key is required and none (or a wrong one) is stored.
 * - `ready`:    the stored key is accepted.
 */
export type AccessMode = 'checking' | 'open' | 'locked' | 'ready';

type ApiKeyContextValue = {
  mode: AccessMode;
  hasKey: boolean;
  /** Validate the key against the API and store it on success. */
  submitKey: (key: string, remember: boolean) => Promise<{ ok: boolean; message?: string }>;
  forgetKey: () => void;
};

const ApiKeyContext = createContext<ApiKeyContextValue | undefined>(undefined);

async function probe(key: string | null): Promise<AccessMode> {
  try {
    await api.getTargets({ apiKey: key, quiet: true });
    return key ? 'ready' : 'open';
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      return 'locked';
    }
    // Backend down or other error: let the pages show it; do not ask for a key.
    return key ? 'ready' : 'open';
  }
}

export function ApiKeyProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<AccessMode>('checking');
  const [hasKey, setHasKey] = useState<boolean>(() => Boolean(readApiKey()));

  useEffect(() => {
    let cancelled = false;
    probe(readApiKey()).then((result) => {
      if (!cancelled) {
        if (result === 'locked') {
          clearApiKey();
          setHasKey(false);
        }
        setMode(result);
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const onUnauthorized = () => {
      clearApiKey();
      setHasKey(false);
      setMode('locked');
    };
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  const submitKey = useCallback(async (key: string, remember: boolean) => {
    const candidate = key.trim();
    if (!candidate) {
      return { ok: false, message: 'Enter the API key.' };
    }
    const result = await probe(candidate);
    if (result === 'locked') {
      return { ok: false, message: 'The API rejected this key.' };
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

  const value = useMemo(
    () => ({ mode, hasKey, submitKey, forgetKey }),
    [mode, hasKey, submitKey, forgetKey],
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
