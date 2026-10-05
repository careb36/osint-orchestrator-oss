/* eslint-disable react-refresh/only-export-components */
import { createContext, useContext, useState, type ReactNode } from 'react';

export type AuthRole = 'viewer' | 'operator' | 'admin';

export type AuthSession = {
  username: string;
  role: AuthRole;
  displayName: string;
};

export const DEMO_USERS: Record<string, { password: string; role: AuthRole; displayName: string }> = {
  viewer: { password: 'viewer', role: 'viewer', displayName: 'Viewer' },
  operator: { password: 'operator', role: 'operator', displayName: 'Operator' },
  admin: { password: 'admin', role: 'admin', displayName: 'Administrator' },
};

export const ROUTE_ACCESS: Record<AuthRole, string[]> = {
  viewer: ['/', '/login'],
  operator: ['/', '/targets', '/runs', '/login'],
  admin: ['/', '/targets', '/runs', '/login'],
};

const SESSION_STORAGE_KEY = 'osint-operator-session';
const API_KEY_STORAGE_KEY = 'osint-operator-api-key';

function readSession(): AuthSession | null {
  const raw = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as AuthSession;
    if (!parsed.username || !parsed.role) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function readLegacyApiKey(): string | null {
  return window.sessionStorage.getItem(API_KEY_STORAGE_KEY);
}

export function persistLegacyApiKey(key: string) {
  if (!key.trim()) {
    window.sessionStorage.removeItem(API_KEY_STORAGE_KEY);
    return;
  }

  window.sessionStorage.setItem(API_KEY_STORAGE_KEY, key.trim());
}

export function hasAccess(role: AuthRole, path: string) {
  const normalized = path === '' ? '/' : path;
  return ROUTE_ACCESS[role].includes(normalized);
}

type AuthContextValue = {
  session: AuthSession | null;
  isAuthenticated: boolean;
  signIn: (username: string, password: string) => { ok: boolean; message?: string };
  signOut: () => void;
  legacyApiKey: string | null;
  setLegacyApiKey: (key: string) => void;
  canAccess: (path: string) => boolean;
};

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<AuthSession | null>(() => readSession());
  const [legacyApiKey, setLegacyApiKeyState] = useState<string | null>(() => readLegacyApiKey());

  const signIn = (username: string, password: string) => {
    const account = DEMO_USERS[username.toLowerCase()];
    if (!account || account.password !== password) {
      return { ok: false, message: 'Invalid username or password.' };
    }

    const nextSession = {
      username: username.toLowerCase(),
      role: account.role,
      displayName: account.displayName,
    };

    window.sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(nextSession));
    setSession(nextSession);
    return { ok: true };
  };

  const signOut = () => {
    window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
    setSession(null);
  };

  const setLegacyApiKey = (key: string) => {
    persistLegacyApiKey(key);
    setLegacyApiKeyState(readLegacyApiKey());
  };

  const canAccess = (path: string) => {
    if (!session) {
      return false;
    }
    return hasAccess(session.role, path);
  };

  const value: AuthContextValue = {
    session,
    isAuthenticated: Boolean(session),
    signIn,
    signOut,
    legacyApiKey,
    setLegacyApiKey,
    canAccess,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}

export function getLegacyApiKeyForRequest() {
  return window.sessionStorage.getItem(API_KEY_STORAGE_KEY) ?? undefined;
}

export function clearSessionState() {
  window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
  window.sessionStorage.removeItem(API_KEY_STORAGE_KEY);
}
