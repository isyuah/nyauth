import { writable } from 'svelte/store';
import { api, ApiError, setCsrfToken, type Branding, type SessionInfo } from './api';
import { cleanProviderAuthError, safeReturnPath, type ProviderAuthErrorResult } from './navigation';

export { safeReturnPath } from './navigation';

export type SessionFailureStatus = 'network_error' | 'server_error';
export type SessionStatus = 'idle' | 'loading' | 'authenticated' | 'unauthenticated' | SessionFailureStatus;

export class SessionInitializationError extends Error {
  constructor(
    readonly status: SessionFailureStatus,
    message: string,
    readonly originalError: unknown,
  ) {
    super(message);
    this.name = 'SessionInitializationError';
  }
}

export interface SessionState {
  initialized: boolean;
  status: SessionStatus;
  session: SessionInfo | null;
  error: string | null;
}

function sessionInitializationError(error: unknown): SessionInitializationError {
  if (error instanceof SessionInitializationError) return error;
  if (error instanceof ApiError) {
    return new SessionInitializationError(
      'server_error',
      '认证服务暂时无法检查会话，请稍后重试。',
      error,
    );
  }
  return new SessionInitializationError(
    'network_error',
    '无法连接认证服务，请检查网络连接后重试。',
    error,
  );
}

export function createSessionStore() {
  const { subscribe, set, update } = writable<SessionState>({
    initialized: false,
    status: 'idle',
    session: null,
    error: null,
  });
  let currentSession: SessionInfo | null = null;
  let generation = 0;
  let pending: { generation: number; promise: Promise<SessionInfo | null> } | null = null;

  function initialize(force = false): Promise<SessionInfo | null> {
    if (pending && !force) return pending.promise;
    const requestGeneration = ++generation;
    update((current) => ({ ...current, status: 'loading', error: null }));
    const promise = api.session()
      .then((session) => {
        if (requestGeneration !== generation) {
          setCsrfToken(currentSession?.csrf_token);
          return currentSession;
        }
        currentSession = session;
        setCsrfToken(session.csrf_token);
        set({ initialized: true, status: 'authenticated', session, error: null });
        return session;
      })
      .catch((error: unknown) => {
        if (requestGeneration !== generation) {
          setCsrfToken(currentSession?.csrf_token);
          return currentSession;
        }
        currentSession = null;
        setCsrfToken('');
        if (error instanceof ApiError && error.status === 401) {
          set({ initialized: true, status: 'unauthenticated', session: null, error: null });
          return null;
        }
        const failure = sessionInitializationError(error);
        set({ initialized: true, status: failure.status, session: null, error: failure.message });
        throw failure;
      })
      .finally(() => {
        if (pending?.generation === requestGeneration) pending = null;
      });
    pending = { generation: requestGeneration, promise };
    return promise;
  }

  return {
    subscribe,
    initialize,
    setSession: (session: SessionInfo) => {
      generation++;
      pending = null;
      currentSession = session;
      setCsrfToken(session.csrf_token);
      set({ initialized: true, status: 'authenticated', session, error: null });
    },
    clear: () => {
      generation++;
      pending = null;
      currentSession = null;
      setCsrfToken('');
      set({ initialized: true, status: 'unauthenticated', session: null, error: null });
    },
  };
}

export const sessionStore = createSessionStore();

export const DEFAULT_BRANDING: Branding = { title: 'Nya', logo_url: '' };

// Server-configured branding with a static fallback: pages render the default
// immediately and update if the deployment has customized it.
export const brandingStore = writable<Branding>(DEFAULT_BRANDING);

let brandingLoaded = false;
export async function initializeBranding(force = false): Promise<void> {
  if (brandingLoaded && !force) return;
  brandingLoaded = true;
  try {
    const branding = await api.getBranding();
    if (branding?.title) brandingStore.set(branding);
  } catch {
    // Keep the default branding when the endpoint is unavailable.
  }
}

export function consumeProviderAuthError(): ProviderAuthErrorResult | null {
  if (typeof window === 'undefined') return null;
  const result = cleanProviderAuthError(window.location.href);
  if (!result) return null;
  window.history.replaceState(window.history.state, '', result.cleanPath);
  return result;
}
