import { writable } from 'svelte/store';
import { api, setCsrfToken, type SessionInfo } from '$lib/api';
import { cleanProviderAuthError, safeReturnPath } from '$lib/navigation';

export { safeReturnPath } from '$lib/navigation';

interface SessionState {
  initialized: boolean;
  session: SessionInfo | null;
}

function createSessionStore() {
  const { subscribe, set } = writable<SessionState>({ initialized: false, session: null });
  let pending: Promise<SessionInfo | null> | null = null;

  async function initialize(force = false): Promise<SessionInfo | null> {
    if (pending && !force) return pending;
    pending = api.session()
      .then((session) => {
        set({ initialized: true, session });
        return session;
      })
      .catch(() => {
        setCsrfToken('');
        set({ initialized: true, session: null });
        return null;
      })
      .finally(() => { pending = null; });
    return pending;
  }

  return {
    subscribe,
    initialize,
    setSession: (session: SessionInfo) => {
      setCsrfToken(session.csrf_token);
      set({ initialized: true, session });
    },
    clear: () => {
      setCsrfToken('');
      set({ initialized: true, session: null });
    },
  };
}

export const sessionStore = createSessionStore();

export function consumeProviderAuthError(): string {
  if (typeof window === 'undefined') return '';
  const result = cleanProviderAuthError(window.location.href);
  if (!result) return '';
  window.history.replaceState(window.history.state, '', result.cleanPath);
  return result.message;
}
