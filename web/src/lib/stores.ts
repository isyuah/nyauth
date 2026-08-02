import { writable } from 'svelte/store';
import { api, ApiError, setCsrfToken, type Branding, type ResolvedTheme, type SessionInfo, type Theme } from './api';
import { cleanProviderAuthError, safeReturnPath, type ProviderAuthErrorResult } from './navigation';
import { applyThemeToDocument, DEFAULT_PRIMARY_COLOR, normalizeHexColor, resolveTheme } from './theme';

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

export const DEFAULT_BRANDING: Branding = {
  title: 'Nya',
  primary_color: DEFAULT_PRIMARY_COLOR,
  primary_text_color: 'auto',
  light_logo_url: '',
  dark_logo_url: '',
  favicon_url: '',
};

// Server-configured branding with a static fallback: pages render the default
// immediately and update if the deployment has customized it.
export const brandingStore = writable<Branding>(DEFAULT_BRANDING);
export const resolvedThemeStore = writable<ResolvedTheme>('light');
const brandingReadyStore = writable(false);

const themeStorageKey = 'nyauth:theme';
const localTheme = writable<Theme>('system');

function normalizeTheme(value: unknown): Theme {
  return value === 'light' || value === 'dark' || value === 'system' ? value : 'system';
}

function readStoredTheme(): Theme {
  if (typeof window === 'undefined') return 'system';
  try {
    return normalizeTheme(window.localStorage.getItem(themeStorageKey));
  } catch {
    return 'system';
  }
}

export const localThemeStore = {
  subscribe: localTheme.subscribe,
  set(value: Theme) {
    const normalized = normalizeTheme(value);
    localTheme.set(normalized);
    if (typeof window !== 'undefined') {
      try {
        window.localStorage.setItem(themeStorageKey, normalized);
      } catch {
        // The current page still applies the preference when storage is unavailable.
      }
    }
  },
};

function normalizeBranding(value: Branding): Branding {
  const primaryTextColor = value.primary_text_color === 'white' || value.primary_text_color === 'black'
    ? value.primary_text_color
    : 'auto';
  return {
    title: typeof value.title === 'string' && value.title.trim() ? value.title : DEFAULT_BRANDING.title,
    primary_color: normalizeHexColor(value.primary_color || '') ?? DEFAULT_PRIMARY_COLOR,
    primary_text_color: primaryTextColor,
    light_logo_url: typeof value.light_logo_url === 'string' ? value.light_logo_url : '',
    dark_logo_url: typeof value.dark_logo_url === 'string' ? value.dark_logo_url : '',
    favicon_url: typeof value.favicon_url === 'string' ? value.favicon_url : '',
  };
}

let brandingLoaded = false;
export async function initializeBranding(force = false): Promise<void> {
  if (brandingLoaded && !force) return;
  brandingLoaded = true;
  try {
    const branding = await api.getBranding();
    brandingStore.set(normalizeBranding(branding));
    brandingReadyStore.set(true);
  } catch {
    // Keep the default branding when the endpoint is unavailable.
  }
}

export function startThemeController(): () => void {
  if (typeof window === 'undefined') return () => {};
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  let branding = DEFAULT_BRANDING;
  let brandingReady = false;
  let preference = readStoredTheme();
  localTheme.set(preference);

  const apply = () => {
    const resolved = resolveTheme(preference, media.matches);
    if (brandingReady) {
      applyThemeToDocument(branding, resolved);
    } else {
      document.documentElement.dataset.theme = resolved;
      document.documentElement.style.colorScheme = resolved;
    }
    resolvedThemeStore.set(resolved);
  };
  const stopBranding = brandingStore.subscribe((value) => {
    branding = value;
    apply();
  });
  const stopTheme = localTheme.subscribe((value) => {
    preference = value;
    apply();
  });
  const stopBrandingReady = brandingReadyStore.subscribe((value) => {
    brandingReady = value;
    apply();
  });
  const handleSystemTheme = () => apply();
  const handleStorage = (event: StorageEvent) => {
    if (event.key === themeStorageKey) localTheme.set(normalizeTheme(event.newValue));
  };
  media.addEventListener('change', handleSystemTheme);
  window.addEventListener('storage', handleStorage);
  return () => {
    stopBranding();
    stopTheme();
    stopBrandingReady();
    media.removeEventListener('change', handleSystemTheme);
    window.removeEventListener('storage', handleStorage);
  };
}

export function consumeProviderAuthError(): ProviderAuthErrorResult | null {
  if (typeof window === 'undefined') return null;
  const result = cleanProviderAuthError(window.location.href);
  if (!result) return null;
  window.history.replaceState(window.history.state, '', result.cleanPath);
  return result;
}
