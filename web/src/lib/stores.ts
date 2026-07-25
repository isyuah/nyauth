import { writable } from 'svelte/store';
import { browser } from '$app/environment';

interface AuthState {
  token: string | null;
  refreshToken: string | null;
  expiresIn: number | null;
}

function createAuthStore() {
  const initial: AuthState = browser
    ? {
        token: localStorage.getItem('nya_token'),
        refreshToken: localStorage.getItem('nya_refresh'),
        expiresIn: null,
      }
    : { token: null, refreshToken: null, expiresIn: null };

  const { subscribe, set } = writable<AuthState>(initial);

  return {
    subscribe,
    set: (state: AuthState) => {
      if (browser) {
        state.token ? localStorage.setItem('nya_token', state.token) : localStorage.removeItem('nya_token');
        state.refreshToken ? localStorage.setItem('nya_refresh', state.refreshToken) : localStorage.removeItem('nya_refresh');
      }
      set(state);
    },
    clear: () => {
      if (browser) {
        localStorage.removeItem('nya_token');
        localStorage.removeItem('nya_refresh');
      }
      set({ token: null, refreshToken: null, expiresIn: null });
    },
  };
}

export const authStore = createAuthStore();
