import { get } from 'svelte/store';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, ApiError, type SessionInfo } from './api';
import { createSessionStore } from './stores';

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function session(username: string, csrfToken: string): SessionInfo {
  return {
    user: {
      id: `${username}-id`, username, role: 'user', status: 'active', created_at: '2026-07-26T00:00:00Z',
    },
    csrf_token: csrfToken,
    must_change_password: false,
    has_password: true,
    email_verified: true,
  };
}

describe('session store initialization', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('classifies a 401 response as unauthenticated without throwing', async () => {
    vi.spyOn(api, 'session').mockRejectedValue(new ApiError('authentication required', 401));
    const store = createSessionStore();

    await expect(store.initialize()).resolves.toBeNull();
    expect(get(store)).toMatchObject({
      initialized: true,
      status: 'unauthenticated',
      session: null,
      error: null,
    });
  });

  it('classifies an HTTP failure as a server error with a safe message', async () => {
    vi.spyOn(api, 'session').mockRejectedValue(new ApiError('database connection details', 503));
    const store = createSessionStore();

    await expect(store.initialize()).rejects.toMatchObject({
      status: 'server_error',
      message: '认证服务暂时无法检查会话，请稍后重试。',
    });
    expect(get(store)).toMatchObject({
      initialized: true,
      status: 'server_error',
      session: null,
      error: '认证服务暂时无法检查会话，请稍后重试。',
    });
  });

  it('classifies a fetch failure as a network error', async () => {
    vi.spyOn(api, 'session').mockRejectedValue(new TypeError('fetch failed'));
    const store = createSessionStore();

    await expect(store.initialize()).rejects.toMatchObject({
      status: 'network_error',
      message: '无法连接认证服务，请检查网络连接后重试。',
    });
    expect(get(store)).toMatchObject({
      initialized: true,
      status: 'network_error',
      session: null,
      error: '无法连接认证服务，请检查网络连接后重试。',
    });
  });

  it('does not let an older 401 overwrite a newly established login session', async () => {
    const first = deferred<SessionInfo>();
    vi.spyOn(api, 'session').mockReturnValue(first.promise);
    const store = createSessionStore();

    const staleInitialization = store.initialize(true);
    const authenticated = session('alice', 'fresh-csrf');
    store.setSession(authenticated);
    first.reject(new ApiError('authentication required', 401));

    await expect(staleInitialization).resolves.toEqual(authenticated);
    expect(get(store)).toMatchObject({
      initialized: true,
      status: 'authenticated',
      session: authenticated,
      error: null,
    });
  });

  it('keeps the newest forced initialization pending when an older request settles', async () => {
    const first = deferred<SessionInfo>();
    const second = deferred<SessionInfo>();
    const sessionSpy = vi.spyOn(api, 'session')
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);
    const store = createSessionStore();

    const staleInitialization = store.initialize(true);
    const currentInitialization = store.initialize(true);
    first.resolve(session('old', 'old-csrf'));
    await staleInitialization;

    expect(store.initialize()).toBe(currentInitialization);
    const current = session('current', 'current-csrf');
    second.resolve(current);
    await expect(currentInitialization).resolves.toEqual(current);
    expect(sessionSpy).toHaveBeenCalledTimes(2);
    expect(get(store).session).toEqual(current);
  });
});
