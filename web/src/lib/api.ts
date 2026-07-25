const BASE = '';

export interface SessionUser {
  id: string;
  username: string;
  email?: string | null;
  display_name?: string | null;
  avatar_url?: string | null;
  role: 'admin' | 'user';
  status?: string;
  created_at?: string;
  last_login_at?: string | null;
}

export interface SessionInfo {
  user: SessionUser;
  csrf_token: string;
  must_change_password: boolean;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly retryAfter?: number,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

let csrfToken = '';

export function setCsrfToken(value: string | null | undefined): void {
  csrfToken = value || '';
}

function isMutation(method?: string): boolean {
  return !['GET', 'HEAD', 'OPTIONS'].includes((method || 'GET').toUpperCase());
}

function safeCurrentPath(): string {
  if (typeof window === 'undefined') return '/';
  return `${window.location.pathname}${window.location.search}`;
}

async function req<T>(path: string, opts: RequestInit = {}, redirectOnUnauthorized = true): Promise<T> {
  const requestHeaders = new Headers(opts.headers);
  if (opts.body && !(opts.body instanceof FormData) && !requestHeaders.has('Content-Type')) {
    requestHeaders.set('Content-Type', 'application/json');
  }
  if (path.startsWith('/api/') && isMutation(opts.method) && csrfToken) {
    requestHeaders.set('X-CSRF-Token', csrfToken);
  }

  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    credentials: 'same-origin',
    headers: requestHeaders,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({})) as { error?: string; error_description?: string; message?: string };
    if (res.status === 401) {
      setCsrfToken('');
      if (redirectOnUnauthorized && typeof window !== 'undefined' && window.location.pathname !== '/login') {
        const returnTo = encodeURIComponent(safeCurrentPath());
        window.location.assign(`/login?return_to=${returnTo}`);
      }
    }
    const retryAfterHeader = res.headers.get('Retry-After');
    const retryAfter = retryAfterHeader ? Number.parseInt(retryAfterHeader, 10) : undefined;
    throw new ApiError(
      body.error_description || body.message || body.error || `请求失败 (${res.status})`,
      res.status,
      Number.isFinite(retryAfter) ? retryAfter : undefined,
    );
  }

  if (res.status === 204) return undefined as T;
  const data = await res.json() as T;
  const maybeSession = data as Partial<SessionInfo>;
  if (maybeSession.csrf_token) setCsrfToken(maybeSession.csrf_token);
  return data;
}

export const api = {
  login: (username: string, password: string) =>
    req<SessionInfo>('/api/login', { method: 'POST', body: JSON.stringify({ username, password }) }, false),
  session: () => req<SessionInfo>('/api/session', { cache: 'no-store' }, false),
  logout: () => req<void>('/api/logout', { method: 'POST' }),
  getMe: () => req<SessionUser>('/api/me'),
  updateMe: (data: { email?: string | null; display_name?: string | null; avatar_url?: string | null }) =>
    req<SessionUser>('/api/me', { method: 'PUT', body: JSON.stringify(data) }),
  changePassword: (currentPassword: string, newPassword: string) =>
    req<SessionInfo>('/api/me/password', {
      method: 'POST',
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),
  getProviders: () => req<Array<{ name: string; type: string }>>('/api/providers'),
  getMyIdentities: () => req<any[]>('/api/me/identities'),
  bindIdentity: (provider: string, returnTo = '/profile') =>
    req<{ redirect_url: string }>(`/api/me/identities/${encodeURIComponent(provider)}/bind`, {
      method: 'POST',
      body: JSON.stringify({ return_to: returnTo }),
    }),

  consent: {
    get: (challenge: string) => req<any>(`/api/consent?challenge=${encodeURIComponent(challenge)}`),
    accept: (challenge: string) => req<any>('/api/consent/accept', { method: 'POST', body: JSON.stringify({ challenge }) }),
    deny: (challenge: string) => req<any>('/api/consent/deny', { method: 'POST', body: JSON.stringify({ challenge }) }),
  },

  my: {
    getClients: () => req<any>('/api/my/clients'),
    createClient: (data: any) => req<any>('/api/my/clients', { method: 'POST', body: JSON.stringify(data) }),
    deleteClient: (id: string) => req<void>(`/api/my/clients/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  },

  admin: {
    getStats: () => req<any>('/api/admin/stats'),
    getLoginTrend: (days = 7) => req<any>(`/api/admin/stats/login-trend?days=${days}`),
    getRecentLogins: (limit = 5) => req<any>(`/api/admin/stats/recent-logins?limit=${limit}`),
    getUsers: (page = 1, pageSize = 20, search = '') =>
      req<any>(`/api/admin/users?page=${page}&page_size=${pageSize}&q=${encodeURIComponent(search)}`),
    createUser: (data: any) => req<any>('/api/admin/users', { method: 'POST', body: JSON.stringify(data) }),
    updateUser: (id: string, data: any) => req<any>(`/api/admin/users/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    deleteUser: (id: string) => req<void>(`/api/admin/users/${id}`, { method: 'DELETE' }),
    resetPassword: (id: string, password: string) =>
      req<void>(`/api/admin/users/${id}/reset-password`, { method: 'POST', body: JSON.stringify({ password }) }),
    suspendUser: (id: string) => req<any>(`/api/admin/users/${id}/suspend`, { method: 'POST' }),
    activateUser: (id: string) => req<any>(`/api/admin/users/${id}/activate`, { method: 'POST' }),
    updateUserRole: (id: string, role: string) =>
      req<any>(`/api/admin/users/${id}/role`, { method: 'PUT', body: JSON.stringify({ role }) }),
    getUserIdentities: (id: string) => req<any[]>(`/api/admin/users/${id}/identities`),
    getClients: (page = 1, pageSize = 20) => req<any>(`/api/admin/clients?page=${page}&page_size=${pageSize}`),
    createClient: (data: any) => req<any>('/api/admin/clients', { method: 'POST', body: JSON.stringify(data) }),
    updateClient: (id: string, data: any) => req<any>(`/api/admin/clients/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    deleteClient: (id: string) => req<void>(`/api/admin/clients/${id}`, { method: 'DELETE' }),
    getProviders: () => req<any[]>('/api/admin/providers'),
    createProvider: (data: any) => req<any>('/api/admin/providers', { method: 'POST', body: JSON.stringify(data) }),
    updateProvider: (id: string, data: any) => req<any>(`/api/admin/providers/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(data) }),
    testProvider: (id: string) => req<any>(`/api/admin/providers/${encodeURIComponent(id)}/test`, { method: 'POST' }),
    deleteProvider: (id: string) => req<void>(`/api/admin/providers/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    getAuditLogs: (page = 1, pageSize = 20, event = '') =>
      req<any>(`/api/admin/audit-logs?page=${page}&page_size=${pageSize}&event=${encodeURIComponent(event)}`),
  },
};
