const BASE = '';

let refreshing = false;
let refreshPromise: Promise<string | null> | null = null;

function getToken(): string | null {
  if (typeof localStorage === 'undefined') return null;
  return localStorage.getItem('nya_token');
}

function getRefreshToken(): string | null {
  if (typeof localStorage === 'undefined') return null;
  return localStorage.getItem('nya_refresh');
}

function setTokens(access: string, refresh?: string) {
  localStorage.setItem('nya_token', access);
  if (refresh) localStorage.setItem('nya_refresh', refresh);
}

function clearAuth() {
  localStorage.removeItem('nya_token');
  localStorage.removeItem('nya_refresh');
}

function headers(): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  const t = getToken();
  if (t) h['Authorization'] = `Bearer ${t}`;
  return h;
}

async function doRefresh(): Promise<string | null> {
  const rt = getRefreshToken();
  if (!rt) return null;
  try {
    const res = await fetch(`${BASE}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt, client_id: 'nyauth-web' }),
    });
    if (!res.ok) return null;
    const data = await res.json();
    setTokens(data.access_token, data.refresh_token);
    return data.access_token;
  } catch {
    return null;
  }
}

async function req<T>(path: string, opts: RequestInit = {}): Promise<T> {
  let res = await fetch(`${BASE}${path}`, { ...opts, headers: { ...headers(), ...(opts.headers as Record<string, string>) } });

  // If 401, try to refresh token once
  if (res.status === 401 && !refreshing) {
    refreshing = true;
    try {
      const newToken = await doRefresh();
      if (newToken) {
        // Retry with new token
        const h: Record<string, string> = { 'Content-Type': 'application/json', 'Authorization': `Bearer ${newToken}` };
        res = await fetch(`${BASE}${path}`, { ...opts, headers: { ...h, ...(opts.headers as Record<string, string>) } });
      }
    } finally {
      refreshing = false;
    }
  }

  if (!res.ok) {
    if (res.status === 401) {
      clearAuth();
      window.location.href = '/login';
    }
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || body.error_description || `HTTP ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

export const api = {
  login: (username: string, password: string) =>
    req<any>('/api/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  logout: () => req<any>('/api/logout', { method: 'POST' }),
  getMe: () => req<any>('/api/me'),
  updateMe: (data: any) => req<any>('/api/me', { method: 'PUT', body: JSON.stringify(data) }),
  getProviders: () => req<Array<{ name: string; type: string }>>('/api/providers'),

  consent: {
    get: (challenge: string) => req<any>(`/api/consent?challenge=${encodeURIComponent(challenge)}`),
    accept: (challenge: string) => req<any>('/api/consent/accept', { method: 'POST', body: JSON.stringify({ challenge }) }),
    deny: (challenge: string) => req<any>('/api/consent/deny', { method: 'POST', body: JSON.stringify({ challenge }) }),
  },

  admin: {
    // Stats
    getStats: () => req<any>('/api/admin/stats'),
    getLoginTrend: (days = 7) => req<any>(`/api/admin/stats/login-trend?days=${days}`),
    getRecentLogins: (limit = 5) => req<any>(`/api/admin/stats/recent-logins?limit=${limit}`),

    // Users
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

    // Clients
    getClients: (page = 1, pageSize = 20) =>
      req<any>(`/api/admin/clients?page=${page}&page_size=${pageSize}`),
    createClient: (data: any) => req<any>('/api/admin/clients', { method: 'POST', body: JSON.stringify(data) }),
    updateClient: (id: string, data: any) => req<any>(`/api/admin/clients/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    deleteClient: (id: string) => req<void>(`/api/admin/clients/${id}`, { method: 'DELETE' }),

    // Providers
    getProviders: () => req<any[]>('/api/admin/providers'),
    createProvider: (data: any) => req<any>('/api/admin/providers', { method: 'POST', body: JSON.stringify(data) }),
    updateProvider: (id: string, data: any) => req<any>(`/api/admin/providers/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    testProvider: (id: string) => req<any>(`/api/admin/providers/${id}/test`, { method: 'POST' }),
    deleteProvider: (id: string) => req<void>(`/api/admin/providers/${id}`, { method: 'DELETE' }),

    // Audit logs
    getAuditLogs: (page = 1, pageSize = 20, event = '') =>
      req<any>(`/api/admin/audit-logs?page=${page}&page_size=${pageSize}&event=${encodeURIComponent(event)}`),
  },
};
