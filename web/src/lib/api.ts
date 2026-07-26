import { PASSWORD_REQUIREMENT } from './password-policy';

const BASE = '';

export type UserRole = 'admin' | 'user';
export type UserStatus = 'active' | 'suspended' | 'pending';

export interface User {
  id: string;
  username: string;
  email?: string | null;
  display_name?: string | null;
  avatar_url?: string | null;
  role: UserRole;
  status: UserStatus;
  must_change_password?: boolean;
  last_login_at?: string | null;
  last_login_ip?: string | null;
  metadata?: Record<string, string>;
  created_at: string;
  updated_at?: string;
}

export type SessionUser = User;

export interface SessionInfo {
  user: SessionUser;
  csrf_token: string;
  must_change_password: boolean;
  has_password: boolean;
  email_verified: boolean;
  authenticated_at?: string;
}

export interface ExternalIdentity {
  id: string;
  user_id: string;
  provider: string;
  external_id: string;
  external_username?: string | null;
  external_email?: string | null;
  created_at: string;
  updated_at?: string;
}

export interface ProviderSummary {
  name: string;
  type: 'github' | 'google' | 'generic' | string;
}

export interface OAuthClient {
  id: string;
  name: string;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  grants: string[];
  scopes: string[];
  is_public: boolean;
  secret_hint?: string | null;
  secret_version: number;
  secret_rotated_at?: string | null;
  secret_last_used_at?: string | null;
  owner_id?: string | null;
  metadata?: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export interface CreateClientInput {
  name: string;
  redirect_uris: string[];
  post_logout_redirect_uris?: string[];
  grants: string[];
  scopes: string[];
  is_public: boolean;
  owner_id?: string | null;
  metadata?: Record<string, string>;
}

export interface UpdateClientInput {
  name?: string;
  redirect_uris?: string[];
  post_logout_redirect_uris?: string[];
  grants?: string[];
  scopes?: string[];
  metadata?: Record<string, string>;
}

export interface CreateClientResult extends OAuthClient {
  secret?: string;
}

export interface RotateClientSecretResult {
  client_id: string;
  secret: string;
  secret_hint: string;
  secret_version: number;
  secret_rotated_at: string;
}

export interface OAuthAuthorization {
  id: string;
  client_id: string;
  client_name: string;
  scopes: string[];
  granted_at: string;
  last_used_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ExternalProvider {
  id: string;
  name: string;
  type: 'github' | 'google' | 'generic' | string;
  client_id: string;
  scopes: string[];
  discovery_url?: string | null;
  authorization_url?: string | null;
  token_url?: string | null;
  userinfo_url?: string | null;
  enabled: boolean;
  revision: number;
  metadata?: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export interface CreateProviderInput {
  name: string;
  type: 'github' | 'google' | 'generic';
  client_id: string;
  client_secret: string;
  enabled: boolean;
  scopes?: string[];
  discovery_url?: string;
  authorization_url?: string;
  token_url?: string;
  userinfo_url?: string;
}

export interface UpdateProviderInput {
  client_id?: string;
  client_secret?: string;
  scopes?: string[];
  discovery_url?: string;
  authorization_url?: string;
  token_url?: string;
  userinfo_url?: string;
  enabled?: boolean;
}

export interface ProviderTestResult {
  provider: string;
  type: string;
  configuration_valid: boolean;
  authorization_endpoint_valid: boolean;
  discovery_reachable?: boolean;
  latency_ms?: number;
  message: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface DashboardStats {
  user_count: number;
  app_count: number;
  login_count_7d: number;
  active_sessions: number;
  failed_logins_7d: number;
}

export interface LoginTrend {
  labels: string[];
  values: number[];
}

export interface RecentLogin {
  username: string;
  role?: UserRole;
  result: string;
  ip: string;
  time: string;
}

export interface ConsentRequest {
  challenge: string;
  client_name: string;
  client_id: string;
  scopes: string[];
  redirect_uri: string;
  redirect_origin: string;
  publisher_type: 'system_managed' | 'user_registered';
  verification_status: 'unverified';
}

export interface AuditLog {
  id: string;
  event: string;
  actor_id?: string | null;
  actor_name?: string | null;
  target_type?: string | null;
  target_id?: string | null;
  ip_address?: string | null;
  result: string;
  risk_level: string;
  details?: Record<string, unknown>;
  created_at: string;
}

export interface AuditLogFilters {
  page?: number;
  pageSize?: number;
  event?: string;
  result?: string;
  risk?: string;
  actor?: string;
  target?: string;
  ip?: string;
  from?: string;
  to?: string;
}

export interface BrowserSession {
  id: string;
  current: boolean;
  ip_address?: string;
  user_agent?: string;
  created_at: string;
  last_seen_at: string;
  authenticated_at: string;
}

export interface Branding {
  title: string;
  logo_url: string;
}

export type ComponentStatus = 'ok' | 'degraded' | 'unavailable' | string;

export interface SystemStatus {
  status: ComponentStatus;
  version: string;
  schema: {
    status: ComponentStatus;
    version: number;
    required_version: number;
  };
  services: {
    postgresql: { status: ComponentStatus; latency_ms: number };
    redis: { status: ComponentStatus; latency_ms: number };
    providers: { status: ComponentStatus; latency_ms: number; snapshot_revision: number };
    jwk: { status: ComponentStatus; latency_ms: number };
  };
  active_signing_key?: {
    kid: string;
    status: ComponentStatus;
    signing_started_at: string;
    next_rotation_at: string;
  };
}

export interface OIDCDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
}

export interface CreateUserInput {
  username: string;
  email?: string;
  password: string;
  display_name?: string;
}

export interface UpdateUserInput {
  email?: string | null;
  display_name?: string | null;
  avatar_url?: string | null;
  status?: UserStatus;
  role?: UserRole;
  metadata?: Record<string, string>;
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

const PASSWORD_POLICY_ERROR = 'password must be valid utf-8 and 12 to 1024 bytes';
const API_ERROR_TRANSLATIONS: Record<string, string> = {
  'invalid credentials': '认证凭据不正确',
  'current password is incorrect': '当前密码不正确',
  'authentication required': '登录状态已失效，请重新登录',
  'recent authentication is required': '请先完成近期身份验证',
  'password reauthentication is unavailable': '此账户无法使用密码重新认证',
  'password login is not available for this account': '此账户无法使用密码登录',
  'a local password is already configured': '此账户已设置本地密码',
  'reauthentication failed': '重新认证失败，请稍后重试',
  'reauthentication session could not be updated': '重新认证成功，但会话更新失败，请重试',
  'csrf_validation_failed': '安全校验失败，请刷新页面后重试',
};

export function localizeAPIErrorMessage(message: string): string {
  const normalized = message.trim().toLowerCase();
  if (normalized.includes(PASSWORD_POLICY_ERROR)) return PASSWORD_REQUIREMENT;
  if (API_ERROR_TRANSLATIONS[normalized]) return API_ERROR_TRANSLATIONS[normalized];
  return message;
}

let csrfToken = '';

export function setCsrfToken(value: string | null | undefined): void {
  csrfToken = value || '';
}

function isMutation(method?: string): boolean {
  return !['GET', 'HEAD', 'OPTIONS'].includes((method || 'GET').toUpperCase());
}

function currentRelativeURL(): string {
  if (typeof window === 'undefined') return '/';
  return `${window.location.pathname}${window.location.search}${window.location.hash}`;
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
    if (res.status === 401 && redirectOnUnauthorized) {
      setCsrfToken('');
      if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
        window.location.assign(`/login?return_to=${encodeURIComponent(currentRelativeURL())}`);
      }
    }
    const retryAfterHeader = res.headers.get('Retry-After');
    const retryAfter = retryAfterHeader ? Number.parseInt(retryAfterHeader, 10) : undefined;
    const message = body.error_description || body.message || body.error || `请求失败 (${res.status})`;
    throw new ApiError(
      localizeAPIErrorMessage(message),
      res.status,
      Number.isFinite(retryAfter) ? retryAfter : undefined,
    );
  }

  if (res.status === 204) return undefined as T;
  const responseBody = await res.text();
  if (!responseBody) return undefined as T;
  let data: T;
  try {
    data = JSON.parse(responseBody) as T;
  } catch {
    throw new ApiError('服务返回了无法解析的响应', res.status);
  }
  const maybeSession = data as Partial<SessionInfo>;
  if (maybeSession.csrf_token) setCsrfToken(maybeSession.csrf_token);
  return data;
}

export const api = {
  login: (username: string, password: string) =>
    req<SessionInfo>('/api/login', { method: 'POST', body: JSON.stringify({ username, password }) }, false),
  session: () => req<SessionInfo>('/api/session', { cache: 'no-store' }, false),
  logout: () => req<void>('/api/logout', { method: 'POST' }),
  getMe: () => req<User>('/api/me'),
  updateMe: (data: Pick<UpdateUserInput, 'display_name' | 'avatar_url'>) =>
    req<User>('/api/me', { method: 'PUT', body: JSON.stringify(data) }),
  changePassword: (currentPassword: string, newPassword: string) =>
    req<SessionInfo>('/api/me/password', {
      method: 'POST',
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }, false),
  getBranding: () => req<Branding>('/api/branding', {}, false),
  getProviders: () => req<ProviderSummary[]>('/api/providers'),
  getMyIdentities: () => req<ExternalIdentity[]>('/api/me/identities'),
  bindIdentity: (provider: string, returnTo = '/profile') =>
    req<{ redirect_url: string }>(`/api/me/identities/${encodeURIComponent(provider)}/bind`, {
      method: 'POST',
      body: JSON.stringify({ return_to: returnTo }),
    }),
  getMySessions: () => req<BrowserSession[]>('/api/me/sessions'),
  revokeMySession: (id: string) => req<void>(`/api/me/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  revokeOtherSessions: () => req<{ revoked: number }>('/api/me/sessions/revoke-others', { method: 'POST' }),
  reauthenticateWithPassword: (password: string) => req<SessionInfo>('/api/me/reauth/password', {
    method: 'POST',
    body: JSON.stringify({ password }),
  }, false),
  reauthenticateWithProvider: (provider: string, returnTo = '/profile') => req<{ redirect_url: string }>(`/api/me/reauth/${encodeURIComponent(provider)}`, {
    method: 'POST',
    body: JSON.stringify({ return_to: returnTo }),
  }),
  setPassword: (newPassword: string) => req<SessionInfo>('/api/me/password/set', {
    method: 'POST',
    body: JSON.stringify({ new_password: newPassword }),
  }),
  deleteMyIdentity: (identityID: string) => req<SessionInfo>(`/api/me/identities/${encodeURIComponent(identityID)}`, { method: 'DELETE' }),
  getMyAuthorizations: () => req<OAuthAuthorization[]>('/api/me/authorizations'),
  revokeMyAuthorization: (clientID: string) => req<void>(`/api/me/authorizations/${encodeURIComponent(clientID)}`, { method: 'DELETE' }),
  discovery: () => req<OIDCDiscoveryDocument>('/.well-known/openid-configuration', {}, false),

  account: {
    requestPasswordReset: (email: string) => req<void>('/api/password/forgot', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }, false),
    confirmPasswordReset: (token: string, newPassword: string) => req<void>('/api/password/reset', {
      method: 'POST',
      body: JSON.stringify({ token, new_password: newPassword }),
    }, false),
    requestEmailVerification: () => req<void>('/api/me/email/verification', { method: 'POST' }),
    confirmEmailVerification: (token: string) => req<void>('/api/email/verify', {
      method: 'POST',
      body: JSON.stringify({ token }),
    }, false),
    requestEmailChange: (email: string) => req<void>('/api/me/email/change', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }),
    confirmEmailChange: (token: string) => req<void>('/api/email/change/confirm', {
      method: 'POST',
      body: JSON.stringify({ token }),
    }, false),
  },

  consent: {
    get: (challenge: string) => req<ConsentRequest>(`/api/consent?challenge=${encodeURIComponent(challenge)}`),
    accept: (challenge: string) => req<{ redirect_url: string }>('/api/consent/accept', { method: 'POST', body: JSON.stringify({ challenge }) }),
    deny: (challenge: string) => req<{ redirect_url: string }>('/api/consent/deny', { method: 'POST', body: JSON.stringify({ challenge }) }),
  },

  my: {
    getClients: () => req<PaginatedResponse<OAuthClient>>('/api/my/clients'),
    createClient: (data: CreateClientInput) => req<CreateClientResult>('/api/my/clients', { method: 'POST', body: JSON.stringify(data) }),
    deleteClient: (id: string) => req<void>(`/api/my/clients/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    rotateClientSecret: (id: string) => req<RotateClientSecretResult>(`/api/my/clients/${encodeURIComponent(id)}/rotate-secret`, { method: 'POST' }),
  },

  admin: {
    getStats: () => req<DashboardStats>('/api/admin/stats'),
    getLoginTrend: (days = 7) => req<LoginTrend>(`/api/admin/stats/login-trend?days=${days}`),
    getRecentLogins: (limit = 5) => req<RecentLogin[]>(`/api/admin/stats/recent-logins?limit=${limit}`),
    getSystemStatus: () => req<SystemStatus>('/api/admin/system/status'),
    updateBranding: (branding: Branding) =>
      req<Branding>('/api/admin/branding', { method: 'PUT', body: JSON.stringify(branding) }),
    getUsers: (page = 1, pageSize = 20, search = '', status?: UserStatus) => {
      const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
      if (search) params.set('q', search);
      if (status) params.set('status', status);
      return req<PaginatedResponse<User>>(`/api/admin/users?${params}`);
    },
    createUser: (data: CreateUserInput) => req<User>('/api/admin/users', { method: 'POST', body: JSON.stringify(data) }),
    updateUser: (id: string, data: UpdateUserInput) => req<User>(`/api/admin/users/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    deleteUser: (id: string) => req<void>(`/api/admin/users/${id}`, { method: 'DELETE' }),
    resetPassword: (id: string, password: string) =>
      req<void>(`/api/admin/users/${id}/reset-password`, { method: 'POST', body: JSON.stringify({ password }) }),
    suspendUser: (id: string) => req<User>(`/api/admin/users/${id}/suspend`, { method: 'POST' }),
    activateUser: (id: string) => req<User>(`/api/admin/users/${id}/activate`, { method: 'POST' }),
    updateUserRole: (id: string, role: UserRole) =>
      req<User>(`/api/admin/users/${id}/role`, { method: 'PUT', body: JSON.stringify({ role }) }),
    getUserIdentities: (id: string) => req<ExternalIdentity[]>(`/api/admin/users/${id}/identities`),
    deleteUserIdentity: (userID: string, identityID: string) =>
      req<void>(`/api/admin/users/${encodeURIComponent(userID)}/identities/${encodeURIComponent(identityID)}`, { method: 'DELETE' }),
    getUserSessions: (id: string) => req<BrowserSession[]>(`/api/admin/users/${encodeURIComponent(id)}/sessions`),
    revokeUserSessions: (id: string) => req<{ revoked: number }>(`/api/admin/users/${encodeURIComponent(id)}/sessions`, { method: 'DELETE' }),
    getClients: (page = 1, pageSize = 20) => req<PaginatedResponse<OAuthClient>>(`/api/admin/clients?page=${page}&page_size=${pageSize}`),
    createClient: (data: CreateClientInput) => req<CreateClientResult>('/api/admin/clients', { method: 'POST', body: JSON.stringify(data) }),
    updateClient: (id: string, data: UpdateClientInput) => req<OAuthClient>(`/api/admin/clients/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    updateClientOwner: (id: string, data: { owner_id: string | null }) =>
      req<OAuthClient>(`/api/admin/clients/${encodeURIComponent(id)}/owner`, { method: 'PUT', body: JSON.stringify(data) }),
    deleteClient: (id: string) => req<void>(`/api/admin/clients/${id}`, { method: 'DELETE' }),
    rotateClientSecret: (id: string) => req<RotateClientSecretResult>(`/api/admin/clients/${encodeURIComponent(id)}/rotate-secret`, { method: 'POST' }),
    getProviders: () => req<ExternalProvider[]>('/api/admin/providers'),
    createProvider: (data: CreateProviderInput) => req<ExternalProvider>('/api/admin/providers', { method: 'POST', body: JSON.stringify(data) }),
    updateProvider: (id: string, data: UpdateProviderInput) => req<ExternalProvider>(`/api/admin/providers/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(data) }),
    testProvider: (id: string) => req<ProviderTestResult>(`/api/admin/providers/${encodeURIComponent(id)}/test`, { method: 'POST' }),
    deleteProvider: (id: string) => req<void>(`/api/admin/providers/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    getAuditLogs: (filters: AuditLogFilters = {}) => {
      const params = new URLSearchParams({
        page: String(filters.page || 1),
        page_size: String(filters.pageSize || 20),
      });
      for (const key of ['event', 'result', 'risk', 'actor', 'target', 'ip', 'from', 'to'] as const) {
        if (filters[key]) params.set(key, filters[key]);
      }
      return req<PaginatedResponse<AuditLog>>(`/api/admin/audit-logs?${params}`);
    },
  },
};
