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

export type MFAMethod = 'totp' | 'recovery_code' | 'passkey';
export type CodeMFAMethod = Exclude<MFAMethod, 'passkey'>;
export type MFAPurpose = 'login' | 'reauthentication';

export interface MFARequiredResponse {
  status: 'mfa_required';
  purpose: MFAPurpose;
  username: string;
  methods: MFAMethod[];
  csrf_token: string;
  expires_at: string;
}

export type LoginResponse = SessionInfo | MFARequiredResponse;
export type ReauthenticationResponse = SessionInfo | MFARequiredResponse;

export interface MFAStatus {
  totp_available: boolean;
  totp_enrolled: boolean;
  can_disable_totp: boolean;
  passkeys_available: boolean;
  passkeys_enrolled: number;
  recovery_codes_remaining: number;
  require_mfa_for_admins: boolean;
  required_for_current_user: boolean;
}

export interface TOTPEnrollment {
  secret: string;
  otpauth_uri: string;
}

export interface TOTPConfirmationResult extends SessionInfo {
  recovery_codes: string[];
}

export interface RecoveryCodesResult {
  recovery_codes: string[];
}

export interface SecuritySettings {
  totp_enabled: boolean;
  passkeys_enabled: boolean;
  require_mfa_for_admins: boolean;
}

export interface WebAuthnOptionsResponse<TPublicKey> {
  ceremony_id: string;
  public_key: TPublicKey;
  mediation?: CredentialMediationRequirement;
  expires_at: string;
}

export type PasskeyAuthenticationOptions = WebAuthnOptionsResponse<PublicKeyCredentialRequestOptionsJSON>;
export type PasskeyRegistrationOptions = WebAuthnOptionsResponse<PublicKeyCredentialCreationOptionsJSON>;

export interface PasskeyCredential {
  id: string;
  name: string;
  transports: string[];
  aaguid?: string;
  attachment?: string;
  backup_eligible: boolean;
  backup_state: boolean;
  clone_warning: boolean;
  created_at: string;
  last_used_at?: string | null;
}

export interface PasskeyRegistrationResult extends SessionInfo {
  passkey: PasskeyCredential;
}

export function isMFARequiredResponse(response: LoginResponse): response is MFARequiredResponse {
  return 'status' in response && response.status === 'mfa_required';
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
  access_policy?: ClientAccessPolicy;
  secret_hint?: string | null;
  secret_version: number;
  secret_rotated_at?: string | null;
  secret_last_used_at?: string | null;
  owner_id?: string | null;
  metadata?: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export type ClientAccessPolicy = 'open' | 'admins_only' | 'allowlist';

export interface ClientAccessUser {
  user_id: string;
  username: string;
  display_name: string;
  status: string;
  created_at: string;
}

export interface CreateClientInput {
  name: string;
  redirect_uris: string[];
  post_logout_redirect_uris?: string[];
  grants: string[];
  scopes: string[];
  is_public: boolean;
  access_policy?: ClientAccessPolicy;
  owner_id?: string | null;
  metadata?: Record<string, string>;
}

export interface UpdateClientInput {
  name?: string;
  redirect_uris?: string[];
  post_logout_redirect_uris?: string[];
  grants?: string[];
  scopes?: string[];
  access_policy?: ClientAccessPolicy;
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
  pending_registrations: number;
  completed_registrations_7d: number;
  registration_completion_rate_30d: number | null;
  mail_backlog: number;
  mail_failures_24h: number;
  smtp_circuit_state: 'closed' | 'open';
  mail_stats_available_from: string;
  refreshed_at: string;
}

export interface LoginTrend {
  labels: string[];
  values: number[];
}

export type StatsTrendDays = 7 | 30 | 90;

export interface RegistrationTrendPoint {
  day: string;
  registrations_started: number;
  registrations_completed: number;
  registrations_expired: number;
  invites_reserved: number;
  invites_consumed: number;
  invites_released: number;
}

export interface RegistrationTrend {
  timezone: 'UTC';
  points: RegistrationTrendPoint[];
}

export interface MailTrendPoint {
  day: string;
  enqueued: number;
  sent: number;
  other_failures: number;
  rejected: number;
  expired: number;
}

export interface MailTrend {
  timezone: 'UTC';
  available_from: string;
  points: MailTrendPoint[];
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

export type RegistrationMode = 'closed' | 'invite_only' | 'open';

export interface RegistrationOptions {
  available: boolean;
  mode: RegistrationMode;
  require_email_verification: boolean;
  allowed_email_domains: string[];
}

export interface RegistrationSettings {
  mode: RegistrationMode;
  require_email_verification: boolean;
  allowed_email_domains: string[];
  pending_registration_ttl: string;
  invite_default_ttl: string;
  invite_default_max_uses: number;
}

export interface RegisterInput {
  username: string;
  email: string;
  password: string;
  invite_code?: string;
}

export interface Invite {
  id: string;
  created_by: string | null;
  note: string;
  max_uses: number;
  used_count: number;
  reserved_count: number;
  expires_at: string;
  revoked_at?: string | null;
  created_at: string;
  status: 'active' | 'expired' | 'exhausted' | 'revoked' | string;
}

export interface CreateInviteResult extends Invite {
  code: string;
  register_url: string;
}

export interface RegisterResult {
  status: 'pending_verification' | 'registered';
  verification_expires_at?: string;
}

export type MailTLSMode = 'starttls' | 'implicit' | 'plain';
export type MailRuntimeMode = 'fallback' | 'active' | 'disabled' | string;
export type MailCircuitState = 'closed' | 'open' | string;
export type MailErrorCategory = 'configuration' | 'authentication' | 'tls' | 'transport' | 'recipient' | 'unknown' | string;

export interface MailConfig {
  source: 'environment' | 'database' | string;
  id?: string;
  revision?: number;
  host: string;
  port: number;
  username: string;
  tls_mode: MailTLSMode;
  from_address: string;
  from_name: string;
  public_base_url: string;
  connect_timeout: string;
  send_timeout: string;
  password_configured: boolean;
  created_by?: string;
  created_at?: string;
}

export interface MailCircuit {
  state: MailCircuitState;
  open_category?: MailErrorCategory;
  open_reason?: string;
  opened_at?: string;
  next_probe_at?: string;
  transport_failure_count: number;
}

export interface MailSettings {
  mode: MailRuntimeMode;
  configured: boolean;
  available: boolean;
  state_revision: number;
  circuit: MailCircuit;
  active?: MailConfig;
  candidate?: MailConfig;
  previous?: MailConfig;
}

export interface SaveMailCandidateInput {
  expected_revision: number;
  host: string;
  port: number;
  username: string;
  password?: string;
  tls_mode: MailTLSMode;
  from_address: string;
  from_name: string;
  public_base_url: string;
  connect_timeout: string;
  send_timeout: string;
}

export interface SaveMailCandidateResult {
  candidate: MailConfig;
  state_revision: number;
}

export interface MailTestResult {
  result: 'success' | 'failure';
  error_category?: MailErrorCategory;
  tested_at: string;
  state_revision: number;
}

export interface MailMutationResult {
  status: 'activated' | 'rolled_back' | 'disabled' | string;
  state_revision: number;
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
    mail: {
      status: ComponentStatus;
      mode: MailRuntimeMode;
      configured: boolean;
      available: boolean;
      circuit_state: MailCircuitState;
    };
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

export interface APIErrorResponse {
  error?: string;
  error_description?: string;
  message?: string;
  missing_admins?: unknown;
  [key: string]: unknown;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly retryAfter?: number,
    readonly serverMessage: string = message,
    readonly response?: APIErrorResponse,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export function missingAdminsFromError(cause: unknown): string[] {
  if (!(cause instanceof ApiError) || !Array.isArray(cause.response?.missing_admins)) return [];
  return cause.response.missing_admins.filter((value): value is string => typeof value === 'string' && value.trim() !== '');
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
  'email verification is required before signing in': '邮箱尚未验证，请先完成验证邮件中的确认再登录',
  'registration is closed': '当前未开放注册',
  'invite code is required': '需要邀请码才能注册',
  'invalid or expired invite code': '邀请码无效或已失效',
  'username or email is already taken': '用户名或邮箱已被使用',
  'email domain is not allowed': '该邮箱域名不允许注册',
  'too many registration attempts': '注册尝试过于频繁，请稍后再试',
  'registration is temporarily unavailable': '注册功能暂时不可用，请稍后重试',
  'registration temporarily unavailable': '注册功能暂时不可用，请稍后重试',
  'registration requires email delivery, which is not configured': '注册功能暂不可用：邮件服务未配置',
  'mail settings are temporarily unavailable': '邮件设置暂时不可用，请稍后重试',
  'mail configuration is invalid': 'SMTP 配置无效，请检查各字段和密码设置',
  'mail configuration version was not found': '邮件配置版本不存在，请重新加载',
  'mail settings changed; reload and try again': '邮件设置已被其他管理员修改，请重新加载后再试',
  'a successful candidate test is required': '激活前必须先成功发送候选配置的测试邮件',
  'the successful candidate test has expired': '候选配置的成功测试已过期，请重新发送测试邮件',
  'no previous mail configuration is available': '没有可回滚的上一版邮件配置',
  'mail is already disabled': '邮件服务已经处于禁用状态',
  'close self-registration before disabling mail': '禁用邮件服务前必须先关闭自助注册',
  'too many mail settings operations': '邮件设置操作过于频繁，请稍后重试',
  'connect_timeout must be a valid duration': '连接超时必须是有效时长，例如 10s',
  'send_timeout must be a valid duration': '发送超时必须是有效时长，例如 30s',
  'plain smtp is forbidden in production': '生产环境禁止使用明文 SMTP',
  'public_base_url must use https in production': '生产环境的公开地址必须使用 HTTPS',
  'email is invalid': '邮箱地址格式无效',
  'mfa challenge expired': '多因素验证已过期，请重新登录',
  'mfa challenge temporarily unavailable': '多因素验证暂时不可用，请稍后重试',
  'mfa verification temporarily unavailable': '多因素验证暂时不可用，请稍后重试',
  'too many mfa attempts': '验证尝试过于频繁，请稍后再试',
  'invalid mfa code': '验证码或恢复码不正确',
  'invalid totp code': '动态验证码不正确',
  'unsupported mfa method': '当前验证方式不可用，请刷新页面重试',
  'account changed; sign in again': '账户安全状态已变化，请重新登录',
  'mfa enrollment is required; contact an administrator': '管理员策略要求启用多因素验证，请联系管理员协助完成设置',
  'totp enrollment is disabled': '管理员已关闭动态验证码注册',
  'totp is already enrolled': '动态验证码已经启用',
  'totp enrollment must be restarted': '本次设置已失效，请重新开始启用动态验证码',
  'totp is not enrolled': '尚未启用动态验证码',
  'mfa is required for active administrators': '管理员策略要求保留多因素验证，当前无法停用',
  'all active administrators must enroll mfa before it can be required': '仍有管理员未启用多因素验证，暂时无法强制执行',
  'totp must remain enabled while administrator mfa is required': '要求管理员启用多因素验证时，必须同时开放动态验证码功能',
  'passkey login temporarily unavailable': 'Passkey 登录暂时不可用，请稍后重试',
  'passkey verification temporarily unavailable': 'Passkey 验证暂时不可用，请稍后重试',
  'passkey reauthentication temporarily unavailable': 'Passkey 重新认证暂时不可用，请稍后重试',
  'passkey registration temporarily unavailable': 'Passkey 注册暂时不可用，请稍后重试',
  'passkey registered; please sign in again': 'Passkey 已注册，但当前会话无法继续使用，请重新登录',
  'passkey removed; please sign in again': 'Passkey 已删除，但当前会话无法继续使用，请重新登录',
  'passkey verification failed': 'Passkey 验证失败，请重试',
  'passkey registration could not be verified': '无法验证这枚 Passkey，请重新注册',
  'passkey enrollment is disabled': '管理员已关闭新的 Passkey 注册',
  'this passkey is already registered': '这枚 Passkey 已经注册',
  'no passkey is registered': '当前账户尚未注册 Passkey',
  'passkey not found': 'Passkey 不存在或已被删除',
  'passkey name must contain 1 to 64 characters': 'Passkey 名称须为 1 至 64 个字符',
  'add a password, provider identity, or another passkey before removing this passkey': '请先添加密码、外部身份或另一枚 Passkey，再删除当前 Passkey',
  'webauthn ceremony id is required': 'Passkey 验证状态缺失，请重新开始',
  'webauthn ceremony expired': 'Passkey 验证已过期，请重新开始',
  'webauthn ceremony is invalid': 'Passkey 验证状态无效，请重新开始',
  'too many passkey ceremonies': 'Passkey 操作过于频繁，请稍后重试',
};

export function localizeAPIErrorMessage(message: string): string {
  const normalized = message.trim().toLowerCase();
  if (normalized.includes(PASSWORD_POLICY_ERROR)) return PASSWORD_REQUIREMENT;
  if (API_ERROR_TRANSLATIONS[normalized]) return API_ERROR_TRANSLATIONS[normalized];
  return message;
}

export function isRecentAuthenticationError(cause: unknown): cause is ApiError {
  return cause instanceof ApiError
    && cause.status === 403
    && cause.serverMessage.trim().toLowerCase() === 'recent authentication is required';
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
  if (path.startsWith('/api/') && isMutation(opts.method) && csrfToken && !requestHeaders.has('X-CSRF-Token')) {
    requestHeaders.set('X-CSRF-Token', csrfToken);
  }

  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    credentials: 'same-origin',
    headers: requestHeaders,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({})) as APIErrorResponse;
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
      message,
      body,
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
  const maybeSession = data as Partial<SessionInfo> & { status?: unknown };
  if (maybeSession.csrf_token && maybeSession.status !== 'mfa_required') {
    setCsrfToken(maybeSession.csrf_token);
  }
  return data;
}

export const api = {
  login: (username: string, password: string, returnTo: string) =>
    req<LoginResponse>('/api/login', {
      method: 'POST', body: JSON.stringify({ username, password, return_to: returnTo }),
    }, false),
  getLoginMFA: () => req<MFARequiredResponse>('/api/login/mfa', { cache: 'no-store' }, false),
  verifyLoginMFA: (method: CodeMFAMethod, code: string, pendingCsrf: string) => req<SessionInfo>('/api/login/mfa', {
    method: 'POST',
    headers: { 'X-CSRF-Token': pendingCsrf },
    body: JSON.stringify({ method, code }),
  }, false),
  cancelLoginMFA: (pendingCsrf: string) => req<void>('/api/login/mfa', {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': pendingCsrf },
  }, false),
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
  getRegistrationOptions: () => req<RegistrationOptions>('/api/registration', {}, false),
  register: (data: RegisterInput) =>
    req<RegisterResult>('/api/register', { method: 'POST', body: JSON.stringify(data) }, false),
  resendPendingEmailVerification: (email: string) =>
    req<{ status: 'accepted' }>('/api/email/verification/resend', {
      method: 'POST', body: JSON.stringify({ email }),
    }, false),
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
  reauthenticateWithPassword: (password: string) => req<ReauthenticationResponse>('/api/me/reauth/password', {
    method: 'POST',
    body: JSON.stringify({ password }),
  }, false),
  reauthenticateWithProvider: (provider: string, returnTo = '/profile') => req<{ redirect_url: string }>(`/api/me/reauth/${encodeURIComponent(provider)}`, {
    method: 'POST',
    body: JSON.stringify({ return_to: returnTo }),
  }),
  beginPasskeyLogin: (conditional: boolean, returnTo: string, signal?: AbortSignal) => req<PasskeyAuthenticationOptions>('/api/login/passkey/options', {
    method: 'POST',
    body: JSON.stringify({ conditional, return_to: returnTo }),
    signal,
  }, false),
  finishPasskeyLogin: (ceremonyID: string, credential: unknown, signal?: AbortSignal) => req<SessionInfo>('/api/login/passkey/verify', {
    method: 'POST',
    headers: { 'X-WebAuthn-Ceremony': ceremonyID },
    body: JSON.stringify(credential),
    signal,
  }, false),
  beginMFAPasskey: (pendingCsrf: string, signal?: AbortSignal) => req<PasskeyAuthenticationOptions>('/api/login/mfa/passkey/options', {
    method: 'POST',
    headers: { 'X-CSRF-Token': pendingCsrf },
    signal,
  }, false),
  finishMFAPasskey: (ceremonyID: string, credential: unknown, pendingCsrf: string, signal?: AbortSignal) => req<SessionInfo>('/api/login/mfa/passkey/verify', {
    method: 'POST',
    headers: { 'X-CSRF-Token': pendingCsrf, 'X-WebAuthn-Ceremony': ceremonyID },
    body: JSON.stringify(credential),
    signal,
  }, false),
  beginPasskeyReauthentication: (signal?: AbortSignal) => req<PasskeyAuthenticationOptions>('/api/me/reauth/passkey/options', { method: 'POST', signal }, false),
  finishPasskeyReauthentication: (ceremonyID: string, credential: unknown, signal?: AbortSignal) => req<SessionInfo>('/api/me/reauth/passkey/verify', {
    method: 'POST',
    headers: { 'X-WebAuthn-Ceremony': ceremonyID },
    body: JSON.stringify(credential),
    signal,
  }, false),
  getMyMFA: () => req<MFAStatus>('/api/me/mfa', { cache: 'no-store' }),
  beginTOTPEnrollment: () => req<TOTPEnrollment>('/api/me/mfa/totp/enroll', { method: 'POST' }),
  confirmTOTPEnrollment: (code: string) => req<TOTPConfirmationResult>('/api/me/mfa/totp/enroll/confirm', {
    method: 'POST', body: JSON.stringify({ code }),
  }),
  regenerateRecoveryCodes: () => req<RecoveryCodesResult>('/api/me/mfa/recovery-codes', { method: 'POST' }),
  disableTOTP: () => req<SessionInfo>('/api/me/mfa/totp', { method: 'DELETE' }),
  getMyPasskeys: () => req<{ passkeys: PasskeyCredential[] }>('/api/me/passkeys', { cache: 'no-store' }),
  beginPasskeyRegistration: (name: string, signal?: AbortSignal) => req<PasskeyRegistrationOptions>('/api/me/passkeys/registration/options', {
    method: 'POST',
    body: JSON.stringify({ name }),
    signal,
  }),
  finishPasskeyRegistration: (ceremonyID: string, credential: unknown, signal?: AbortSignal) => req<PasskeyRegistrationResult>('/api/me/passkeys/registration/verify', {
    method: 'POST',
    headers: { 'X-WebAuthn-Ceremony': ceremonyID },
    body: JSON.stringify(credential),
    signal,
  }, false),
  renamePasskey: (id: string, name: string) => req<PasskeyCredential>(`/api/me/passkeys/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify({ name }),
  }),
  deletePasskey: (id: string) => req<SessionInfo>(`/api/me/passkeys/${encodeURIComponent(id)}`, { method: 'DELETE' }, false),
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
    getRegistrationTrend: (days: StatsTrendDays = 30) =>
      req<RegistrationTrend>(`/api/admin/stats/registration-trend?days=${days}`),
    getMailTrend: (days: StatsTrendDays = 30) =>
      req<MailTrend>(`/api/admin/stats/mail-trend?days=${days}`),
    getRecentLogins: (limit = 5) => req<RecentLogin[]>(`/api/admin/stats/recent-logins?limit=${limit}`),
    getSystemStatus: () => req<SystemStatus>('/api/admin/system/status'),
    updateBranding: (branding: Branding) =>
      req<Branding>('/api/admin/branding', { method: 'PUT', body: JSON.stringify(branding) }),
    getRegistrationSettings: () => req<RegistrationSettings>('/api/admin/settings/registration'),
    updateRegistrationSettings: (settings: RegistrationSettings) =>
      req<RegistrationSettings>('/api/admin/settings/registration', { method: 'PUT', body: JSON.stringify(settings) }),
    getSecuritySettings: () => req<SecuritySettings>('/api/admin/settings/security'),
    updateSecuritySettings: (settings: SecuritySettings) =>
      req<SecuritySettings>('/api/admin/settings/security', { method: 'PUT', body: JSON.stringify(settings) }),
    getMailSettings: () => req<MailSettings>('/api/admin/settings/mail'),
    saveMailCandidate: (settings: SaveMailCandidateInput) =>
      req<SaveMailCandidateResult>('/api/admin/settings/mail/candidate', { method: 'PUT', body: JSON.stringify(settings) }),
    testMailCandidate: (expectedRevision: number, versionID: string, email: string) =>
      req<MailTestResult>('/api/admin/settings/mail/candidate/test', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision, version_id: versionID, email }),
      }),
    activateMailCandidate: (expectedRevision: number, versionID: string) =>
      req<MailMutationResult>('/api/admin/settings/mail/activate', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision, version_id: versionID }),
      }),
    rollbackMailSettings: (expectedRevision: number) =>
      req<MailMutationResult>('/api/admin/settings/mail/rollback', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision }),
      }),
    disableMail: (expectedRevision: number) =>
      req<MailMutationResult>('/api/admin/settings/mail/disable', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision }),
      }),
    getInvites: () => req<Invite[]>('/api/admin/invites'),
    createInvite: (data: { note?: string; max_uses?: number; ttl?: string }) =>
      req<CreateInviteResult>('/api/admin/invites', { method: 'POST', body: JSON.stringify(data) }),
    revokeInvite: (id: string) =>
      req<void>(`/api/admin/invites/${encodeURIComponent(id)}`, { method: 'DELETE' }),
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
    getClientAccessUsers: (id: string) => req<ClientAccessUser[]>(`/api/admin/clients/${encodeURIComponent(id)}/access-users`),
    updateClientAccessUsers: (id: string, userIDs: string[]) =>
      req<ClientAccessUser[]>(`/api/admin/clients/${encodeURIComponent(id)}/access-users`, { method: 'PUT', body: JSON.stringify({ user_ids: userIDs }) }),
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
