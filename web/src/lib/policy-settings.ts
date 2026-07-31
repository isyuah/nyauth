import type {
  LifecycleSettings,
  OAuthSettings,
  ProtectionAccountSettings,
  ProtectionAvatarSettings,
  ProtectionLoginSettings,
  ProtectionMailSettings,
  ProtectionSettings,
  UpdateLifecycleSettingsInput,
  UpdateOAuthSettingsInput,
  UpdateProtectionSettingsInput,
} from './api';
import { writable } from 'svelte/store';
import {
  cloneScopeDefinitions,
  DEFAULT_CLAIM_ASSIGNMENT_POLICIES,
  DEFAULT_SCOPE_DEFINITIONS,
  OAUTH_CLAIMS,
} from './oauth-catalog';

export const DISABLE_RATE_LIMITS_CONFIRMATION = 'DISABLE RATE LIMITS';

export const OAUTH_GRANT_TYPES = ['authorization_code', 'refresh_token', 'client_credentials'] as const;
export const OAUTH_SCOPES = ['openid', 'profile', 'email', 'offline_access'] as const;

export const DEFAULT_OAUTH_SETTINGS: OAuthSettings = {
  revision: 0,
  self_service_client_creation_enabled: true,
  public_clients_enabled: true,
  allowed_grant_types: [...OAUTH_GRANT_TYPES],
  allowed_scopes: [...OAUTH_SCOPES],
  scope_definitions: cloneScopeDefinitions(DEFAULT_SCOPE_DEFINITIONS),
  claim_assignment_policies: { ...DEFAULT_CLAIM_ASSIGNMENT_POLICIES },
  max_redirect_uris: 20,
  max_post_logout_redirect_uris: 20,
};

export type ProtectionPreset = 'default' | 'strict' | 'relaxed';
export type ProtectionGroup = 'login' | 'account' | 'avatar' | 'mail';

export interface FieldValidationError {
  field: string;
  message: string;
}

export const protectionSettingsStore = writable<ProtectionSettings | null>(null);

export function publishProtectionSettings(settings: ProtectionSettings) {
  protectionSettingsStore.set({
    revision: settings.revision,
    login: { ...settings.login },
    account: { ...settings.account },
    avatar: { ...settings.avatar },
    mail: { ...settings.mail },
    owned_client_default_limit: settings.owned_client_default_limit,
  });
}

export const DEFAULT_PROTECTION_SETTINGS: ProtectionSettings = {
  revision: 0,
  login: {
    enabled: true,
    window: '5m',
    identity_limit: 5,
    ip_limit: 30,
    passkey_ceremony_ip_limit: 120,
  },
  account: {
    enabled: true,
    window: '15m',
    subject_limit: 5,
    ip_limit: 20,
  },
  avatar: {
    enabled: true,
    window: '15m',
    user_limit: 30,
    ip_limit: 200,
  },
  mail: {
    enabled: true,
    window: '15m',
    save_limit: 60,
    test_limit: 30,
    activate_limit: 30,
    rollback_limit: 30,
    disable_limit: 30,
    ip_limit: 200,
  },
  owned_client_default_limit: 10,
};

const RATE_LIMIT_MIN = 1;
const RATE_LIMIT_MAX = 100_000;
const WINDOW_MIN_MS = 10_000;
const WINDOW_MAX_MS = 24 * 60 * 60 * 1_000;

function scaleLimit(value: number, preset: ProtectionPreset): number {
  if (preset === 'strict') return Math.ceil(value / 2);
  if (preset === 'relaxed') return Math.min(value * 4, RATE_LIMIT_MAX);
  return value;
}

function presetLogin(preset: ProtectionPreset): ProtectionLoginSettings {
  const base = DEFAULT_PROTECTION_SETTINGS.login;
  return {
    enabled: true,
    window: base.window,
    identity_limit: scaleLimit(base.identity_limit, preset),
    ip_limit: scaleLimit(base.ip_limit, preset),
    passkey_ceremony_ip_limit: scaleLimit(base.passkey_ceremony_ip_limit, preset),
  };
}

function presetAccount(preset: ProtectionPreset): ProtectionAccountSettings {
  const base = DEFAULT_PROTECTION_SETTINGS.account;
  return {
    enabled: true,
    window: base.window,
    subject_limit: scaleLimit(base.subject_limit, preset),
    ip_limit: scaleLimit(base.ip_limit, preset),
  };
}

function presetAvatar(preset: ProtectionPreset): ProtectionAvatarSettings {
  const base = DEFAULT_PROTECTION_SETTINGS.avatar;
  return {
    enabled: true,
    window: base.window,
    user_limit: scaleLimit(base.user_limit, preset),
    ip_limit: scaleLimit(base.ip_limit, preset),
  };
}

function presetMail(preset: ProtectionPreset): ProtectionMailSettings {
  const base = DEFAULT_PROTECTION_SETTINGS.mail;
  return {
    enabled: true,
    window: base.window,
    save_limit: scaleLimit(base.save_limit, preset),
    test_limit: scaleLimit(base.test_limit, preset),
    activate_limit: scaleLimit(base.activate_limit, preset),
    rollback_limit: scaleLimit(base.rollback_limit, preset),
    disable_limit: scaleLimit(base.disable_limit, preset),
    ip_limit: scaleLimit(base.ip_limit, preset),
  };
}

export function applyProtectionPreset(
  current: ProtectionSettings,
  preset: ProtectionPreset,
): ProtectionSettings {
  return {
    revision: current.revision,
    login: presetLogin(preset),
    account: presetAccount(preset),
    avatar: presetAvatar(preset),
    mail: presetMail(preset),
    // Client ownership is a quota, not a request rate. Rate presets must not alter it.
    owned_client_default_limit: current.owned_client_default_limit,
  };
}

function rateGroupsEqual(left: ProtectionSettings, right: ProtectionSettings): boolean {
  return JSON.stringify([left.login, left.account, left.avatar, left.mail])
    === JSON.stringify([right.login, right.account, right.avatar, right.mail]);
}

export function matchingProtectionPreset(settings: ProtectionSettings): ProtectionPreset | null {
  for (const preset of ['default', 'strict', 'relaxed'] as const) {
    if (rateGroupsEqual(settings, applyProtectionPreset(settings, preset))) return preset;
  }
  return null;
}

export function disabledProtectionGroups(
  previous: ProtectionSettings,
  next: Pick<UpdateProtectionSettingsInput, ProtectionGroup>,
): ProtectionGroup[] {
  return (['login', 'account', 'avatar', 'mail'] as const)
    .filter((group) => previous[group].enabled && !next[group].enabled);
}

export function retentionConfirmation(days: number): string {
  return `RETENTION ${days} DAYS`;
}

export function parseDurationMilliseconds(value: string): number | null {
  const input = value.trim();
  if (!input) return null;
  const unitMilliseconds: Record<string, number> = {
    ms: 1,
    s: 1_000,
    m: 60_000,
    h: 3_600_000,
  };
  const part = /(\d+(?:\.\d+)?)(ms|s|m|h)/gy;
  let total = 0;
  let offset = 0;
  while (offset < input.length) {
    part.lastIndex = offset;
    const match = part.exec(input);
    if (!match) return null;
    total += Number(match[1]) * unitMilliseconds[match[2]];
    offset = part.lastIndex;
  }
  return Number.isFinite(total) ? total : null;
}

function validLimit(value: number): boolean {
  return Number.isSafeInteger(value) && value >= RATE_LIMIT_MIN && value <= RATE_LIMIT_MAX;
}

function validWindow(value: string): boolean {
  const milliseconds = parseDurationMilliseconds(value);
  return milliseconds !== null && milliseconds >= WINDOW_MIN_MS && milliseconds <= WINDOW_MAX_MS;
}

export function protectionValidationError(input: UpdateProtectionSettingsInput): FieldValidationError | null {
  for (const [field, label, window] of [
    ['protection-login-window', '登录', input.login.window],
    ['protection-account-window', '账户操作', input.account.window],
    ['protection-avatar-window', '头像', input.avatar.window],
    ['protection-mail-window', 'SMTP 管理', input.mail.window],
  ] as const) {
    if (!validWindow(window)) return { field, message: `${label}限流窗口须在 10 秒至 24 小时之间。` };
  }

  const limits = [
    ['protection-login-identity', '登录身份次数', input.login.identity_limit],
    ['protection-login-ip', '登录 IP 次数', input.login.ip_limit],
    ['protection-login-passkey', 'Passkey ceremony IP 次数', input.login.passkey_ceremony_ip_limit],
    ['protection-account-subject', '账户操作主体次数', input.account.subject_limit],
    ['protection-account-ip', '账户操作 IP 次数', input.account.ip_limit],
    ['protection-avatar-user', '头像用户次数', input.avatar.user_limit],
    ['protection-avatar-ip', '头像 IP 次数', input.avatar.ip_limit],
    ['protection-mail-save', 'SMTP 保存次数', input.mail.save_limit],
    ['protection-mail-test', 'SMTP 测试次数', input.mail.test_limit],
    ['protection-mail-activate', 'SMTP 激活次数', input.mail.activate_limit],
    ['protection-mail-rollback', 'SMTP 回滚次数', input.mail.rollback_limit],
    ['protection-mail-disable', 'SMTP 禁用次数', input.mail.disable_limit],
    ['protection-mail-ip', 'SMTP 管理 IP 次数', input.mail.ip_limit],
  ] as const;
  for (const [field, label, value] of limits) {
    if (!validLimit(value)) return { field, message: `${label}须为 1 至 100000 的整数。` };
  }
  if (!Number.isSafeInteger(input.owned_client_default_limit)
    || input.owned_client_default_limit < 0
    || input.owned_client_default_limit > 1_000) {
    return { field: 'protection-client-quota', message: '自助客户端默认配额须为 0 至 1000 的整数。' };
  }
  return null;
}

export function validateProtectionSettings(input: UpdateProtectionSettingsInput): string {
  return protectionValidationError(input)?.message ?? '';
}

export function lifecycleValidationError(input: UpdateLifecycleSettingsInput): FieldValidationError | null {
  const absoluteTTL = parseDurationMilliseconds(input.session_absolute_ttl);
  if (absoluteTTL === null || absoluteTTL < 15 * 60_000 || absoluteTTL > 720 * 3_600_000) {
    return { field: 'lifecycle-session-ttl', message: '会话绝对有效期须在 15 分钟至 720 小时之间。' };
  }
  const idleTTL = parseDurationMilliseconds(input.session_idle_ttl);
  if (idleTTL === null || idleTTL < 5 * 60_000 || idleTTL > 720 * 3_600_000) {
    return { field: 'lifecycle-session-idle-ttl', message: '会话空闲有效期须在 5 分钟至 720 小时之间。' };
  }
  if (idleTTL > absoluteTTL) {
    return { field: 'lifecycle-session-idle-ttl', message: '会话空闲有效期不能超过绝对有效期。' };
  }
  if (!Number.isSafeInteger(input.max_concurrent_sessions)
    || input.max_concurrent_sessions < 0
    || input.max_concurrent_sessions > 100) {
    return { field: 'lifecycle-max-concurrent-sessions', message: '并发会话上限须为 0 至 100 的整数。' };
  }
  const recentTTL = parseDurationMilliseconds(input.recent_authentication_ttl);
  if (recentTTL === null || recentTTL < 60_000 || recentTTL > 3_600_000) {
    return { field: 'lifecycle-recent-auth-ttl', message: '近期认证有效期须在 1 分钟至 1 小时之间。' };
  }
  const accessTokenTTL = parseDurationMilliseconds(input.access_token_ttl);
  if (accessTokenTTL === null || accessTokenTTL < 5 * 60_000 || accessTokenTTL > 24 * 3_600_000) {
    return { field: 'lifecycle-access-token-ttl', message: 'Access Token 有效期须在 5 分钟至 24 小时之间。' };
  }
  const refreshTokenTTL = parseDurationMilliseconds(input.refresh_token_ttl);
  if (refreshTokenTTL === null || refreshTokenTTL < 3_600_000 || refreshTokenTTL > 8_760 * 3_600_000) {
    return { field: 'lifecycle-refresh-token-ttl', message: 'Refresh Token 有效期须在 1 小时至 8760 小时之间。' };
  }
  const authorizationCodeTTL = parseDurationMilliseconds(input.authorization_code_ttl);
  if (authorizationCodeTTL === null || authorizationCodeTTL < 30_000 || authorizationCodeTTL > 10 * 60_000) {
    return { field: 'lifecycle-authorization-code-ttl', message: '授权码有效期须在 30 秒至 10 分钟之间。' };
  }
  if (!Number.isSafeInteger(input.audit_retention_days)
    || input.audit_retention_days < 7
    || input.audit_retention_days > 3_650) {
    return { field: 'lifecycle-audit-retention', message: '审计保留天数须为 7 至 3650 的整数。' };
  }
  return null;
}

export function validateLifecycleSettings(input: UpdateLifecycleSettingsInput): string {
  return lifecycleValidationError(input)?.message ?? '';
}

export function oauthPolicyValidationError(input: UpdateOAuthSettingsInput): FieldValidationError | null {
  const grants = new Set(input.allowed_grant_types);
  const scopes = new Set(input.allowed_scopes);
  if (grants.size !== input.allowed_grant_types.length || input.allowed_grant_types.length === 0
    || input.allowed_grant_types.some((grant) => !OAUTH_GRANT_TYPES.includes(grant))) {
    return { field: 'oauth-grants', message: '至少选择一种受支持的 Grant，且不能重复。' };
  }
  if (scopes.size !== input.allowed_scopes.length
    || input.allowed_scopes.some((scope) => !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope))) {
    return { field: 'oauth-scopes', message: 'Scope 不能重复，且必须是符合 OAuth 2.0 的可见 ASCII scope-token。' };
  }
  for (const scope of input.allowed_scopes) {
    const definition = input.scope_definitions[scope];
    if (!definition || !definition.display_name.trim() || !definition.description.trim()) {
      return { field: 'oauth-scopes', message: `Scope ${scope} 需要完整的名称和授权说明。` };
    }
    if (definition.display_name.length > 80 || definition.description.length > 300) {
      return { field: 'oauth-scopes', message: `Scope ${scope} 的名称或说明过长。` };
    }
    if (!['self_service', 'admin_only'].includes(definition.assignment_policy)
      || !['low', 'personal_data', 'sensitive'].includes(definition.risk_level)) {
      return { field: 'oauth-scopes', message: `Scope ${scope} 的分配策略或风险等级无效。` };
    }
    const claimSet = new Set(definition.claims);
    if (claimSet.size !== definition.claims.length
      || definition.claims.some((claim) => !OAUTH_CLAIMS.includes(claim as typeof OAUTH_CLAIMS[number]))) {
      return { field: 'oauth-scopes', message: `Scope ${scope} 包含不受支持或重复的 Claim。` };
    }
  }
  for (const claim of OAUTH_CLAIMS) {
    if (!['self_service', 'admin_only'].includes(input.claim_assignment_policies[claim])) {
      return { field: 'oauth-scopes', message: `Claim ${claim} 缺少有效的分配策略。` };
    }
  }
  if (grants.has('refresh_token') && !grants.has('authorization_code')) {
    return { field: 'oauth-grants', message: '允许 Refresh Token 时必须同时允许 Authorization Code。' };
  }
  if (scopes.has('offline_access') && !grants.has('refresh_token')) {
    return { field: 'oauth-scopes', message: '允许 offline_access 时必须同时允许 Refresh Token。' };
  }
  if (input.public_clients_enabled && !grants.has('authorization_code')) {
    return { field: 'oauth-public-clients', message: '允许 Public Client 时必须同时允许 Authorization Code。' };
  }
  if (!Number.isSafeInteger(input.max_redirect_uris)
    || input.max_redirect_uris < 1 || input.max_redirect_uris > 100) {
    return { field: 'oauth-max-redirects', message: 'Redirect URI 上限须为 1 至 100 的整数。' };
  }
  if (!Number.isSafeInteger(input.max_post_logout_redirect_uris)
    || input.max_post_logout_redirect_uris < 0 || input.max_post_logout_redirect_uris > 100) {
    return { field: 'oauth-max-logouts', message: 'Post-logout Redirect URI 上限须为 0 至 100 的整数。' };
  }
  return null;
}

export function oauthSettingsFromInput(
  input: UpdateOAuthSettingsInput,
  revision = input.expected_revision,
): OAuthSettings {
  return {
    revision,
    self_service_client_creation_enabled: input.self_service_client_creation_enabled,
    public_clients_enabled: input.public_clients_enabled,
    allowed_grant_types: [...input.allowed_grant_types],
    allowed_scopes: [...input.allowed_scopes],
    scope_definitions: cloneScopeDefinitions(input.scope_definitions),
    claim_assignment_policies: { ...input.claim_assignment_policies },
    max_redirect_uris: input.max_redirect_uris,
    max_post_logout_redirect_uris: input.max_post_logout_redirect_uris,
  };
}

export function protectionSettingsFromInput(
  input: UpdateProtectionSettingsInput,
  revision = input.expected_revision,
): ProtectionSettings {
  return {
    revision,
    login: { ...input.login },
    account: { ...input.account },
    avatar: { ...input.avatar },
    mail: { ...input.mail },
    owned_client_default_limit: input.owned_client_default_limit,
  };
}

export function lifecycleSettingsFromInput(
  input: UpdateLifecycleSettingsInput,
  revision = input.expected_revision,
): LifecycleSettings {
  return {
    revision,
    session_absolute_ttl: input.session_absolute_ttl,
    session_idle_ttl: input.session_idle_ttl,
    max_concurrent_sessions: input.max_concurrent_sessions,
    recent_authentication_ttl: input.recent_authentication_ttl,
    access_token_ttl: input.access_token_ttl,
    refresh_token_ttl: input.refresh_token_ttl,
    authorization_code_ttl: input.authorization_code_ttl,
    audit_retention_days: input.audit_retention_days,
  };
}
