import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  api,
  ApiError,
  buildAuditLogExportURL,
  isMFARequiredResponse,
  isAPIErrorCode,
  localizeAPIErrorMessage,
  missingAdminsFromError,
  setCsrfToken,
  type MFARequiredResponse,
  type SessionInfo,
} from './api';
import { PASSWORD_REQUIREMENT } from './password-policy';

describe('localizeAPIErrorMessage', () => {
  it.each([
    'invalid input: password must be valid UTF-8 and 12 to 1024 bytes',
    'invalid account request: password must be valid UTF-8 and 12 to 1024 bytes',
  ])('maps the backend password policy error to the shared Chinese requirement', (message) => {
    expect(localizeAPIErrorMessage(message)).toBe(PASSWORD_REQUIREMENT);
  });

  it.each([
    ['invalid credentials', '认证凭据不正确'],
    ['current password is incorrect', '当前密码不正确'],
    ['recent authentication is required', '请先完成近期身份验证'],
    ['password reauthentication is unavailable', '此账户无法使用密码重新认证'],
    ['a local password is already configured', '此账户已设置本地密码'],
    ['csrf_validation_failed', '安全校验失败，请刷新页面后重试'],
    ['invalid CSRF token', '安全校验失败，请刷新页面后重试'],
    ['password change required', '请先修改密码后再继续'],
    ['registration is temporarily unavailable', '注册功能暂时不可用，请稍后重试'],
    ['mail settings changed; reload and try again', '邮件设置已被其他管理员修改，请重新加载后再试'],
    ['a successful candidate test is required', '激活前必须先成功发送候选配置的测试邮件'],
    ['close self-registration before disabling mail', '禁用邮件服务前必须先关闭自助注册'],
    ['invalid MFA code', '验证码或恢复码不正确'],
    ['MFA challenge expired', '多因素验证已过期，请重新登录'],
    ['TOTP enrollment is disabled', '管理员已关闭动态验证码注册'],
    ['MFA is required for active administrators', '管理员策略要求保留多因素验证，当前无法停用'],
    ['Passkey registered; please sign in again', 'Passkey 已注册，但当前会话无法继续使用，请重新登录'],
    ['Passkey removed; please sign in again', 'Passkey 已删除，但当前会话无法继续使用，请重新登录'],
  ])('maps stable authentication error %s', (message, expected) => {
    expect(localizeAPIErrorMessage(message)).toBe(expected);
  });

  it('preserves unrelated API errors', () => {
    expect(localizeAPIErrorMessage('provider temporarily unavailable')).toBe('provider temporarily unavailable');
  });

  it('localizes by stable error code when backend wording changes', () => {
    expect(localizeAPIErrorMessage('wording changed', 'auth.recent_authentication_required')).toBe('请先完成近期身份验证');
    expect(localizeAPIErrorMessage('wording changed', 'account.password_change_required')).toBe('请先修改密码后再继续');
    expect(localizeAPIErrorMessage('wording changed', 'service_control.registration_conflict')).toBe('当前运行控制状态不允许启用该注册策略，请先调整注册或邮件投递能力');
    expect(localizeAPIErrorMessage('wording changed', 'settings.revision_conflict')).toBe('设置已被其他管理员修改，请加载最新设置后重试');
    expect(localizeAPIErrorMessage('wording changed', 'media.instances_not_ready')).toBe('仍有运行实例尚未加载候选配置，请稍后重试');
  });

  it('uses a Chinese fallback for an unknown coded backend error', () => {
    expect(localizeAPIErrorMessage('new backend wording', 'request_failed')).toBe('请求失败，请稍后重试');
  });

  it('matches control-flow errors by code instead of server wording', () => {
    const error = new ApiError('本地化消息', 400, undefined, 'wording changed', { code: 'mfa.challenge_expired' }, 'mfa.challenge_expired');
    expect(isAPIErrorCode(error, 'mfa.challenge_expired')).toBe(true);
  });
});

describe('MFA API contract', () => {
  const mfaRequired: MFARequiredResponse = {
    status: 'mfa_required',
    purpose: 'login',
    username: 'alice',
    methods: ['totp', 'recovery_code', 'passkey'],
    csrf_token: 'mfa-csrf',
    expires_at: '2026-07-27T12:05:00Z',
  };

  const session: SessionInfo = {
    user: {
      id: '11111111-1111-1111-1111-111111111111',
      username: 'alice',
      email: 'alice@example.com',
      display_name: 'Alice',
      role: 'user',
      status: 'active',
      created_at: '2026-01-01T00:00:00Z',
    },
    csrf_token: 'session-csrf',
    must_change_password: false,
    has_password: true,
    email_verified: true,
    authenticated_at: '2026-07-27T12:00:00Z',
  };

  beforeEach(() => setCsrfToken(''));

  afterEach(() => {
    setCsrfToken('');
    vi.unstubAllGlobals();
  });

  it('sends return_to, narrows the 202 response, and explicitly uses pending CSRF for verification', async () => {
    const responses = [
      new Response(JSON.stringify(mfaRequired), { status: 202, headers: { 'Content-Type': 'application/json' } }),
      new Response(JSON.stringify(session), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    ];
    const fetchMock = vi.fn(async () => responses.shift()!);
    vi.stubGlobal('fetch', fetchMock);

    const result = await api.login('alice', 'correct horse battery staple', '/authorize?client_id=demo');
    expect(isMFARequiredResponse(result)).toBe(true);

    const [, loginInit] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(JSON.parse(String(loginInit.body))).toEqual({
      username: 'alice',
      password: 'correct horse battery staple',
      return_to: '/authorize?client_id=demo',
    });

    await api.verifyLoginMFA('recovery_code', 'ABCDEFGH-234567ABCDEFGH', mfaRequired.csrf_token);
    const [, verifyInit] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(new Headers(verifyInit.headers).get('X-CSRF-Token')).toBe('mfa-csrf');
    expect(JSON.parse(String(verifyInit.body))).toEqual({
      method: 'recovery_code',
      code: 'ABCDEFGH-234567ABCDEFGH',
    });
  });

  it('does not replace or clear the formal-session CSRF during a reauthentication challenge', async () => {
    const challenge: MFARequiredResponse = {
      ...mfaRequired,
      purpose: 'reauthentication',
      csrf_token: 'reauth-mfa-csrf',
    };
    const responses = [
      new Response(JSON.stringify(challenge), { status: 202, headers: { 'Content-Type': 'application/json' } }),
      new Response(null, { status: 204 }),
      new Response(JSON.stringify(session.user), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    ];
    const fetchMock = vi.fn(async () => responses.shift()!);
    vi.stubGlobal('fetch', fetchMock);
    setCsrfToken('formal-session-csrf');

    const result = await api.reauthenticateWithPassword('current password');
    expect(isMFARequiredResponse(result)).toBe(true);
    await api.cancelLoginMFA(challenge.csrf_token);
    await api.updateMe({ display_name: 'Alice' });

    const [, reauthInit] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(new Headers(reauthInit.headers).get('X-CSRF-Token')).toBe('formal-session-csrf');
    const [, cancelInit] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(new Headers(cancelInit.headers).get('X-CSRF-Token')).toBe('reauth-mfa-csrf');
    const [, updateInit] = fetchMock.mock.calls[2] as unknown as [string, RequestInit];
    expect(new Headers(updateInit.headers).get('X-CSRF-Token')).toBe('formal-session-csrf');
  });

  it('preserves missing_admins from a structured security-settings error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      error: 'all active administrators must enroll MFA before it can be required',
      missing_admins: ['admin-a', 'admin-b', 42],
    }), { status: 409, headers: { 'Content-Type': 'application/json' } })));

    let caught: unknown;
    try {
      await api.admin.updateSecuritySettings({ expected_revision: 3, totp_enabled: true, passkeys_enabled: true, require_mfa_for_admins: true });
    } catch (cause) {
      caught = cause;
    }

    expect(missingAdminsFromError(caught)).toEqual(['admin-a', 'admin-b']);
  });

  it('uses the public Passkey login routes and sends the ceremony only in its header', async () => {
    const options = {
      ceremony_id: 'login-ceremony',
      public_key: { challenge: 'AQID', rpId: 'localhost' },
      mediation: 'required',
      expires_at: '2026-07-27T12:05:00Z',
    };
    const credential = { id: 'credential-id', type: 'public-key', response: { signature: 'BAUG' } };
    const responses = [
      new Response(JSON.stringify(options), { status: 200, headers: { 'Content-Type': 'application/json' } }),
      new Response(JSON.stringify(session), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    ];
    const fetchMock = vi.fn(async () => responses.shift()!);
    vi.stubGlobal('fetch', fetchMock);

    await api.beginPasskeyLogin(true, '/dashboard');
    await api.finishPasskeyLogin(options.ceremony_id, credential);

    const [, beginInit] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(JSON.parse(String(beginInit.body))).toEqual({ conditional: true, return_to: '/dashboard' });
    const [, finishInit] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    const finishHeaders = new Headers(finishInit.headers);
    expect(finishHeaders.get('X-WebAuthn-Ceremony')).toBe('login-ceremony');
    expect(finishHeaders.get('X-CSRF-Token')).toBeNull();
    expect(JSON.parse(String(finishInit.body))).toEqual(credential);
  });

  it('sends both pending CSRF and ceremony headers for Passkey MFA', async () => {
    const options = {
      ceremony_id: 'mfa-ceremony',
      public_key: { challenge: 'AQID' },
      mediation: 'required',
      expires_at: '2026-07-27T12:05:00Z',
    };
    const credential = { id: 'credential-id', type: 'public-key', response: { signature: 'BAUG' } };
    const responses = [
      new Response(JSON.stringify(options), { status: 200, headers: { 'Content-Type': 'application/json' } }),
      new Response(JSON.stringify(session), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    ];
    const fetchMock = vi.fn(async () => responses.shift()!);
    vi.stubGlobal('fetch', fetchMock);
    setCsrfToken('formal-session-csrf');

    await api.beginMFAPasskey('pending-mfa-csrf');
    await api.finishMFAPasskey(options.ceremony_id, credential, 'pending-mfa-csrf');

    const calls = fetchMock.mock.calls as unknown as Array<[string, RequestInit]>;
    for (const [, init] of calls) {
      const headers = new Headers(init.headers);
      expect(headers.get('X-CSRF-Token')).toBe('pending-mfa-csrf');
    }
    const finishHeaders = new Headers(calls[1][1].headers);
    expect(finishHeaders.get('X-WebAuthn-Ceremony')).toBe('mfa-ceremony');
  });

  it('matches Passkey management and reauthentication routes exactly', async () => {
    const options = {
      ceremony_id: 'ceremony-id',
      public_key: { challenge: 'AQID' },
      expires_at: '2026-07-27T12:05:00Z',
    };
    const passkey = {
      id: '22222222-2222-2222-2222-222222222222',
      name: 'Laptop',
      transports: ['internal'],
      backup_eligible: true,
      backup_state: true,
      clone_warning: false,
      created_at: '2026-07-27T12:00:00Z',
    };
    const responses = [
      new Response(JSON.stringify({ passkeys: [passkey] }), { status: 200, headers: { 'Content-Type': 'application/json' } }),
      new Response(JSON.stringify(options), { status: 200, headers: { 'Content-Type': 'application/json' } }),
      new Response(JSON.stringify({ ...session, passkey }), { status: 200, headers: { 'Content-Type': 'application/json' } }),
      new Response(JSON.stringify(passkey), { status: 200, headers: { 'Content-Type': 'application/json' } }),
      new Response(JSON.stringify(session), { status: 200, headers: { 'Content-Type': 'application/json' } }),
      new Response(JSON.stringify(options), { status: 200, headers: { 'Content-Type': 'application/json' } }),
      new Response(JSON.stringify(session), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    ];
    const fetchMock = vi.fn(async () => responses.shift()!);
    vi.stubGlobal('fetch', fetchMock);
    const credential = { id: 'credential-id', type: 'public-key', response: {} };

    await api.getMyPasskeys();
    await api.beginPasskeyRegistration('Laptop');
    await api.finishPasskeyRegistration('ceremony-id', credential);
    await api.renamePasskey(passkey.id, 'Security key');
    await api.deletePasskey(passkey.id);
    await api.beginPasskeyReauthentication();
    await api.finishPasskeyReauthentication('ceremony-id', credential);

    const calls = fetchMock.mock.calls as unknown as Array<[string, RequestInit]>;
    expect(calls.map(([url]) => url)).toEqual([
      '/api/me/passkeys',
      '/api/me/passkeys/registration/options',
      '/api/me/passkeys/registration/verify',
      `/api/me/passkeys/${passkey.id}`,
      `/api/me/passkeys/${passkey.id}`,
      '/api/me/reauth/passkey/options',
      '/api/me/reauth/passkey/verify',
    ]);
    expect(JSON.parse(String(calls[1][1].body))).toEqual({ name: 'Laptop' });
    expect(new Headers(calls[2][1].headers).get('X-WebAuthn-Ceremony')).toBe('ceremony-id');
    expect(calls[3][1].method).toBe('PUT');
    expect(calls[4][1].method).toBe('DELETE');
  });

  it('returns a purpose-tagged MFA challenge from password reauthentication', async () => {
    const challenge: MFARequiredResponse = {
      ...mfaRequired,
      purpose: 'reauthentication',
      csrf_token: 'reauth-mfa-csrf',
    };
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(challenge), {
      status: 202,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await api.reauthenticateWithPassword('current password');
    expect(isMFARequiredResponse(result)).toBe(true);
    if (isMFARequiredResponse(result)) expect(result.purpose).toBe('reauthentication');

    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(JSON.parse(String(init.body))).toEqual({ password: 'current password' });
  });
});

describe('avatar API contract', () => {
  const user = {
    id: '11111111-1111-1111-1111-111111111111',
    username: 'alice',
    role: 'user' as const,
    status: 'active' as const,
    created_at: '2026-01-01T00:00:00Z',
  };

  afterEach(() => {
    setCsrfToken('');
    vi.unstubAllGlobals();
  });

  it('uses multipart without overriding the boundary and returns updated users for deletion', async () => {
    const responses = Array.from({ length: 4 }, () => new Response(JSON.stringify(user), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
    const fetchMock = vi.fn(async () => responses.shift()!);
    vi.stubGlobal('fetch', fetchMock);
    setCsrfToken('avatar-csrf');
    const blob = new Blob(['webp'], { type: 'image/webp' });

    await api.uploadAvatar(blob);
    await api.removeAvatar();
    await api.admin.uploadUserAvatar(user.id, blob);
    await api.admin.removeUserAvatar(user.id);

    const calls = fetchMock.mock.calls as unknown as Array<[string, RequestInit]>;
    expect(calls.map(([url]) => url)).toEqual([
      '/api/me/avatar',
      '/api/me/avatar',
      `/api/admin/users/${user.id}/avatar`,
      `/api/admin/users/${user.id}/avatar`,
    ]);
    expect(calls.map(([, init]) => init.method)).toEqual(['POST', 'DELETE', 'POST', 'DELETE']);
    for (const index of [0, 2]) {
      const init = calls[index][1];
      expect(init.body).toBeInstanceOf(FormData);
      expect((init.body as FormData).get('avatar')).toBeInstanceOf(Blob);
      expect(new Headers(init.headers).get('Content-Type')).toBeNull();
    }
    for (const [, init] of calls) {
      expect(new Headers(init.headers).get('X-CSRF-Token')).toBe('avatar-csrf');
    }
  });
});

describe('admin user insights API contract', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('uses the dedicated, encoded detail endpoints and preserves pagination', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify({ items: [], total: 0, page: 2, page_size: 10, total_pages: 0 }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);
    const id = 'user id/with separators';

    await api.admin.getUserOverview(id);
    await api.admin.getUserSecurity(id);
    await api.admin.getUserAuthorizations(id);
    await api.admin.getUserClients(id, 2, 10);
    await api.admin.updateUserClientQuota(id, 25);
    await api.admin.updateUserClientQuota(id, null);
    await api.admin.getUserActivity(id, 3, 25);

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      '/api/admin/users/user%20id%2Fwith%20separators/overview',
      '/api/admin/users/user%20id%2Fwith%20separators/security',
      '/api/admin/users/user%20id%2Fwith%20separators/authorizations',
      '/api/admin/users/user%20id%2Fwith%20separators/clients?page=2&page_size=10',
      '/api/admin/users/user%20id%2Fwith%20separators/client-quota',
      '/api/admin/users/user%20id%2Fwith%20separators/client-quota',
      '/api/admin/users/user%20id%2Fwith%20separators/activity?page=3&page_size=25',
    ]);
    const calls = fetchMock.mock.calls as unknown as Array<[string, RequestInit]>;
    expect(calls[4][1].method).toBe('PUT');
    expect(calls[4][1].body).toBe(JSON.stringify({ quota_override: 25 }));
    expect(calls[5][1].body).toBe(JSON.stringify({ quota_override: null }));
  });
});

describe('audit API contract', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('uses the options endpoint and maps exact filters to backend parameter names', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const body = url.endsWith('/options')
        ? { events: ['user.login'], results: ['success'], risks: ['low'], target_types: ['user'] }
        : { items: [], total: 0, page: 2, page_size: 25, total_pages: 0 };
      return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
    });
    vi.stubGlobal('fetch', fetchMock);

    await api.admin.getAuditLogOptions();
    await api.admin.getAuditLogs({
      page: 2,
      pageSize: 25,
      events: ['user.login', 'user.logout'],
      result: 'failure',
      risk: 'high',
      actor: 'alice',
      target: 'oauth',
      subjectUserId: 'user/id',
      targetType: 'client',
      targetId: 'client id',
      ip: '192.0.2.10',
      from: '2026-07-27T01:00:00.000Z',
      to: '2026-07-27T02:00:00.000Z',
    });

    expect(fetchMock.mock.calls[0][0]).toBe('/api/admin/audit-logs/options');
    const requestURL = new URL(String(fetchMock.mock.calls[1][0]), 'https://auth.example');
    expect(requestURL.searchParams.getAll('event')).toEqual(['user.login', 'user.logout']);
    expect(Object.fromEntries(Array.from(requestURL.searchParams).filter(([key]) => key !== 'event'))).toEqual({
      page: '2',
      page_size: '25',
      result: 'failure',
      risk: 'high',
      actor: 'alice',
      target: 'oauth',
      subject_user_id: 'user/id',
      target_type: 'client',
      target_id: 'client id',
      ip: '192.0.2.10',
      from: '2026-07-27T01:00:00.000Z',
      to: '2026-07-27T02:00:00.000Z',
    });
  });

  it('builds exports from the same filter mapping without pagination', () => {
    const url = new URL(buildAuditLogExportURL({
      page: 4,
      pageSize: 10,
      subjectUserId: 'subject-user',
      targetType: 'provider',
      targetId: 'github',
      from: '2026-07-01T00:00:00.000Z',
      to: '2026-07-02T00:00:00.000Z',
    }, 'cef'), 'https://auth.example');

    expect(Object.fromEntries(url.searchParams)).toEqual({
      subject_user_id: 'subject-user',
      target_type: 'provider',
      target_id: 'github',
      from: '2026-07-01T00:00:00.000Z',
      to: '2026-07-02T00:00:00.000Z',
      format: 'cef',
      limit: '50000',
    });
  });
});

describe('service control API contract', () => {
  afterEach(() => {
    setCsrfToken('');
    vi.unstubAllGlobals();
  });

  it('uses only the public and management operations endpoints and preserves the revision payload', async () => {
    const publicStatus = {
      status: 'restricted',
      paused_capabilities: ['self_registration'],
      public_message: 'Maintenance',
      expires_at: '2026-07-28T12:00:00Z',
      retry_after_seconds: 60,
    };
    const settings = {
      ...publicStatus,
      revision: 9,
      internal_reason: 'Database maintenance',
      updated_at: '2026-07-28T11:00:00Z',
      updated_by: 'admin-id',
      application_status: 'applied',
      active_instances: 0,
      applied_instances: 0,
      instances: [],
    };
    const responses = [publicStatus, settings, { ...settings, revision: 10 }];
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(responses.shift()), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);
    setCsrfToken('operations-csrf');

    await api.getServiceStatus();
    await api.admin.getOperationsSettings();
    await api.admin.updateOperationsSettings({
      expected_revision: 9,
      paused_capabilities: ['self_registration'],
      public_message: 'Maintenance',
      internal_reason: 'Database maintenance',
      expires_at: '2026-07-28T12:00:00Z',
    });

    const calls = fetchMock.mock.calls as unknown as Array<[string, RequestInit]>;
    expect(calls.map(([url]) => url)).toEqual([
      '/api/service-status',
      '/api/admin/settings/operations',
      '/api/admin/settings/operations',
    ]);
    expect(calls[0][1].cache).toBe('no-store');
    expect(calls[1][1].cache).toBe('no-store');
    expect(calls[2][1].method).toBe('PUT');
    expect(new Headers(calls[2][1].headers).get('X-CSRF-Token')).toBe('operations-csrf');
    expect(JSON.parse(String(calls[2][1].body))).toEqual({
      expected_revision: 9,
      paused_capabilities: ['self_registration'],
      public_message: 'Maintenance',
      internal_reason: 'Database maintenance',
      expires_at: '2026-07-28T12:00:00Z',
    });
  });
});

describe('runtime policy settings API contract', () => {
  afterEach(() => {
    setCsrfToken('');
    vi.unstubAllGlobals();
  });

  it('uses the versioned protection and lifecycle revisions without changing the payload', async () => {
    const protection = {
      revision: 4,
      login: { enabled: true, window: '5m', identity_limit: 5, ip_limit: 30, passkey_ceremony_ip_limit: 120 },
      account: { enabled: true, window: '15m', subject_limit: 5, ip_limit: 20 },
      avatar: { enabled: true, window: '15m', user_limit: 30, ip_limit: 200 },
      mail: { enabled: true, window: '15m', save_limit: 60, test_limit: 30, activate_limit: 30, rollback_limit: 30, disable_limit: 30, ip_limit: 200 },
      owned_client_default_limit: 10,
    };
    const lifecycle = {
      revision: 6,
      session_absolute_ttl: '24h',
      recent_authentication_ttl: '10m',
      audit_retention_days: 365,
    };
    const responses = [protection, { ...protection, revision: 5 }, lifecycle, { ...lifecycle, revision: 7 }];
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(responses.shift()), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);
    setCsrfToken('policy-csrf');

    await api.admin.getProtectionSettings();
    await api.admin.updateProtectionSettings({
      expected_revision: protection.revision,
      login: protection.login,
      account: protection.account,
      avatar: protection.avatar,
      mail: protection.mail,
      owned_client_default_limit: protection.owned_client_default_limit,
      disable_confirmation: 'DISABLE RATE LIMITS',
    });
    await api.admin.getLifecycleSettings();
    await api.admin.updateLifecycleSettings({
      expected_revision: lifecycle.revision,
      session_absolute_ttl: lifecycle.session_absolute_ttl,
      recent_authentication_ttl: lifecycle.recent_authentication_ttl,
      audit_retention_days: 90,
      retention_confirmation: 'RETENTION 90 DAYS',
    });

    const calls = fetchMock.mock.calls as unknown as Array<[string, RequestInit]>;
    expect(calls.map(([url]) => url)).toEqual([
      '/api/admin/settings/protection',
      '/api/admin/settings/protection',
      '/api/admin/settings/lifecycle',
      '/api/admin/settings/lifecycle',
    ]);
    expect(calls[0][1].cache).toBe('no-store');
    expect(calls[2][1].cache).toBe('no-store');
    for (const index of [1, 3]) {
      expect(calls[index][1].method).toBe('PUT');
      expect(new Headers(calls[index][1].headers).get('X-CSRF-Token')).toBe('policy-csrf');
    }
    expect(JSON.parse(String(calls[1][1].body))).toMatchObject({
      expected_revision: 4,
      disable_confirmation: 'DISABLE RATE LIMITS',
    });
    expect(JSON.parse(String(calls[3][1].body))).toEqual({
      expected_revision: 6,
      session_absolute_ttl: '24h',
      recent_authentication_ttl: '10m',
      audit_retention_days: 90,
      retention_confirmation: 'RETENTION 90 DAYS',
    });
  });
});

describe('runtime media storage API contract', () => {
  afterEach(() => {
    setCsrfToken('');
    vi.unstubAllGlobals();
  });

  it('uses revisioned media endpoints without exposing credentials in response types', async () => {
    const profile = {
      id: '22222222-2222-2222-2222-222222222222',
      backend: 's3',
      settings: {
        endpoint: 'https://s3.example.test',
        region: 'auto',
        bucket: 'private-media',
        prefix: 'nyauth',
        path_style: true,
      },
      credentials_configured: true,
      session_token_configured: false,
      created_by_name: 'admin',
      created_at: '2026-07-29T01:00:00Z',
    };
    const migration = {
      id: '33333333-3333-3333-3333-333333333333',
      source_backend: 'local',
      target_profile_id: profile.id,
      target_backend: 's3',
      status: 'running',
      total_count: 2,
      copied_count: 1,
      completed_count: 1,
      failed_count: 0,
      created_by_name: 'admin',
      created_at: '2026-07-29T01:05:00Z',
      updated_at: '2026-07-29T01:06:00Z',
    };
    const responses = [
      { mode: 'fallback', revision: 1, available: true, active: { backend: 'local', credentials_configured: true }, fallback: { backend: 'local', credentials_configured: true } },
      { candidate: profile, revision: 2 },
      { candidate: { ...profile, test_result: 'success' }, revision: 3, result: 'success' },
      { migration, revision: 3 },
      { migration: { ...migration, source_backend: 's3', target_profile_id: undefined, target_backend: 'local' }, revision: 4 },
      { migration: { ...migration, status: 'pending' } },
    ];
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(responses.shift()), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);
    setCsrfToken('media-csrf');

    await api.admin.getMediaSettings();
    await api.admin.saveMediaCandidate({
      expected_revision: 1,
      ...profile.settings,
      access_key_id: 'access-key',
      secret_access_key: 'secret-key',
      session_token: '',
    });
    await api.admin.testMediaCandidate(2, profile.id);
    await api.admin.startMediaMigration(3, profile.id);
    await api.admin.migrateMediaToLocalFallback(4);
    await api.admin.retryMediaMigration(migration.id);

    const calls = fetchMock.mock.calls as unknown as Array<[string, RequestInit]>;
    expect(calls.map(([url]) => url)).toEqual([
      '/api/admin/settings/media',
      '/api/admin/settings/media/candidate',
      '/api/admin/settings/media/candidate/test',
      '/api/admin/settings/media/migrations',
      '/api/admin/settings/media/fallback/migrate',
      `/api/admin/settings/media/migrations/${migration.id}/retry`,
    ]);
    expect(calls[0][1].cache).toBe('no-store');
    expect(JSON.parse(String(calls[1][1].body))).toEqual({
      expected_revision: 1,
      ...profile.settings,
      access_key_id: 'access-key',
      secret_access_key: 'secret-key',
      session_token: '',
    });
    expect(JSON.parse(String(calls[2][1].body))).toEqual({ expected_revision: 2, profile_id: profile.id });
    expect(JSON.parse(String(calls[3][1].body))).toEqual({ expected_revision: 3, profile_id: profile.id });
    expect(JSON.parse(String(calls[4][1].body))).toEqual({ expected_revision: 4 });
    expect(calls[5][1].method).toBe('POST');
    for (const index of [1, 2, 3, 4, 5]) {
      expect(new Headers(calls[index][1].headers).get('X-CSRF-Token')).toBe('media-csrf');
    }
  });
});
