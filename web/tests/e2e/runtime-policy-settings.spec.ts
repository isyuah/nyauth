import { expect, test, type Page, type Route } from '@playwright/test';
import type {
  AdminUserClientSummary,
  AdminUserOverview,
  ClientQuota,
  ClientQuotaPage,
  LifecycleSettings,
  MyClientPage,
  OAuthClient,
  OAuthSettings,
  ProtectionSettings,
  ServiceStatus,
  SessionInfo,
  UpdateLifecycleSettingsInput,
  UpdateOAuthSettingsInput,
  UpdateProtectionSettingsInput,
  User,
} from '../../src/lib/api';
import { DEFAULT_CLAIM_ASSIGNMENT_POLICIES, DEFAULT_SCOPE_DEFINITIONS } from '../../src/lib/oauth-catalog';

const adminID = '11111111-1111-1111-1111-111111111111';
const targetUserID = '22222222-2222-2222-2222-222222222222';

const normalServiceStatus: ServiceStatus = {
  status: 'normal',
  paused_capabilities: [],
  public_message: '',
  expires_at: null,
  retry_after_seconds: 0,
};

const adminUser: User = {
  id: adminID,
  username: 'admin',
  email: 'admin@example.test',
  display_name: 'Admin',
  role: 'admin',
  status: 'active',
  created_at: '2026-01-01T00:00:00Z',
};

const targetUser: User = {
  id: targetUserID,
  username: 'alice',
  email: 'alice@example.test',
  display_name: 'Alice',
  role: 'user',
  status: 'active',
  created_at: '2026-01-02T00:00:00Z',
};

const protectionSettings: ProtectionSettings = {
  revision: 7,
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

const lifecycleSettings: LifecycleSettings = {
  revision: 4,
  session_absolute_ttl: '24h',
  session_idle_ttl: '12h',
  max_concurrent_sessions: 5,
  recent_authentication_ttl: '10m',
  access_token_ttl: '1h',
  refresh_token_ttl: '720h',
  authorization_code_ttl: '5m',
  audit_retention_days: 365,
};

const oauthSettings: OAuthSettings = {
  revision: 5,
  self_service_client_creation_enabled: true,
  public_clients_enabled: true,
  allowed_grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
  allowed_scopes: ['openid', 'profile', 'email', 'offline_access'],
  scope_definitions: DEFAULT_SCOPE_DEFINITIONS,
  claim_assignment_policies: DEFAULT_CLAIM_ASSIGNMENT_POLICIES,
  max_redirect_uris: 20,
  max_post_logout_redirect_uris: 20,
};

const ownedClient: OAuthClient = {
  id: 'quota-client',
  name: 'Quota Client',
  homepage_uri: '',
  privacy_policy_uri: '',
  terms_of_service_uri: '',
  current_logo_id: null,
  logo_url: null,
  identity_revision: 1,
  authorization_revision: 1,
  redirect_uris: ['https://client.example.test/callback'],
  post_logout_redirect_uris: [],
  grants: ['authorization_code', 'refresh_token'],
  scopes: ['openid', 'profile'],
  optional_scopes: [],
  allowed_claims: ['sub', 'preferred_username', 'name', 'picture'],
  is_public: false,
  secret_hint: 'abcd1234',
  secret_version: 1,
  secret_rotated_at: '2026-01-03T00:00:00Z',
  owner_id: targetUserID,
  publisher_type: 'user_registered',
  publisher_verification_status: 'unverified',
  created_at: '2026-01-03T00:00:00Z',
  updated_at: '2026-01-03T00:00:00Z',
};

const targetOverview: AdminUserOverview = {
  user: targetUser,
  creation_source: 'admin',
  created_by: {
    id: adminID,
    username: adminUser.username,
    display_name: adminUser.display_name,
  },
  self_registration: null,
};

type RouteHandler = (route: Route, path: string, method: string) => Promise<boolean>;

async function json(route: Route, status: number, body: unknown) {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

function sessionFor(role: 'admin' | 'user'): SessionInfo {
  return {
    user: role === 'admin' ? adminUser : targetUser,
    csrf_token: `runtime-policy-${role}-csrf`,
    must_change_password: false,
    has_password: true,
    email_verified: true,
    authenticated_at: '2026-07-29T09:00:00Z',
    session_expires_at: '2099-07-30T09:00:00Z',
    recent_authentication_expires_at: '2099-07-29T09:10:00Z',
  };
}

async function installAPIMocks(
  page: Page,
  role: 'admin' | 'user',
  handle: RouteHandler,
) {
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();

    if (path === '/api/service-status' && method === 'GET') {
      await json(route, 200, normalServiceStatus);
      return;
    }
    if (path === '/api/branding' && method === 'GET') {
      await json(route, 200, { title: 'Nya', primary_color: '#704DE8', primary_text_color: 'auto', light_logo_url: '', dark_logo_url: '', favicon_url: '' });
      return;
    }
    if (path === '/api/session' && method === 'GET') {
      await json(route, 200, sessionFor(role));
      return;
    }
    if (await handle(route, path, method)) return;
    await json(route, 404, { error: `unmocked request: ${method} ${path}` });
  });
}

function protectionResponse(input: UpdateProtectionSettingsInput): ProtectionSettings {
  return {
    revision: input.expected_revision + 1,
    login: input.login,
    account: input.account,
    avatar: input.avatar,
    mail: input.mail,
    owned_client_default_limit: input.owned_client_default_limit,
  };
}

test('protection presets require the exact disable phrase and save the expected revision', async ({ page }) => {
  const bodies: UpdateProtectionSettingsInput[] = [];
  await installAPIMocks(page, 'admin', async (route, path, method) => {
    if (path !== '/api/admin/settings/protection') return false;
    if (method === 'GET') {
      await json(route, 200, protectionSettings);
      return true;
    }
    if (method === 'PUT') {
      const body = route.request().postDataJSON() as UpdateProtectionSettingsInput;
      bodies.push(body);
      await json(route, 200, protectionResponse(body));
      return true;
    }
    return false;
  });

  await page.goto('/admin/settings/protection');
  await expect(page.getByRole('heading', { name: '访问保护', exact: true })).toBeVisible();
  await page.getByRole('button', { name: /^严格/ }).click();
  await page.getByRole('button', { name: '展开高级字段' }).click();
  await expect(page.getByRole('spinbutton', { name: '身份次数', exact: true })).toHaveValue('3');
  await expect(page.locator('#protection-login-ip')).toHaveValue('15');

  await page.getByRole('switch', { name: '启用登录限流' }).click();
  await page.getByRole('button', { name: '保存访问保护设置' }).click();
  await expect(page.locator('#protection-disable-confirmation-error')).toContainText('DISABLE RATE LIMITS');
  expect(bodies).toHaveLength(0);

  await page.getByLabel('输入“DISABLE RATE LIMITS”以确认').fill('DISABLE RATE LIMITS');
  await page.getByRole('button', { name: '保存访问保护设置' }).click();
  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies[0]).toMatchObject({
    expected_revision: 7,
    login: {
      enabled: false,
      window: '5m',
      identity_limit: 3,
      ip_limit: 15,
      passkey_ceremony_ip_limit: 60,
    },
    account: { enabled: true, subject_limit: 3, ip_limit: 10 },
    avatar: { enabled: true, user_limit: 15, ip_limit: 100 },
    mail: {
      enabled: true,
      save_limit: 30,
      test_limit: 15,
      activate_limit: 15,
      rollback_limit: 15,
      disable_limit: 15,
      ip_limit: 100,
    },
    owned_client_default_limit: 10,
    disable_confirmation: 'DISABLE RATE LIMITS',
  });
});

test('protection revision conflicts preserve the draft and offer an explicit reload', async ({ page }) => {
  await installAPIMocks(page, 'admin', async (route, path, method) => {
    if (path !== '/api/admin/settings/protection') return false;
    if (method === 'GET') {
      await json(route, 200, protectionSettings);
      return true;
    }
    if (method === 'PUT') {
      await json(route, 409, {
        code: 'settings.revision_conflict',
        error: 'settings revision conflict',
      });
      return true;
    }
    return false;
  });

  await page.goto('/admin/settings/protection');
  await page.getByRole('spinbutton', { name: '自助客户端全局默认配额', exact: true }).fill('23');
  await page.getByRole('button', { name: '保存访问保护设置' }).click();

  await expect(page.getByRole('alert')).toContainText('当前表单草稿已保留');
  await expect(page.getByRole('button', { name: '加载最新设置' })).toBeVisible();
  await expect(page.getByRole('spinbutton', { name: '自助客户端全局默认配额', exact: true })).toHaveValue('23');
});

test('protection validation opens the field, focuses it and exposes reusable help', async ({ page }) => {
  await installAPIMocks(page, 'admin', async (route, path, method) => {
    if (path === '/api/admin/settings/protection' && method === 'GET') {
      await json(route, 200, protectionSettings);
      return true;
    }
    return false;
  });

  await page.goto('/admin/settings/protection');
  await page.getByRole('button', { name: '展开高级字段' }).click();
  const helpButton = page.getByRole('button', { name: '查看“身份次数”说明' });
  await helpButton.click();
  await expect(page.getByRole('tooltip')).toContainText('跨 IP 共享额度');
  await helpButton.press('Escape');
  await expect(page.getByRole('tooltip')).toHaveCount(0);

  await page.getByRole('textbox', { name: '窗口', exact: true }).first().fill('1s');
  await page.getByRole('button', { name: '收起高级字段' }).click();
  await page.getByRole('button', { name: '保存访问保护设置' }).click();

  await expect(page.getByText('登录限流窗口须在 10 秒至 24 小时之间。').first()).toBeVisible();
  await expect(page.getByRole('button', { name: '收起高级字段' })).toBeVisible();
  await expect(page.locator('#protection-login-window')).toBeFocused();
  await expect(page.locator('#protection-login-window')).toHaveAttribute('aria-invalid', 'true');
});

test('rate-limit warning disappears immediately after the disabled group is enabled', async ({ page }) => {
  let current: ProtectionSettings = {
    ...protectionSettings,
    avatar: { ...protectionSettings.avatar, enabled: false },
  };
  await installAPIMocks(page, 'admin', async (route, path, method) => {
    if (path !== '/api/admin/settings/protection') return false;
    if (method === 'GET') {
      await json(route, 200, current);
      return true;
    }
    if (method === 'PUT') {
      const input = route.request().postDataJSON() as UpdateProtectionSettingsInput;
      current = protectionResponse(input);
      await json(route, 200, current);
      return true;
    }
    return false;
  });

  await page.goto('/admin/settings/protection');
  await expect(page.getByText('头像限流已关闭')).toBeVisible();
  await page.getByRole('switch', { name: '启用图片写入限流' }).click();
  await page.getByRole('button', { name: '保存访问保护设置' }).click();

  await expect(page.getByText('访问保护设置已保存，立即对所有实例生效。')).toBeVisible();
  await expect(page.getByText('头像限流已关闭')).toHaveCount(0);
});

test('lifecycle retention shortening requires the exact phrase and preserves the CAS contract', async ({ page }) => {
  const bodies: UpdateLifecycleSettingsInput[] = [];
  await installAPIMocks(page, 'admin', async (route, path, method) => {
    if (path !== '/api/admin/settings/lifecycle') return false;
    if (method === 'GET') {
      await json(route, 200, lifecycleSettings);
      return true;
    }
    if (method === 'PUT') {
      const body = route.request().postDataJSON() as UpdateLifecycleSettingsInput;
      bodies.push(body);
      await json(route, 200, {
        revision: body.expected_revision + 1,
        session_absolute_ttl: body.session_absolute_ttl,
        session_idle_ttl: body.session_idle_ttl,
        max_concurrent_sessions: body.max_concurrent_sessions,
        recent_authentication_ttl: body.recent_authentication_ttl,
        access_token_ttl: body.access_token_ttl,
        refresh_token_ttl: body.refresh_token_ttl,
        authorization_code_ttl: body.authorization_code_ttl,
        audit_retention_days: body.audit_retention_days,
      } satisfies LifecycleSettings);
      return true;
    }
    return false;
  });

  await page.goto('/admin/settings/lifecycle');
  await expect(page.getByRole('heading', { name: '生命周期', exact: true })).toBeVisible();
  await page.getByRole('spinbutton', { name: '保留天数', exact: true }).fill('90');
  await page.getByRole('button', { name: '保存生命周期设置' }).click();
  await expect(page.locator('#lifecycle-retention-confirmation-error')).toContainText('RETENTION 90 DAYS');
  expect(bodies).toHaveLength(0);

  await page.getByLabel('输入“RETENTION 90 DAYS”以确认').fill('RETENTION 90 DAYS');
  await page.getByRole('button', { name: '保存生命周期设置' }).click();
  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies[0]).toEqual({
    expected_revision: 4,
    session_absolute_ttl: '24h',
    session_idle_ttl: '12h',
    max_concurrent_sessions: 5,
    recent_authentication_ttl: '10m',
    access_token_ttl: '1h',
    refresh_token_ttl: '720h',
    authorization_code_ttl: '5m',
    audit_retention_days: 90,
    retention_confirmation: 'RETENTION 90 DAYS',
  });
});

test('lifecycle page saves browser-session and OAuth credential policies together', async ({ page }) => {
  const bodies: UpdateLifecycleSettingsInput[] = [];
  await installAPIMocks(page, 'admin', async (route, path, method) => {
    if (path !== '/api/admin/settings/lifecycle') return false;
    if (method === 'GET') {
      await json(route, 200, lifecycleSettings);
      return true;
    }
    if (method === 'PUT') {
      const body = route.request().postDataJSON() as UpdateLifecycleSettingsInput;
      bodies.push(body);
      await json(route, 200, {
        revision: body.expected_revision + 1,
        session_absolute_ttl: body.session_absolute_ttl,
        session_idle_ttl: body.session_idle_ttl,
        max_concurrent_sessions: body.max_concurrent_sessions,
        recent_authentication_ttl: body.recent_authentication_ttl,
        access_token_ttl: body.access_token_ttl,
        refresh_token_ttl: body.refresh_token_ttl,
        authorization_code_ttl: body.authorization_code_ttl,
        audit_retention_days: body.audit_retention_days,
      } satisfies LifecycleSettings);
      return true;
    }
    return false;
  });

  await page.goto('/admin/settings/lifecycle');
  await page.getByRole('textbox', { name: '会话绝对有效期', exact: true }).fill('48h');
  await page.getByRole('textbox', { name: '会话空闲有效期', exact: true }).fill('2h');
  await page.getByRole('spinbutton', { name: '每位用户并发会话上限', exact: true }).fill('3');
  await page.getByRole('textbox', { name: '近期认证有效期', exact: true }).fill('15m');
  await page.getByRole('textbox', { name: 'Access Token 有效期', exact: true }).fill('30m');
  await page.getByRole('textbox', { name: 'Refresh Token 有效期', exact: true }).fill('168h');
  await page.getByRole('textbox', { name: '授权码有效期', exact: true }).fill('2m');
  await page.getByRole('button', { name: '保存生命周期设置' }).click();

  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies[0]).toMatchObject({
    expected_revision: 4,
    session_absolute_ttl: '48h',
    session_idle_ttl: '2h',
    max_concurrent_sessions: 3,
    recent_authentication_ttl: '15m',
    access_token_ttl: '30m',
    refresh_token_ttl: '168h',
    authorization_code_ttl: '2m',
  });
});

test('lifecycle validation focuses the invalid field without moving the panel', async ({ page }) => {
  await installAPIMocks(page, 'admin', async (route, path, method) => {
    if (path === '/api/admin/settings/lifecycle' && method === 'GET') {
      await json(route, 200, lifecycleSettings);
      return true;
    }
    return false;
  });

  await page.goto('/admin/settings/lifecycle');
  await page.getByRole('textbox', { name: '近期认证有效期', exact: true }).fill('61m');
  await page.getByRole('button', { name: '保存生命周期设置' }).click();

  await expect(page.getByText('近期认证有效期须在 1 分钟至 1 小时之间。').first()).toBeVisible();
  await expect(page.locator('#lifecycle-recent-auth-ttl')).toBeFocused();
  await expect(page.locator('#lifecycle-recent-auth-ttl')).toHaveAttribute('aria-invalid', 'true');
});

test('OAuth client policy saves a revisioned restricted policy', async ({ page }) => {
  const bodies: UpdateOAuthSettingsInput[] = [];
  await installAPIMocks(page, 'admin', async (route, path, method) => {
    if (path !== '/api/admin/settings/oauth') return false;
    if (method === 'GET') {
      await json(route, 200, oauthSettings);
      return true;
    }
    if (method === 'PUT') {
      const body = route.request().postDataJSON() as UpdateOAuthSettingsInput;
      bodies.push(body);
      await json(route, 200, { ...body, revision: body.expected_revision + 1 });
      return true;
    }
    return false;
  });

  await page.goto('/admin/settings/oauth');
  await expect(page.getByRole('heading', { name: 'OAuth 客户端', exact: true })).toBeVisible();
  await page.getByRole('switch', { name: '允许 Public Client' }).click();
  await page.getByLabel('Client Credentials').uncheck();
  await page.getByRole('checkbox', { name: 'offline_access', exact: true }).uncheck();
  await expect(page.locator('#oauth-scope-openid-name')).toHaveCount(0);
  await page.getByRole('button', { name: '展开 openid 配置' }).click();
  await expect(page.locator('#oauth-scope-openid-name')).toBeVisible();
  await page.getByRole('button', { name: '添加自定义 Scope' }).click();
  const addScopeDialog = page.getByRole('dialog', { name: '添加自定义 Scope' });
  await addScopeDialog.getByLabel('Scope 标识').fill('tenant.read');
  await addScopeDialog.getByLabel('Scope 显示名称', { exact: true }).fill('读取租户');
  await addScopeDialog.getByLabel('授权说明').fill('读取当前用户可以访问的租户和账户角色。');
  await addScopeDialog.getByRole('checkbox', { name: /账户角色/ }).check();
  await addScopeDialog.getByRole('button', { name: '添加到目录' }).click();
  await expect(addScopeDialog).toBeHidden();
  const tenantScope = page.locator('[data-scope="tenant.read"]');
  await expect(tenantScope).toBeVisible();
  await expect(page.locator('#oauth-scope-openid-name')).toHaveCount(0);
  await expect(page.locator('[id="oauth-scope-tenant.read-name"]')).toBeVisible();
  await page.locator('#oauth-max-redirects').fill('12');
  await page.locator('#oauth-max-logouts').fill('4');
  await page.getByRole('button', { name: '保存 OAuth 客户端策略' }).click();

  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies[0]).toEqual({
    expected_revision: 5,
    self_service_client_creation_enabled: true,
    public_clients_enabled: false,
    allowed_grant_types: ['authorization_code', 'refresh_token'],
    allowed_scopes: ['openid', 'profile', 'email', 'tenant.read'],
    scope_definitions: {
      openid: DEFAULT_SCOPE_DEFINITIONS.openid,
      profile: DEFAULT_SCOPE_DEFINITIONS.profile,
      email: DEFAULT_SCOPE_DEFINITIONS.email,
      'tenant.read': {
        display_name: '读取租户',
        description: '读取当前用户可以访问的租户和账户角色。',
        claims: ['role'],
        assignment_policy: 'admin_only',
        risk_level: 'sensitive',
      },
    },
    claim_assignment_policies: DEFAULT_CLAIM_ASSIGNMENT_POLICIES,
    max_redirect_uris: 12,
    max_post_logout_redirect_uris: 4,
  });
  await expect(page.getByText('OAuth 客户端策略已保存')).toBeVisible();
});

test('administrator OAuth console is available in production routes and uses the live Scope Catalog', async ({ page }) => {
  await installAPIMocks(page, 'admin', async (route, path, method) => {
    if (path === '/api/admin/settings/oauth' && method === 'GET') {
      await json(route, 200, oauthSettings);
      return true;
    }
    return false;
  });

  await page.goto('/admin/oauth/test');
  await expect(page.getByRole('heading', { name: 'OAuth 2.0 流程测试' })).toBeVisible();
  await expect(page.getByLabel('Client ID')).toHaveValue('nya-test-client');
  await expect(page.getByLabel('Redirect URI')).toHaveValue(/\/admin\/oauth\/test$/);
  await expect(page.getByText('Secret 只保存在当前页面内存中')).toBeVisible();
  await expect(page.getByRole('button', { name: 'openid', exact: true })).toBeVisible();
  await expect(page.getByLabel('查看 openid Scope 说明')).toBeVisible();
});

test('confidential OAuth test callback never persists the secret and asks for it again before exchange', async ({ page }) => {
  let tokenBody = '';
  await page.addInitScript(() => {
    sessionStorage.setItem('nya_pkce_verifier', 'a'.repeat(43));
    sessionStorage.setItem('nya_state', 'expected-state');
    sessionStorage.setItem('nya_oauth_test_client_id', 'confidential-client');
    sessionStorage.setItem('nya_oauth_test_secret_required', 'true');
  });
  await page.route('**/token', async (route) => {
    tokenBody = route.request().postData() || '';
    await json(route, 200, { access_token: 'access-token', token_type: 'Bearer', expires_in: 3600 });
  });
  await installAPIMocks(page, 'admin', async (route, path, method) => {
    if (path === '/api/admin/settings/oauth' && method === 'GET') {
      await json(route, 200, oauthSettings);
      return true;
    }
    return false;
  });

  await page.goto('/admin/oauth/test?code=authorization-code&state=expected-state');
  await expect(page.getByRole('heading', { name: '重新输入 Client Secret' })).toBeVisible();
  expect(tokenBody).toBe('');
  const secret = page.getByLabel('回调后的 Client Secret');
  await secret.fill('one-time-test-secret');
  await page.getByRole('button', { name: '换取 Token' }).click();
  await expect.poll(() => tokenBody).toContain('client_id=confidential-client');
  expect(tokenBody).toContain('client_secret=one-time-test-secret');
  await expect(secret).toHaveCount(0);
  await expect(page.locator('pre').filter({ hasText: '"access_token": "access-token"' })).toBeVisible();
});

test('OAuth policy revision conflict keeps the draft until the administrator reloads', async ({ page }) => {
  let getCount = 0;
  await installAPIMocks(page, 'admin', async (route, path, method) => {
    if (path !== '/api/admin/settings/oauth') return false;
    if (method === 'GET') {
      getCount++;
      await json(route, 200, getCount === 1 ? oauthSettings : { ...oauthSettings, revision: 6, max_redirect_uris: 8 });
      return true;
    }
    if (method === 'PUT') {
      await json(route, 409, { code: 'settings.revision_conflict', error: 'settings revision conflict' });
      return true;
    }
    return false;
  });

  await page.goto('/admin/settings/oauth');
  const redirects = page.locator('#oauth-max-redirects');
  await redirects.fill('12');
  await page.getByRole('button', { name: '保存 OAuth 客户端策略' }).click();
  await expect(page.getByText('设置已被其他管理员修改。当前草稿已保留，请加载最新设置后重新核对。')).toBeVisible();
  await expect(redirects).toHaveValue('12');
  await page.getByRole('button', { name: '加载最新设置' }).click();
  await expect(redirects).toHaveValue('8');
});

test('my applications build new clients only from the current OAuth policy', async ({ page }) => {
  const bodies: unknown[] = [];
  let policyLoads = 0;
  const result: MyClientPage = {
    items: [], total: 0, page: 1, page_size: 50, total_pages: 0,
    quota_used: 0, quota_limit: 10, quota_override: null,
    client_policy: {
      self_service_client_creation_enabled: true,
      public_clients_enabled: false,
      allowed_grant_types: ['client_credentials'],
      allowed_scopes: ['email'],
      scope_definitions: DEFAULT_SCOPE_DEFINITIONS,
      claim_assignment_policies: DEFAULT_CLAIM_ASSIGNMENT_POLICIES,
      max_redirect_uris: 2,
      max_post_logout_redirect_uris: 0,
    },
  };
  await installAPIMocks(page, 'user', async (route, path, method) => {
    if (path === '/api/my/clients' && method === 'GET') {
      policyLoads++;
      await json(route, 200, result);
      return true;
    }
    if (path === '/api/my/clients' && method === 'POST') {
      bodies.push(route.request().postDataJSON());
      await json(route, 201, { id: 'machine-client', secret: 'visible-once' });
      return true;
    }
    return false;
  });

  await page.goto('/dashboard/apps');
  await page.getByRole('button', { name: '创建应用' }).first().click();
  await expect.poll(() => policyLoads).toBe(2);
  const dialog = page.getByRole('dialog', { name: '创建应用' });
  const scrollWidthBefore = await dialog.evaluate((element) => element.scrollWidth);
  await dialog.getByRole('button', { name: '查看 email Scope 说明' }).hover();
  const tooltip = page.locator('[data-tooltip-content]');
  await expect(tooltip).toBeVisible();
  expect(await tooltip.evaluate((element) => element.closest('[role="dialog"]') === null)).toBe(true);
  expect(await dialog.evaluate((element) => element.scrollWidth)).toBe(scrollWidthBefore);
  await expect(dialog.getByRole('checkbox', { name: /Client Credentials/ })).toBeChecked();
  await expect(dialog.locator('#my-client-create-scope-email')).toBeChecked();
  await expect(dialog.getByRole('checkbox', { name: /Authorization Code/ })).toHaveCount(0);
  await expect(dialog.locator('#my-client-create-scope-offline_access')).toHaveCount(0);
  await expect(page.getByLabel('公共客户端')).toBeDisabled();
  await expect(page.getByLabel(/Post-logout Redirect URI/)).toBeDisabled();
  await page.getByLabel('应用名称').fill('Machine Client');
  await page.getByRole('button', { name: '创建', exact: true }).click();
  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies[0]).toEqual({
    name: 'Machine Client',
    homepage_uri: '',
    privacy_policy_uri: '',
    terms_of_service_uri: '',
    redirect_uris: [],
    post_logout_redirect_uris: [],
    grants: ['client_credentials'],
    scopes: ['email'],
    optional_scopes: [],
    allowed_claims: ['email', 'email_verified'],
    is_public: false,
  });
});

test('my applications explain a policy change that races with an open create dialog', async ({ page }) => {
  const result: MyClientPage = {
    items: [], total: 0, page: 1, page_size: 50, total_pages: 0,
    quota_used: 0, quota_limit: 10, quota_override: null,
    client_policy: {
      self_service_client_creation_enabled: true,
      public_clients_enabled: true,
      allowed_grant_types: ['authorization_code', 'refresh_token'],
      allowed_scopes: ['openid', 'profile'],
      scope_definitions: DEFAULT_SCOPE_DEFINITIONS,
      claim_assignment_policies: DEFAULT_CLAIM_ASSIGNMENT_POLICIES,
      max_redirect_uris: 2,
      max_post_logout_redirect_uris: 2,
    },
  };
  await installAPIMocks(page, 'user', async (route, path, method) => {
    if (path === '/api/my/clients' && method === 'GET') {
      await json(route, 200, result);
      return true;
    }
    if (path === '/api/my/clients' && method === 'POST') {
      await json(route, 400, {
        code: 'client.configuration_invalid',
        error: 'invalid OAuth client: scope "profile" is disabled by OAuth policy',
      });
      return true;
    }
    return false;
  });

  await page.goto('/dashboard/apps');
  await page.getByRole('button', { name: '创建应用' }).first().click();
  const dialog = page.getByRole('dialog', { name: '创建应用' });
  await dialog.getByLabel('应用名称').fill('Stale Policy App');
  await dialog.getByLabel(/Redirect URI/).first().fill('https://client.example/callback');
  await dialog.getByRole('button', { name: '创建', exact: true }).click();
  await expect(dialog.getByRole('alert')).toHaveText('Scope “profile” 已被管理员停用，请重新打开窗口后选择当前可用权限');
});

test('my applications use the server quota and disable creation when it is full', async ({ page }) => {
  const result: MyClientPage = {
    items: [ownedClient],
    total: 1,
    page: 1,
    page_size: 50,
    total_pages: 1,
    quota_used: 3,
    quota_limit: 3,
    quota_override: null,
    client_policy: {
      self_service_client_creation_enabled: true,
      public_clients_enabled: true,
      allowed_grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
      allowed_scopes: ['openid', 'profile', 'email', 'offline_access'],
      scope_definitions: DEFAULT_SCOPE_DEFINITIONS,
      claim_assignment_policies: DEFAULT_CLAIM_ASSIGNMENT_POLICIES,
      max_redirect_uris: 20,
      max_post_logout_redirect_uris: 20,
    },
  };
  await installAPIMocks(page, 'user', async (route, path, method) => {
    if (path === '/api/my/clients' && method === 'GET') {
      await json(route, 200, result);
      return true;
    }
    return false;
  });

  await page.goto('/dashboard/apps');
  await expect(page.getByText('3/3', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '创建应用' })).toBeDisabled();
});

test('admin user access saves a numeric quota override and restores the global default', async ({ page }) => {
  const bodies: Array<{ quota_override: number | null }> = [];
  const clientPage: ClientQuotaPage<AdminUserClientSummary> = {
    items: [],
    total: 0,
    page: 1,
    page_size: 50,
    total_pages: 0,
    quota_used: 2,
    quota_limit: 10,
    quota_override: null,
  };
  await installAPIMocks(page, 'admin', async (route, path, method) => {
    const base = `/api/admin/users/${targetUserID}`;
    if (path === `${base}/overview` && method === 'GET') {
      await json(route, 200, targetOverview);
      return true;
    }
    if (path === `${base}/identities` && method === 'GET') {
      await json(route, 200, []);
      return true;
    }
    if (path === `${base}/authorizations` && method === 'GET') {
      await json(route, 200, []);
      return true;
    }
    if (path === `${base}/clients` && method === 'GET') {
      await json(route, 200, clientPage);
      return true;
    }
    if (path === `${base}/client-quota` && method === 'PUT') {
      const body = route.request().postDataJSON() as { quota_override: number | null };
      bodies.push(body);
      const response: ClientQuota = {
        quota_used: 2,
        quota_limit: body.quota_override ?? 10,
        quota_override: body.quota_override,
      };
      await json(route, 200, response);
      return true;
    }
    return false;
  });

  await page.goto(`/admin/users/${targetUserID}/access`);
  await expect(page.getByRole('heading', { name: '拥有的 OAuth / OIDC 客户端' })).toBeVisible();
  await page.getByLabel('为该用户设置独立配额').check();
  await page.getByLabel('配额上限').fill('25');
  await page.getByRole('button', { name: '保存配额' }).click();
  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies[0]).toEqual({ quota_override: 25 });
  await expect(page.getByRole('status')).toContainText('已将用户应用配额设为 25');

  await page.getByLabel('为该用户设置独立配额').uncheck();
  await page.getByRole('button', { name: '保存配额' }).click();
  await expect.poll(() => bodies.length).toBe(2);
  expect(bodies[1]).toEqual({ quota_override: null });
  await expect(page.getByRole('status')).toContainText('已恢复全局应用配额 10');
});
