import { expect, test, type Page, type Route } from '@playwright/test';
import type { MailConfig, MailSettings } from '../../src/lib/api';

type Role = 'admin' | 'user';

interface MockState {
  authenticated: boolean;
  mustChangePassword: boolean;
  role: Role;
  csrfToken: string;
  authenticatedAt?: string;
  hasPassword?: boolean;
  identities?: Array<typeof githubIdentity>;
  identityLoadFailures?: number;
  identityLoadRequests?: number;
  providerListFailures?: number;
  providerListRequests?: number;
  passwordFailures?: number;
  passwordCSRF?: string | null;
  logoutCSRF?: string | null;
  bindCSRF?: string | null;
  bindBody?: unknown;
  revokeOthersCSRF?: string | null;
  authorizationRevokeCSRF?: string | null;
  clientRotateCSRF?: string | null;
  reauthCSRF?: string | null;
  reauthBody?: unknown;
  providerReauthCSRF?: string | null;
  providerReauthBody?: unknown;
  providerReauthError?: string;
  setPasswordCSRF?: string | null;
  identityDeleteCSRF?: string | null;
  adminRequestSeen?: boolean;
  adminClients?: Array<typeof oauthClient>;
  adminClientQueries?: string[];
  adminClientCreateBody?: unknown;
  adminClientCreateCSRF?: string | null;
  adminClientUpdateBody?: unknown;
  adminClientUpdateCSRF?: string | null;
  adminClientOwnerUpdateBodies?: Array<{ owner_id: string | null }>;
  adminClientOwnerUpdateCSRFs?: Array<string | null>;
  adminUsers?: Array<typeof user>;
  adminUserQueries?: string[];
  adminUserIdentities?: Array<typeof githubIdentity>;
  adminUserUpdateBody?: unknown;
  adminUserUpdateCSRF?: string | null;
  adminUserIdentityDeleteCSRF?: string | null;
  adminUserRoleUpdateError?: string;
  adminProviders?: Array<typeof externalProvider>;
  adminProviderCreateBody?: unknown;
  adminProviderCreateCSRF?: string | null;
  adminProviderUpdateBody?: unknown;
  adminProviderUpdateCSRF?: string | null;
  adminProviderTestRequests?: number;
  systemStatus?: typeof systemStatus;
}

const user = {
  id: '11111111-1111-1111-1111-111111111111',
  username: 'alice',
  email: 'alice@example.com',
  display_name: 'Alice',
  avatar_url: null,
  metadata: { department: 'engineering' },
  status: 'active',
  role: 'user' as Role,
  created_at: '2026-01-01T00:00:00Z',
  last_login_at: '2026-01-02T00:00:00Z',
};

const ownerUser = {
  ...user,
  id: '55555555-5555-5555-5555-555555555555',
  username: 'bob',
  email: 'bob@example.com',
  display_name: 'Bob',
};

const suspendedOwnerUser = {
  ...user,
  id: '66666666-6666-6666-6666-666666666666',
  username: 'suspended-owner',
  email: 'suspended@example.com',
  display_name: 'Suspended Owner',
  status: 'suspended',
};

const browserSessions = [
  {
    id: 'session-current',
    current: true,
    ip_address: '192.0.2.10',
    user_agent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/126.0',
    created_at: '2026-01-01T00:00:00Z',
    last_seen_at: '2026-01-02T00:00:00Z',
    authenticated_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 'session-other',
    current: false,
    ip_address: '198.51.100.24',
    user_agent: 'Mozilla/5.0 (Android 15) Firefox/128.0',
    created_at: '2026-01-01T01:00:00Z',
    last_seen_at: '2026-01-02T01:00:00Z',
    authenticated_at: '2026-01-01T01:00:00Z',
  },
];

const oauthAuthorization = {
  id: '22222222-2222-2222-2222-222222222222',
  client_id: 'example-client',
  client_name: 'Example App',
  scopes: ['openid', 'profile', 'offline_access'],
  granted_at: '2026-01-01T00:00:00Z',
  last_used_at: '2026-01-02T00:00:00Z',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-02T00:00:00Z',
};

const oauthClient = {
  id: 'example-client',
  name: 'Example App',
  redirect_uris: ['https://app.example/callback'],
  post_logout_redirect_uris: ['https://app.example/signed-out'],
  grants: ['authorization_code', 'refresh_token'],
  scopes: ['openid', 'profile', 'offline_access'],
  is_public: false,
  secret_hint: 'abcd1234',
  secret_version: 1,
  secret_rotated_at: '2026-01-01T00:00:00Z',
  owner_id: user.id as string | null,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

const externalProvider = {
  id: '44444444-4444-4444-4444-444444444444',
  name: 'company-sso',
  type: 'generic',
  client_id: 'provider-client',
  scopes: ['openid', 'profile'],
  discovery_url: 'https://idp.example/.well-known/openid-configuration',
  authorization_url: 'https://idp.example/authorize',
  token_url: 'https://idp.example/token',
  userinfo_url: 'https://idp.example/userinfo',
  enabled: true,
  revision: 4,
  metadata: { environment: 'production' },
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-02T00:00:00Z',
};

const systemStatus = {
  status: 'ok',
  version: '0.3.0-test',
  schema: {
    status: 'ok',
    version: 1,
    required_version: 1,
  },
  services: {
    postgresql: { status: 'ok', latency_ms: 3 },
    redis: { status: 'ok', latency_ms: 2 },
    providers: { status: 'degraded', latency_ms: 8, snapshot_revision: 12 },
    jwk: { status: 'ok', latency_ms: 1 },
    mail: { status: 'ok', mode: 'fallback', configured: true, available: true, circuit_state: 'closed' },
  },
  active_signing_key: {
    kid: 'signing-key-2026-07',
    status: 'ok',
    signing_started_at: '2026-07-01T00:00:00Z',
    next_rotation_at: '2026-08-01T00:00:00Z',
  },
};

const mailSettings: MailSettings = {
  mode: 'fallback',
  configured: true,
  available: true,
  state_revision: 0,
  circuit: {
    state: 'closed',
    transport_failure_count: 0,
  },
  active: {
    source: 'environment',
    host: 'smtp.bootstrap.example.com',
    port: 587,
    username: 'bootstrap-user',
    tls_mode: 'starttls',
    from_address: 'noreply@example.com',
    from_name: 'Nyauth',
    public_base_url: 'https://auth.example.com',
    connect_timeout: '10s',
    send_timeout: '30s',
    password_configured: true,
  },
};

const githubIdentity = {
  id: '33333333-3333-3333-3333-333333333333',
  user_id: user.id,
  provider: 'github',
  external_id: 'github-123',
  external_username: 'alice-gh',
  external_email: 'alice@example.com',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

function sessionResponse(state: MockState) {
  return {
    user: { ...user, role: state.role },
    csrf_token: state.csrfToken,
    must_change_password: state.mustChangePassword,
    has_password: state.hasPassword ?? true,
    email_verified: true,
    authenticated_at: state.authenticatedAt || '2026-01-02T00:00:00Z',
  };
}

async function fulfillJSON(route: Route, status: number, body: unknown, headers?: Record<string, string>) {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
    headers,
  });
}

async function installAPIMocks(page: Page, state: MockState) {
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const requestURL = new URL(request.url());
    const path = requestURL.pathname;

    if (path === '/api/session') {
      if (!state.authenticated) {
        await fulfillJSON(route, 401, { error: 'authentication_required' });
        return;
      }
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }

    if (path === '/api/login' && request.method() === 'POST') {
      state.authenticated = true;
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }

    if (path === '/api/logout' && request.method() === 'POST') {
      state.logoutCSRF = await request.headerValue('x-csrf-token');
      state.authenticated = false;
      await route.fulfill({ status: 204 });
      return;
    }

    if (path === '/api/me/password' && request.method() === 'POST') {
      state.passwordCSRF = await request.headerValue('x-csrf-token');
      if ((state.passwordFailures || 0) > 0) {
        state.passwordFailures = (state.passwordFailures || 0) - 1;
        await fulfillJSON(route, 401, { error: 'current password is incorrect' });
        return;
      }
      state.mustChangePassword = false;
      state.csrfToken = 'csrf-rotated';
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }

    if (path === '/api/providers') {
      state.providerListRequests = (state.providerListRequests || 0) + 1;
      if ((state.providerListFailures || 0) > 0) {
        state.providerListFailures = (state.providerListFailures || 0) - 1;
        await fulfillJSON(route, 503, { error: 'provider list unavailable' });
        return;
      }
      await fulfillJSON(route, 200, [{ name: 'github', type: 'github' }]);
      return;
    }

    if (path === '/api/me/identities') {
      state.identityLoadRequests = (state.identityLoadRequests || 0) + 1;
      if ((state.identityLoadFailures || 0) > 0) {
        state.identityLoadFailures = (state.identityLoadFailures || 0) - 1;
        await fulfillJSON(route, 503, { error: '外部身份服务暂时不可用' });
        return;
      }
      await fulfillJSON(route, 200, state.identities || []);
      return;
    }

    if (path === '/api/me/reauth/password' && request.method() === 'POST') {
      state.reauthCSRF = await request.headerValue('x-csrf-token');
      state.reauthBody = request.postDataJSON();
      state.authenticatedAt = new Date().toISOString();
      state.csrfToken = 'csrf-reauthenticated';
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }

    if (path.startsWith('/api/me/reauth/') && request.method() === 'POST') {
      state.providerReauthCSRF = await request.headerValue('x-csrf-token');
      state.providerReauthBody = request.postDataJSON();
      const body = state.providerReauthBody as { return_to?: string };
      const returnTo = body.return_to || '/profile';
      const redirectURL = new URL(returnTo, request.url());
      if (state.providerReauthError) {
        redirectURL.searchParams.set('auth_error', state.providerReauthError);
      } else {
        state.authenticatedAt = new Date().toISOString();
        state.csrfToken = 'csrf-provider-reauthenticated';
      }
      await fulfillJSON(route, 200, { redirect_url: redirectURL.toString() });
      return;
    }

    if (path === '/api/me/password/set' && request.method() === 'POST') {
      state.setPasswordCSRF = await request.headerValue('x-csrf-token');
      state.hasPassword = true;
      state.csrfToken = 'csrf-password-set';
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }

    if (path === `/api/me/identities/${githubIdentity.id}` && request.method() === 'DELETE') {
      state.identityDeleteCSRF = await request.headerValue('x-csrf-token');
      state.identities = [];
      state.csrfToken = 'csrf-identity-rotated';
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }

    if (path === '/api/me/sessions' && request.method() === 'GET') {
      await fulfillJSON(route, 200, browserSessions);
      return;
    }

    if (path === '/api/me/sessions/revoke-others' && request.method() === 'POST') {
      state.revokeOthersCSRF = await request.headerValue('x-csrf-token');
      await fulfillJSON(route, 200, { revoked: 1 });
      return;
    }

    if (path === '/api/me/authorizations' && request.method() === 'GET') {
      await fulfillJSON(route, 200, [oauthAuthorization]);
      return;
    }

    if (path === `/api/me/authorizations/${oauthAuthorization.client_id}` && request.method() === 'DELETE') {
      state.authorizationRevokeCSRF = await request.headerValue('x-csrf-token');
      await route.fulfill({ status: 204 });
      return;
    }

    if (path === '/api/me/identities/github/bind' && request.method() === 'POST') {
      state.bindCSRF = await request.headerValue('x-csrf-token');
      state.bindBody = request.postDataJSON();
      await fulfillJSON(route, 200, { redirect_url: 'https://provider.example/authorize' });
      return;
    }

    if (path === '/api/me') {
      await fulfillJSON(route, 200, { ...user, role: state.role });
      return;
    }

    if (path === `/api/my/clients/${oauthClient.id}/rotate-secret` && request.method() === 'POST') {
      state.clientRotateCSRF = await request.headerValue('x-csrf-token');
      await fulfillJSON(route, 200, {
        client_id: oauthClient.id,
        secret: 'new-client-secret-visible-once',
        secret_hint: 'ibleonce',
        secret_version: 2,
        secret_rotated_at: '2026-01-03T00:00:00Z',
      });
      return;
    }

    if (path === '/api/my/clients') {
      await fulfillJSON(route, 200, { items: [oauthClient], total: 1, page: 1, page_size: 50, total_pages: 1 });
      return;
    }

    if (path === '/api/admin/clients' && request.method() === 'GET' && state.adminClients) {
      const pageNumber = Math.max(1, Number(requestURL.searchParams.get('page')) || 1);
      const pageSize = Math.max(1, Number(requestURL.searchParams.get('page_size')) || 20);
      const start = (pageNumber - 1) * pageSize;
      state.adminClientQueries ||= [];
      state.adminClientQueries.push(requestURL.search);
      await fulfillJSON(route, 200, {
        items: state.adminClients.slice(start, start + pageSize),
        total: state.adminClients.length,
        page: pageNumber,
        page_size: pageSize,
        total_pages: Math.ceil(state.adminClients.length / pageSize),
      });
      return;
    }

    if (path === '/api/admin/clients' && request.method() === 'POST' && state.adminClients) {
      state.adminClientCreateCSRF = await request.headerValue('x-csrf-token');
      state.adminClientCreateBody = request.postDataJSON();
      const body = state.adminClientCreateBody as {
        name: string;
        redirect_uris: string[];
        post_logout_redirect_uris: string[];
        grants: string[];
        scopes: string[];
        is_public: boolean;
        owner_id: string | null;
      };
      const created = {
        ...oauthClient,
        ...body,
        id: 'created-owner-client',
        secret_version: 1,
        created_at: '2026-01-04T00:00:00Z',
        updated_at: '2026-01-04T00:00:00Z',
      };
      state.adminClients = [created];
      await fulfillJSON(route, 201, { ...created, secret: 'created-client-secret' });
      return;
    }

    if (path === '/api/admin/users' && request.method() === 'GET' && state.adminUsers) {
      state.adminUserQueries ||= [];
      state.adminUserQueries.push(requestURL.search);
      const pageNumber = Math.max(1, Number(requestURL.searchParams.get('page') || '1') || 1);
      const pageSize = Math.max(1, Number(requestURL.searchParams.get('page_size') || '20') || 20);
      const status = requestURL.searchParams.get('status') || '';
      const search = (requestURL.searchParams.get('q') || '').toLowerCase();
      const filteredUsers = state.adminUsers.filter((candidate) => {
        const matchesStatus = !status || candidate.status === status;
        const searchable = [candidate.username, candidate.email, candidate.display_name].filter(Boolean).join(' ').toLowerCase();
        return matchesStatus && (!search || searchable.includes(search));
      });
      const start = (pageNumber - 1) * pageSize;
      await fulfillJSON(route, 200, {
        items: filteredUsers.slice(start, start + pageSize),
        total: filteredUsers.length,
        page: pageNumber,
        page_size: pageSize,
        total_pages: Math.ceil(filteredUsers.length / pageSize),
      });
      return;
    }

    if (path === `/api/admin/clients/${oauthClient.id}/owner` && request.method() === 'PUT' && state.adminClients) {
      const body = request.postDataJSON() as { owner_id: string | null };
      state.adminClientOwnerUpdateBodies ||= [];
      state.adminClientOwnerUpdateBodies.push(body);
      state.adminClientOwnerUpdateCSRFs ||= [];
      state.adminClientOwnerUpdateCSRFs.push(await request.headerValue('x-csrf-token'));
      await fulfillJSON(route, 200, { ...oauthClient, owner_id: body.owner_id, updated_at: '2026-01-05T00:00:00Z' });
      return;
    }

    if (path === `/api/admin/users/${user.id}` && request.method() === 'PUT' && state.adminUsers) {
      state.adminUserUpdateCSRF = await request.headerValue('x-csrf-token');
      state.adminUserUpdateBody = request.postDataJSON();
      await fulfillJSON(route, 200, {
        ...state.adminUsers[0],
        ...(state.adminUserUpdateBody as object),
        updated_at: '2026-01-03T00:00:00Z',
      });
      return;
    }

    if (path === `/api/admin/users/${user.id}/role` && request.method() === 'PUT' && state.adminUsers) {
      if (state.adminUserRoleUpdateError) {
        await fulfillJSON(route, 409, { error: state.adminUserRoleUpdateError });
        return;
      }
      const body = request.postDataJSON() as { role: Role };
      const updated = { ...state.adminUsers[0], role: body.role };
      state.adminUsers = [updated];
      await fulfillJSON(route, 200, updated);
      return;
    }

    if (path === `/api/admin/users/${user.id}/identities` && request.method() === 'GET' && state.adminUserIdentities) {
      await fulfillJSON(route, 200, state.adminUserIdentities);
      return;
    }

    if (path === `/api/admin/users/${user.id}/identities/${githubIdentity.id}` && request.method() === 'DELETE' && state.adminUserIdentities) {
      state.adminUserIdentityDeleteCSRF = await request.headerValue('x-csrf-token');
      state.adminUserIdentities = state.adminUserIdentities.filter((identity) => identity.id !== githubIdentity.id);
      await route.fulfill({ status: 204 });
      return;
    }

    if (path === `/api/admin/users/${user.id}/sessions` && request.method() === 'GET' && state.adminUsers) {
      await fulfillJSON(route, 200, []);
      return;
    }

    if (path === `/api/admin/clients/${oauthClient.id}` && request.method() === 'PUT' && state.adminClients) {
      state.adminClientUpdateCSRF = await request.headerValue('x-csrf-token');
      state.adminClientUpdateBody = request.postDataJSON();
      await fulfillJSON(route, 200, {
        ...oauthClient,
        name: 'Renamed App',
        redirect_uris: ['https://new.example/callback', 'https://backup.example/callback'],
        post_logout_redirect_uris: ['https://new.example/signed-out'],
        scopes: ['openid', 'email', 'custom'],
        metadata: { environment: 'production', team: 'identity' },
        updated_at: '2026-01-03T00:00:00Z',
      });
      return;
    }

    if (path === '/api/admin/providers' && request.method() === 'GET' && state.adminProviders) {
      await fulfillJSON(route, 200, state.adminProviders);
      return;
    }

    if (path === '/api/admin/providers' && request.method() === 'POST' && state.adminProviders) {
      state.adminProviderCreateCSRF = await request.headerValue('x-csrf-token');
      state.adminProviderCreateBody = request.postDataJSON();
      const body = state.adminProviderCreateBody as {
        name: string;
        type: string;
        client_id: string;
        scopes: string[];
        enabled: boolean;
      };
      await fulfillJSON(route, 201, {
        ...externalProvider,
        name: body.name,
        type: body.type,
        client_id: body.client_id,
        scopes: body.scopes,
        enabled: body.enabled,
      });
      return;
    }

    if (path === `/api/admin/providers/${externalProvider.name}` && request.method() === 'PUT' && state.adminProviders) {
      state.adminProviderUpdateCSRF = await request.headerValue('x-csrf-token');
      state.adminProviderUpdateBody = request.postDataJSON();
      const current = state.adminProviders[0];
      const updated = {
        ...current,
        ...(state.adminProviderUpdateBody as object),
        revision: current.revision + 1,
        updated_at: '2026-01-03T00:00:00Z',
      };
      state.adminProviders = [updated];
      await fulfillJSON(route, 200, updated);
      return;
    }

    if (path === `/api/admin/providers/${externalProvider.name}/test` && request.method() === 'POST' && state.adminProviders) {
      state.adminProviderTestRequests = (state.adminProviderTestRequests || 0) + 1;
      await fulfillJSON(route, 200, {
        provider: externalProvider.name,
        type: externalProvider.type,
        configuration_valid: true,
        authorization_endpoint_valid: true,
        discovery_reachable: true,
        latency_ms: 8,
        message: 'Discovery 可访问',
      });
      return;
    }

    if (path === '/api/admin/system/status' && request.method() === 'GET' && state.systemStatus) {
      await fulfillJSON(route, 200, state.systemStatus);
      return;
    }

    if (path === '/api/admin/settings/mail' && request.method() === 'GET') {
      await fulfillJSON(route, 200, mailSettings);
      return;
    }

    if (path.startsWith('/api/admin/')) {
      state.adminRequestSeen = true;
      await fulfillJSON(route, 403, { error: 'forbidden' });
      return;
    }

    await fulfillJSON(route, 404, { error: `unmocked endpoint: ${path}` });
  });
}

test('protected routes show a safe server-error state when session initialization fails', async ({ page }) => {
  await page.route('**/api/session', (route) => fulfillJSON(route, 503, { error: 'internal dependency details' }));

  await page.goto('/dashboard');

  await expect(page.getByText('认证服务暂时无法检查会话，请稍后重试。')).toBeVisible();
  await expect(page.getByText('internal dependency details')).toHaveCount(0);
});

test('protected routes distinguish a network failure from a server response', async ({ page }) => {
  await page.route('**/api/session', (route) => route.abort('connectionrefused'));

  await page.goto('/dashboard');

  await expect(page.getByText('无法连接认证服务，请检查网络连接后重试。')).toBeVisible();
});

test('login requires first password change and sends CSRF', async ({ page }) => {
  const state: MockState = {
    authenticated: false,
    mustChangePassword: true,
    role: 'user',
    csrfToken: 'csrf-login',
  };
  await installAPIMocks(page, state);

  await page.goto('/login');
  await page.getByLabel('用户名').fill('alice');
  await page.getByLabel('密码').fill('temporary-password');
  await page.getByRole('button', { name: '登录', exact: true }).click();

  await expect(page).toHaveURL(/\/change-password\?return_to=%2Fdashboard$/);
  const passwordInputs = page.locator('input[type="password"]');
  await passwordInputs.nth(0).fill('temporary-password');
  await passwordInputs.nth(1).fill('a-new-password-123');
  await passwordInputs.nth(2).fill('a-new-password-123');
  await page.getByRole('button', { name: '确认修改' }).click();

  await expect(page).toHaveURL(/\/dashboard$/);
  expect(state.passwordCSRF).toBe('csrf-login');
});

test('wrong current password stays on the change-password page and preserves CSRF for retry', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
    passwordFailures: 1,
  };
  await installAPIMocks(page, state);

  await page.goto('/change-password?return_to=/profile');
  const passwordInputs = page.locator('input[type="password"]');
  await passwordInputs.nth(0).fill('wrong-current-password');
  await passwordInputs.nth(1).fill('a-new-password-123');
  await passwordInputs.nth(2).fill('a-new-password-123');
  await page.getByRole('button', { name: '确认修改' }).click();

  await expect(page).toHaveURL(/\/change-password\?return_to=\/profile$/);
  await expect(page.getByRole('alert')).toContainText('当前密码不正确');
  await page.getByRole('button', { name: '确认修改' }).click();

  await expect(page).toHaveURL(/\/profile$/);
  expect(state.passwordCSRF).toBe('csrf-user');
});

test('provider login methods expose a retry instead of becoming an empty list', async ({ page }) => {
  const state: MockState = {
    authenticated: false,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-login',
    providerListFailures: 1,
  };
  await installAPIMocks(page, state);

  await page.goto('/login');
  await expect(page.getByRole('alert')).toContainText('外部登录方式暂时不可用');
  await page.getByRole('button', { name: '重试' }).click();

  await expect(page.getByRole('button', { name: 'github' })).toBeVisible();
  expect(state.providerListRequests).toBe(2);
});

test('provider denial cleanup preserves the sanitized return path for the next login', async ({ page }) => {
  const state: MockState = {
    authenticated: false,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-login',
  };
  await installAPIMocks(page, state);

  await page.goto('/login?return_to=%2Fdashboard%3Fauth_error%3Dprovider_denied%26tab%3Dsecurity');
  await expect(page.getByRole('alert')).toContainText('取消了外部身份提供商的授权');
  await page.getByLabel('用户名').fill('alice');
  await page.getByLabel('密码').fill('valid-password-value');
  await page.getByRole('button', { name: '登录', exact: true }).click();

  await expect(page).toHaveURL(/\/dashboard\?tab=security$/);
});

test('ordinary users cannot enter the admin area', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
  };
  await installAPIMocks(page, state);

  await page.goto('/admin');

  await expect(page).toHaveURL(/\/dashboard$/);
  expect(state.adminRequestSeen).not.toBe(true);
});

test('logout sends CSRF and returns to login', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
  };
  await installAPIMocks(page, state);

  await page.goto('/dashboard');
  await page.getByRole('button', { name: '退出登录' }).click();

  await expect(page).toHaveURL(/\/login$/);
  expect(state.logoutCSRF).toBe('csrf-user');
});

test('the desktop sidebar recovers after the window shrinks below the mobile breakpoint', async ({ page }) => {
  await installAPIMocks(page, {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-resize',
  });

  await page.goto('/dashboard');
  const sidebar = page.getByRole('complementary', { name: '用户中心导航' });
  await expect(sidebar).toHaveCSS('width', '248px');

  await page.setViewportSize({ width: 700, height: 900 });
  await expect(sidebar).not.toBeVisible();

  await page.setViewportSize({ width: 1280, height: 900 });
  await expect(sidebar).toHaveCSS('width', '248px');
});

test('mobile navigation traps focus, closes with Escape, and restores the menu trigger', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
  };
  await installAPIMocks(page, state);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/dashboard');

  const trigger = page.getByRole('button', { name: '打开导航菜单' });
  await expect(trigger).toHaveAttribute('aria-expanded', 'false');
  await trigger.click();

  await expect(page.getByRole('dialog', { name: '用户中心导航' })).toBeVisible();
  await expect(page.getByRole('button', { name: '关闭导航菜单' })).toHaveAttribute('aria-expanded', 'true');
  await page.keyboard.press('Escape');

  await expect(page.getByRole('dialog', { name: '用户中心导航' })).toBeHidden();
  await expect(trigger).toBeFocused();
});

test('identity binding starts from the current session with CSRF', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
  };
  await installAPIMocks(page, state);
  await page.route('https://provider.example/**', (route) => route.fulfill({ status: 200, body: 'provider' }));

  await page.goto('/profile');
  const bindRequest = page.waitForRequest((request) => new URL(request.url()).pathname === '/api/me/identities/github/bind');
  await page.getByRole('button', { name: /github/i }).click();
  await bindRequest;

  expect(state.bindCSRF).toBe('csrf-user');
  expect(state.bindBody).toEqual({ return_to: '/profile' });
});

test('revoking other device sessions sends CSRF and preserves the current session', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
  };
  await installAPIMocks(page, state);

  await page.goto('/profile');
  await page.getByRole('button', { name: '退出其他设备' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('button', { name: '退出其他设备' }).click();

  await expect(dialog).toBeHidden();
  await expect(page.getByText('当前设备')).toBeVisible();
  await expect(page.getByText('Firefox · Android')).toBeHidden();
  expect(state.revokeOthersCSRF).toBe('csrf-user');
});

test('revoking an OAuth authorization sends CSRF and removes the grant', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
  };
  await installAPIMocks(page, state);

  await page.goto('/profile');
  await page.getByRole('button', { name: '撤销授权' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('button', { name: '撤销授权' }).click();

  await expect(dialog).toBeHidden();
  await expect(page.getByText('当前没有活动的 OAuth 应用授权。')).toBeVisible();
  expect(state.authorizationRevokeCSRF).toBe('csrf-user');
});

test('client secret rotation requires name confirmation and reveals the new secret once', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
  };
  await installAPIMocks(page, state);

  await page.goto('/dashboard/apps');
  await page.getByRole('button', { name: '轮换 Secret' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel(/输入“Example App”以确认/).fill('Example App');
  await dialog.getByRole('button', { name: '立即轮换' }).click();

  await expect(dialog).toBeHidden();
  await page.getByRole('button', { name: '显示新 Client Secret' }).click();
  await expect(page.getByText('new-client-secret-visible-once')).toBeVisible();
  expect(state.clientRotateCSRF).toBe('csrf-user');
});

test('password reauthentication refreshes the session and CSRF token', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
  };
  await installAPIMocks(page, state);

  await page.goto('/profile');
  await page.getByRole('button', { name: '使用当前密码' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel(/^当前密码/).fill('current-password');
  await dialog.getByRole('button', { name: '重新认证' }).click();

  await expect(dialog).toBeHidden();
  await expect(page.getByText('认证有效')).toBeVisible();
  expect(state.reauthCSRF).toBe('csrf-user');
  expect(state.reauthBody).toEqual({ password: 'current-password' });
});

test('an external-only account can set a local password after recent authentication', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
    authenticatedAt: new Date().toISOString(),
    hasPassword: false,
    identities: [githubIdentity],
  };
  await installAPIMocks(page, state);

  await page.goto('/profile');
  await page.getByRole('button', { name: '设置本地密码' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel(/^新密码/).fill('a-new-password-123');
  await dialog.getByLabel(/^确认新密码/).fill('a-new-password-123');
  await dialog.getByRole('button', { name: '设置密码' }).click();

  await expect(dialog).toBeHidden();
  await expect(page.getByRole('button', { name: '修改密码' })).toBeVisible();
  expect(state.setPasswordCSRF).toBe('csrf-user');
});

test('recent authentication status expires while the profile page remains open', async ({ page }) => {
  const now = new Date('2026-07-26T08:00:00Z');
  await page.clock.install({ time: now });
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
    authenticatedAt: now.toISOString(),
  };
  await installAPIMocks(page, state);

  await page.goto('/profile');
  await expect(page.getByText('认证有效', { exact: true })).toBeVisible();
  await page.clock.fastForward(11 * 60 * 1000);

  await expect(page.getByText('需要重新认证', { exact: true })).toBeVisible();
});

test('identity removal requires recent authentication and name confirmation', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
    authenticatedAt: new Date().toISOString(),
    identities: [githubIdentity],
  };
  await installAPIMocks(page, state);

  await page.goto('/profile');
  await page.getByRole('button', { name: '解绑' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel(/输入“github”以确认/).fill('github');
  await dialog.getByRole('button', { name: '确认解绑' }).click();

  await expect(dialog).toBeHidden();
  await expect(page.getByText('尚未绑定外部身份')).toBeVisible();
  expect(state.identityDeleteCSRF).toBe('csrf-user');
});

test('profile identity failures are isolated and independently retryable', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
    identities: [githubIdentity],
    identityLoadFailures: 1,
  };
  await installAPIMocks(page, state);

  await page.goto('/profile');
  const identitySection = page.locator('section').filter({
    has: page.getByRole('heading', { name: '外部身份' }),
  });
  await expect(identitySection.getByText('外部身份服务暂时不可用')).toBeVisible();
  await expect(page.getByText('Chrome · Windows')).toBeVisible();
  await expect(page.getByText('Example App', { exact: true })).toBeVisible();

  await identitySection.getByRole('button', { name: '重试' }).click();
  await expect(identitySection.getByText('alice-gh')).toBeVisible();
  expect(state.identityLoadRequests).toBe(2);
});

test('password recovery uses the public account endpoints without revealing account existence', async ({ page }) => {
  let requestBody: unknown;
  await page.route('**/api/password/forgot', async (route) => {
    requestBody = route.request().postDataJSON();
    await fulfillJSON(route, 202, { status: 'accepted' });
  });

  await page.goto('/forgot-password');
  await page.getByLabel('邮箱地址').fill('unknown@example.com');
  await page.getByRole('button', { name: '发送重置邮件' }).click();

  await expect(page.getByText('如果该邮箱已绑定到可恢复的账户，重置邮件会很快送达。')).toBeVisible();
  expect(requestBody).toEqual({ email: 'unknown@example.com' });
});

test('password reset is only consumed after explicit confirmation', async ({ page }) => {
  let requests = 0;
  let requestBody: unknown;
  await page.route('**/api/password/reset', async (route) => {
    requests += 1;
    requestBody = route.request().postDataJSON();
    await fulfillJSON(route, 200, { status: 'password_reset' });
  });

  await page.goto('/reset-password?token=reset-token-from-email');
  await expect(page).toHaveURL(/\/reset-password$/);
  expect(requests).toBe(0);
  await page.getByLabel(/^新密码/).fill('a-new-password-123');
  await page.getByLabel('确认新密码').fill('a-new-password-123');
  await page.getByRole('button', { name: '确认重置' }).click();

  await expect(page.getByText('密码已更新，所有旧会话和令牌均已失效。')).toBeVisible();
  expect(requests).toBe(1);
  expect(requestBody).toEqual({ token: 'reset-token-from-email', new_password: 'a-new-password-123' });
});

test('email action links are never consumed during page load', async ({ page }) => {
  let verificationRequests = 0;
  let changeRequests = 0;
  let verificationBody: unknown;
  let changeBody: unknown;

  await page.route('**/api/email/verify', async (route) => {
    verificationRequests += 1;
    verificationBody = route.request().postDataJSON();
    await fulfillJSON(route, 200, { status: 'email_verified' });
  });
  await page.route('**/api/email/change/confirm', async (route) => {
    changeRequests += 1;
    changeBody = route.request().postDataJSON();
    await fulfillJSON(route, 200, { status: 'email_changed' });
  });
  await page.route('**/api/session', (route) => fulfillJSON(route, 401, { error: 'authentication_required' }));

  await page.goto('/verify-email?token=verification-token-from-email');
  await expect(page).toHaveURL(/\/verify-email$/);
  expect(verificationRequests).toBe(0);
  await page.getByRole('button', { name: '确认验证邮箱' }).click();
  await expect(page.getByText('邮箱验证完成，现在可以用于账户恢复。')).toBeVisible();
  expect(verificationRequests).toBe(1);
  expect(verificationBody).toEqual({ token: 'verification-token-from-email' });

  await page.goto('/change-email?token=email-change-token-from-email');
  await expect(page).toHaveURL(/\/change-email$/);
  expect(changeRequests).toBe(0);
  await page.getByRole('button', { name: '确认更换邮箱' }).click();
  await expect(page.getByText('新邮箱已生效。为保护账户安全，请重新登录。')).toBeVisible();
  expect(changeRequests).toBe(1);
  expect(changeBody).toEqual({ token: 'email-change-token-from-email' });
});

test('account action pages without a token show recovery guidance instead of a form', async ({ page }) => {
  let confirmRequests = 0;
  for (const path of ['**/api/password/reset', '**/api/email/verify', '**/api/email/change/confirm']) {
    await page.route(path, async (route) => {
      confirmRequests += 1;
      await fulfillJSON(route, 200, {});
    });
  }
  await page.route('**/api/session', (route) => fulfillJSON(route, 401, { error: 'authentication_required' }));

  await page.goto('/reset-password');
  await expect(page.getByText('重置链接不完整，请重新发起密码找回。')).toBeVisible();
  await expect(page.getByRole('link', { name: '重新发送邮件' })).toHaveAttribute('href', '/forgot-password');

  await page.goto('/verify-email');
  await expect(page.getByText('验证链接不完整，请从个人资料页重新发送。')).toBeVisible();

  await page.goto('/change-email');
  await expect(page.getByText('确认链接不完整，请从个人资料页重新发起邮箱变更。')).toBeVisible();

  expect(confirmRequests).toBe(0);
});

test('client-side password validation blocks the reset request before the token is spent', async ({ page }) => {
  let requests = 0;
  await page.route('**/api/password/reset', async (route) => {
    requests += 1;
    await fulfillJSON(route, 200, { status: 'password_reset' });
  });

  await page.goto('/reset-password?token=reset-token-from-email');
  await page.getByLabel(/^新密码/).fill('short');
  await page.getByLabel('确认新密码').fill('short');
  await page.getByRole('button', { name: '确认重置' }).click();
  await expect(page.getByRole('alert')).toHaveText('密码长度需为 12–1024 字节（按 UTF-8 编码）。');

  await page.getByLabel(/^新密码/).fill('a-new-password-123');
  await page.getByLabel('确认新密码').fill('a-different-password-456');
  await page.getByRole('button', { name: '确认重置' }).click();
  await expect(page.getByRole('alert')).toHaveText('两次输入的新密码不一致。');

  expect(requests).toBe(0);
});

test('an expired reset token shows the server error and keeps the form usable for retry', async ({ page }) => {
  let requests = 0;
  await page.route('**/api/password/reset', async (route) => {
    requests += 1;
    await fulfillJSON(route, 400, { error: 'invalid or expired account action token' });
  });

  await page.goto('/reset-password?token=expired-token');
  await page.getByLabel(/^新密码/).fill('a-new-password-123');
  await page.getByLabel('确认新密码').fill('a-new-password-123');
  await page.getByRole('button', { name: '确认重置' }).click();

  await expect(page.getByRole('alert')).toHaveText('invalid or expired account action token');
  await expect(page.getByText('密码已更新，所有旧会话和令牌均已失效。')).not.toBeVisible();
  expect(requests).toBe(1);

  await page.getByRole('button', { name: '确认重置' }).click();
  await expect(page.getByRole('alert')).toHaveText('invalid or expired account action token');
  expect(requests).toBe(2);
});

test('invalid email action tokens surface the failure without a false success state', async ({ page }) => {
  await page.route('**/api/email/verify', (route) =>
    fulfillJSON(route, 400, { error: 'invalid or expired account action token' }));
  await page.route('**/api/email/change/confirm', (route) =>
    fulfillJSON(route, 400, { error: 'invalid or expired account action token' }));
  await page.route('**/api/session', (route) => fulfillJSON(route, 401, { error: 'authentication_required' }));

  await page.goto('/verify-email?token=stale-token');
  await page.getByRole('button', { name: '确认验证邮箱' }).click();
  await expect(page.getByRole('alert')).toHaveText('invalid or expired account action token');
  await expect(page.getByText('邮箱验证完成，现在可以用于账户恢复。')).not.toBeVisible();
  await expect(page.getByRole('button', { name: '确认验证邮箱' })).toBeVisible();

  await page.goto('/change-email?token=stale-token');
  await page.getByRole('button', { name: '确认更换邮箱' }).click();
  await expect(page.getByRole('alert')).toHaveText('invalid or expired account action token');
  await expect(page.getByText('新邮箱已生效。为保护账户安全，请重新登录。')).not.toBeVisible();
});

const registrationOptions = (mode: string, domains: string[] = [], available = mode !== 'closed') => ({
  available,
  mode,
  require_email_verification: true,
  allowed_email_domains: domains,
});

test('the login page links to registration only when it is open', async ({ page }) => {
  await page.route('**/api/session', (route) => fulfillJSON(route, 401, { error: 'authentication required' }));
  await page.route('**/api/providers', (route) => fulfillJSON(route, 200, []));
  let mode = 'closed';
  await page.route('**/api/registration', (route) => fulfillJSON(route, 200, registrationOptions(mode)));

  await page.goto('/login');
  await expect(page.getByRole('link', { name: '忘记密码？' })).toBeVisible();
  await expect(page.getByRole('link', { name: '注册账号' })).not.toBeVisible();

  mode = 'invite_only';
  await page.reload();
  await expect(page.getByRole('link', { name: '注册账号' })).toBeVisible();
});

test('closed registration shows guidance instead of a form', async ({ page }) => {
  await page.route('**/api/registration', (route) => fulfillJSON(route, 200, registrationOptions('closed')));
  await page.goto('/register');
  await expect(page.getByText('当前未开放注册，请联系管理员创建账号。')).toBeVisible();
  await expect(page.getByLabel('用户名')).not.toBeVisible();
});

test('registration explains when SMTP is unavailable before showing a form', async ({ page }) => {
  await page.route('**/api/registration', (route) => fulfillJSON(route, 200, registrationOptions('open', [], false)));

  await page.goto('/register');

  await expect(page.getByRole('alert')).toContainText('邮件服务当前不可用');
  await expect(page.getByText('系统不会创建无法接收验证邮件的待验证账号')).toBeVisible();
  await expect(page.getByLabel('用户名')).not.toBeVisible();
});

test('invite-only registration submits the invite code and shows the pending state', async ({ page }) => {
  await page.route('**/api/registration', (route) => fulfillJSON(route, 200, registrationOptions('invite_only')));
  let registerBody: unknown;
  await page.route('**/api/register', async (route) => {
    registerBody = route.request().postDataJSON();
    await fulfillJSON(route, 201, {
      status: 'pending_verification',
      verification_expires_at: '2026-07-29T12:00:00Z',
    });
  });

  await page.goto('/register?invite=welcome-code-123');
  await expect(page).toHaveURL(/\/register$/);
  await expect(page.getByLabel('邀请码')).toHaveValue('welcome-code-123');

  await page.getByLabel('用户名').fill('newbie');
  await page.getByLabel('邮箱地址').fill('newbie@example.com');
  await page.locator('#register-password').fill('a-new-password-123');
  await page.locator('#register-confirm').fill('a-new-password-123');
  await page.getByRole('button', { name: '注册' }).click();

  await expect(page.getByText(/验证邮件已成功加入发送队列/)).toBeVisible();
  await expect(page.getByText(/截止时间不会因重发而延长/)).toBeVisible();
  await expect(page.getByRole('link', { name: '重发验证邮件' })).toHaveAttribute('href', '/resend-verification');
  expect(registerBody).toEqual({
    username: 'newbie',
    email: 'newbie@example.com',
    password: 'a-new-password-123',
    invite_code: 'welcome-code-123',
  });
});

test('open registration hides the invite field and surfaces conflicts', async ({ page }) => {
  await page.route('**/api/registration', (route) =>
    fulfillJSON(route, 200, registrationOptions('open', ['corp.example.com'])));
  let requests = 0;
  await page.route('**/api/register', async (route) => {
    requests += 1;
    await fulfillJSON(route, 409, { error: 'username or email is already taken' });
  });

  await page.goto('/register');
  await expect(page.getByText('仅允许以下域名的邮箱：corp.example.com')).toBeVisible();
  await expect(page.getByLabel('邀请码')).not.toBeVisible();

  await page.getByLabel('用户名').fill('taken');
  await page.getByLabel('邮箱地址').fill('taken@corp.example.com');
  await page.locator('#register-password').fill('a-new-password-123');
  await page.locator('#register-confirm').fill('a-new-password-123');
  await page.getByRole('button', { name: '注册' }).click();

  await expect(page.getByRole('alert')).toHaveText('用户名或邮箱已被使用');
  expect(requests).toBe(1);
  await expect(page.getByRole('button', { name: '注册' })).toBeEnabled();
});

test('registration preserves the form and explains SMTP recovery after a 503', async ({ page }) => {
  await page.route('**/api/registration', (route) => fulfillJSON(route, 200, registrationOptions('open')));
  await page.route('**/api/register', (route) => fulfillJSON(
    route,
    503,
    { error: 'registration is temporarily unavailable' },
    { 'Retry-After': '60' },
  ));

  await page.goto('/register');
  await page.getByLabel('用户名').fill('waiting-user');
  await page.getByLabel('邮箱地址').fill('waiting@example.com');
  await page.locator('#register-password').fill('a-new-password-123');
  await page.locator('#register-confirm').fill('a-new-password-123');
  await page.getByRole('button', { name: '注册' }).click();

  await expect(page.getByRole('alert')).toHaveText('注册邮件服务正在恢复，请在 60 秒后重试。你填写的内容尚未提交。');
  await expect(page.getByLabel('用户名')).toHaveValue('waiting-user');
  await expect(page.getByLabel('邮箱地址')).toHaveValue('waiting@example.com');
  await expect(page.getByRole('button', { name: '注册' })).toBeEnabled();
});

test('login distinguishes an unverified email from bad credentials', async ({ page }) => {
  await page.route('**/api/session', (route) => fulfillJSON(route, 401, { error: 'authentication required' }));
  await page.route('**/api/providers', (route) => fulfillJSON(route, 200, []));
  await page.route('**/api/registration', (route) => fulfillJSON(route, 200, registrationOptions('closed')));
  await page.route('**/api/login', (route) =>
    fulfillJSON(route, 403, { error: 'email verification is required before signing in' }));

  await page.goto('/login');
  await page.getByLabel('用户名').fill('pending-user');
  await page.getByLabel('密码').fill('a-valid-password-123');
  await page.getByRole('button', { name: '登录' }).click();

  await expect(page.getByText('邮箱尚未验证，请先完成验证邮件中的确认再登录')).toBeVisible();
  await expect(page.getByRole('link', { name: '重发验证邮件' })).toHaveAttribute('href', '/resend-verification');
});

test('pending verification resend is enumeration-safe and recovers after rate limiting', async ({ page }) => {
  let requests = 0;
  let resendBody: unknown;
  await page.route('**/api/email/verification/resend', async (route) => {
    requests += 1;
    resendBody = route.request().postDataJSON();
    if (requests === 1) {
      await fulfillJSON(route, 429, { error: 'too many email verification requests' }, { 'Retry-After': '15' });
      return;
    }
    await fulfillJSON(route, 202, { status: 'accepted' });
  });

  await page.goto('/resend-verification');
  await page.getByLabel('注册邮箱').fill('pending@example.com');
  await page.getByRole('button', { name: '提交重发请求' }).click();
  await expect(page.getByRole('alert')).toHaveText('请求过于频繁，请在 15 秒后重试。');
  await expect(page.getByLabel('注册邮箱')).toHaveValue('pending@example.com');

  await page.getByRole('button', { name: '提交重发请求' }).click();
  await expect(page.getByText('如果该邮箱对应仍有效的待验证注册，新邮件已成功加入发送队列。')).toBeVisible();
  await expect(page.getByText('重发不会延长原注册截止时间。')).toBeVisible();
  expect(resendBody).toEqual({ email: 'pending@example.com' });
  expect(requests).toBe(2);
});

test('forgot-password surfaces rate limiting and allows a later retry', async ({ page }) => {
  let requests = 0;
  await page.route('**/api/password/forgot', async (route) => {
    requests += 1;
    if (requests === 1) {
      await fulfillJSON(route, 429, { error: 'too many account recovery requests' });
    } else {
      await fulfillJSON(route, 202, { status: 'accepted' });
    }
  });

  await page.goto('/forgot-password');
  await page.getByLabel('邮箱地址').fill('alice@example.com');
  await page.getByRole('button', { name: '发送重置邮件' }).click();
  await expect(page.getByRole('alert')).toHaveText('too many account recovery requests');
  await expect(page.getByLabel('邮箱地址')).toHaveValue('alice@example.com');

  await page.getByRole('button', { name: '发送重置邮件' }).click();
  await expect(page.getByText('如果该邮箱已绑定到可恢复的账户，重置邮件会很快送达。')).toBeVisible();
  expect(requests).toBe(2);
});

test('the dashboard login-trend chart draws real data points', async ({ page }) => {
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(String(error)));

  await installAPIMocks(page, {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin',
  });
  await page.route('**/api/admin/stats', (route) => fulfillJSON(route, 200, {
    user_count: 12, app_count: 3, login_count_7d: 41, active_sessions: 5, failed_logins_7d: 4,
  }));
  await page.route('**/api/admin/stats/login-trend**', (route) => fulfillJSON(route, 200, {
    labels: ['07-20', '07-21', '07-22', '07-23', '07-24', '07-25', '07-26'],
    values: [3, 5, 2, 8, 6, 4, 7],
  }));
  await page.route('**/api/admin/stats/recent-logins**', (route) => fulfillJSON(route, 200, []));

  await page.goto('/admin');

  // The canvas existing is not enough: a chart initialization failure leaves
  // a mounted but blank canvas. Assert that pixels were actually painted.
  const canvas = page.locator('section', { hasText: '登录趋势' }).locator('canvas');
  await expect(canvas).toBeVisible();
  await expect
    .poll(async () => canvas.evaluate((el: HTMLCanvasElement) => {
      const data = el.getContext('2d')!.getImageData(0, 0, el.width, el.height).data;
      let painted = 0;
      for (let i = 3; i < data.length; i += 4) if (data[i] > 0) painted += 1;
      return painted;
    }))
    .toBeGreaterThan(100);
  expect(pageErrors).toEqual([]);
});

test('administrators can edit OAuth clients without mutating immutable ownership fields', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin',
    adminClients: [oauthClient],
  };
  await installAPIMocks(page, state);

  await page.goto('/admin/clients');
  await page.getByRole('button', { name: '编辑', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('应用名称').fill('Renamed App');
  await dialog.getByLabel('Redirect URI（每行一个）', { exact: true }).fill([
    'https://new.example/callback',
    'https://backup.example/callback',
  ].join('\n'));
  await dialog.getByLabel('Post-logout Redirect URI（每行一个）').fill('https://new.example/signed-out');
  await dialog.getByLabel('Scopes（空格、逗号或换行分隔）').fill('openid email\ncustom');
  await dialog.getByLabel('Metadata（JSON 字符串键值）').fill(JSON.stringify({
    environment: 'production',
    team: 'identity',
  }));
  await dialog.getByRole('button', { name: '保存更改' }).click();

  await expect(dialog).toBeHidden();
  expect(state.adminClientUpdateCSRF).toBe('csrf-admin');
  expect(state.adminClientUpdateBody).toEqual({
    name: 'Renamed App',
    redirect_uris: ['https://new.example/callback', 'https://backup.example/callback'],
    post_logout_redirect_uris: ['https://new.example/signed-out'],
    grants: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'email', 'custom'],
    metadata: { environment: 'production', team: 'identity' },
    access_policy: 'open',
  });
  expect(state.adminClientUpdateBody).not.toHaveProperty('is_public');
  expect(state.adminClientUpdateBody).not.toHaveProperty('owner_id');
});

test('an allowlist client exposes its access list and saves changes with CSRF', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-access',
    adminClients: [{ ...oauthClient, access_policy: 'allowlist' } as typeof oauthClient],
  };
  await installAPIMocks(page, state);

  let putBody: unknown;
  let putCSRF: string | null = null;
  await page.route('**/api/admin/clients/example-client/access-users', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJSON(route, 200, [{
        user_id: user.id, username: user.username, display_name: user.display_name,
        status: 'active', created_at: '2026-01-01T00:00:00Z',
      }]);
      return;
    }
    putBody = route.request().postDataJSON();
    putCSRF = route.request().headers()['x-csrf-token'] ?? null;
    await fulfillJSON(route, 200, []);
  });

  await page.goto('/admin/clients');
  await expect(page.getByText('访问：白名单')).toBeVisible();
  await page.getByRole('button', { name: `管理 ${oauthClient.name} 访问名单` }).click();

  await expect(page.getByText('@alice')).toBeVisible();
  await page.getByRole('button', { name: '移除 alice' }).click();
  await page.getByRole('button', { name: '保存名单' }).click();

  await expect(page.getByText('访问名单已保存，名单外用户的现有令牌将在下次使用时失效。')).toBeVisible();
  expect(putBody).toEqual({ user_ids: [] });
  expect(putCSRF).toBe('csrf-access');
  await expect(page.getByText('名单为空：当前没有任何用户可以授权此应用。')).toBeVisible();
});

test('administrator client pagination is server-backed and preserved in the URL', async ({ page }) => {
  const adminClients = Array.from({ length: 21 }, (_, index) => ({
    ...oauthClient,
    id: `client-${index + 1}`,
    name: `Client ${index + 1}`,
  }));
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin',
    adminClients,
  };
  await installAPIMocks(page, state);

  await page.goto('/admin/clients?page=2');

  await expect(page.getByRole('heading', { name: 'Client 21' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Client 1', exact: true })).toHaveCount(0);
  await expect(page.getByText('2 / 2')).toBeVisible();
  expect(state.adminClientQueries).toContain('?page=2&page_size=20');

  await page.getByRole('button', { name: '上一页' }).click();
  await expect(page).toHaveURL(/\/admin\/clients$/);
  await expect(page.getByRole('heading', { name: 'Client 1', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Client 21' })).toHaveCount(0);
  expect(state.adminClientQueries).toContain('?page=1&page_size=20');
});

test('administrators can select an active owner while creating a client', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin',
    adminClients: [],
    adminUsers: [ownerUser, suspendedOwnerUser],
  };
  await installAPIMocks(page, state);

  await page.goto('/admin/clients');
  await page.getByRole('button', { name: '创建应用' }).first().click();
  const dialog = page.getByRole('dialog', { name: '创建应用' });
  await expect(dialog.getByRole('radio', { name: /Bob \(@bob\)/ })).toBeVisible();
  await expect(dialog.getByRole('radio', { name: /Suspended Owner/ })).toHaveCount(0);
  await dialog.getByLabel('搜索 Owner').fill('bob');
  await expect.poll(() => state.adminUserQueries?.some((query) => query.includes('page_size=8') && query.includes('q=bob'))).toBe(true);
  await dialog.getByRole('radio', { name: /Bob \(@bob\)/ }).check();
  await dialog.getByLabel('应用名称').fill('Owner App');
  await dialog.getByLabel(/Redirect URI/).first().fill('https://owner.example/callback');
  await dialog.getByRole('button', { name: '创建', exact: true }).click();

  await expect(dialog).toBeHidden();
  await page.getByRole('button', { name: '显示Client Secret' }).click();
  await expect(page.getByText('created-client-secret')).toBeVisible();
  expect(state.adminClientCreateCSRF).toBe('csrf-admin');
  expect(state.adminClientCreateBody).toEqual({
    name: 'Owner App',
    redirect_uris: ['https://owner.example/callback'],
    post_logout_redirect_uris: [],
    grants: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    is_public: false,
    owner_id: ownerUser.id,
  });
});

test('client owner transfer and removal require exact client-name confirmation', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin',
    adminClients: [oauthClient],
    adminUsers: [ownerUser, suspendedOwnerUser],
  };
  await installAPIMocks(page, state);

  await page.goto('/admin/clients');
  await page.getByRole('button', { name: '管理 Example App Owner' }).click();
  let ownerDialog = page.getByRole('dialog', { name: /管理 Client Owner/ });
  await ownerDialog.getByRole('radio', { name: /Bob \(@bob\)/ }).check();
  await ownerDialog.getByRole('button', { name: '继续' }).click();

  let confirmation = page.getByRole('dialog', { name: '确认变更 Client Owner' });
  let confirmButton = confirmation.getByRole('button', { name: '确认转移' });
  await expect(confirmButton).toBeDisabled();
  await confirmation.getByLabel('输入“Example App”以确认').fill('example app');
  await expect(confirmButton).toBeDisabled();
  await confirmation.getByLabel('输入“Example App”以确认').fill('Example App');
  await confirmButton.click();

  await expect(confirmation).toBeHidden();
  await expect(page.getByText(ownerUser.id)).toBeVisible();
  expect(state.adminClientOwnerUpdateBodies).toEqual([{ owner_id: ownerUser.id }]);

  await page.getByRole('button', { name: '管理 Example App Owner' }).click();
  ownerDialog = page.getByRole('dialog', { name: /管理 Client Owner/ });
  await ownerDialog.getByRole('radio', { name: /未分配/ }).check();
  await ownerDialog.getByRole('button', { name: '继续' }).click();
  confirmation = page.getByRole('dialog', { name: '确认变更 Client Owner' });
  confirmButton = confirmation.getByRole('button', { name: '确认解除' });
  await confirmation.getByLabel('输入“Example App”以确认').fill('Example App');
  await confirmButton.click();

  await expect(confirmation).toBeHidden();
  await expect(page.getByText(/Owner：/)).toContainText('未分配');
  expect(state.adminClientOwnerUpdateBodies).toEqual([{ owner_id: ownerUser.id }, { owner_id: null }]);
  expect(state.adminClientOwnerUpdateCSRFs).toEqual(['csrf-admin', 'csrf-admin']);
});

test('user role update errors remain visible inside the user drawer', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin',
    adminUsers: [user],
    adminUserIdentities: [],
    adminUserRoleUpdateError: '不能降级最后一个有效管理员',
  };
  await installAPIMocks(page, state);

  await page.goto('/admin/users');
  await page.getByRole('button', { name: 'alice', exact: true }).click();
  const drawer = page.getByRole('dialog', { name: /用户详情/ });
  await drawer.getByLabel('角色').click();
  await page.getByRole('option', { name: '管理员' }).click();
  await drawer.getByRole('button', { name: '保存角色' }).click();

  await expect(drawer.getByRole('alert')).toContainText('不能降级最后一个有效管理员');
  await expect(drawer).toBeVisible();
});

test('administrators can update user profiles and remove a confirmed external identity', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin',
    adminUsers: [user],
    adminUserIdentities: [githubIdentity],
  };
  await installAPIMocks(page, state);

  await page.goto('/admin/users');
  await page.getByRole('button', { name: 'alice', exact: true }).click();
  const drawer = page.getByRole('dialog', { name: /用户详情/ });
  await drawer.getByLabel('邮箱', { exact: true }).fill('alice.updated@example.com');
  await drawer.getByLabel('显示名称', { exact: true }).fill('Alice Updated');
  await drawer.getByLabel('头像 URL', { exact: true }).fill('https://cdn.example/alice.png');
  await drawer.getByLabel('Metadata（JSON 字符串键值）').fill(JSON.stringify({
    department: 'security',
    region: 'apac',
  }));
  await drawer.getByRole('button', { name: '保存资料' }).click();

  await expect(drawer.getByText('用户资料已更新。')).toBeVisible();
  expect(state.adminUserUpdateCSRF).toBe('csrf-admin');
  expect(state.adminUserUpdateBody).toEqual({
    email: 'alice.updated@example.com',
    display_name: 'Alice Updated',
    avatar_url: 'https://cdn.example/alice.png',
    metadata: { department: 'security', region: 'apac' },
  });

  await drawer.getByRole('button', { name: '解绑 github 身份' }).click();
  const confirmation = page.getByRole('dialog', { name: '解绑外部身份' });
  const confirmButton = confirmation.getByRole('button', { name: '确认解绑' });
  await expect(confirmButton).toBeDisabled();
  await confirmation.getByLabel('输入“github”以确认').fill('GitHub');
  await expect(confirmButton).toBeDisabled();
  await confirmation.getByLabel('输入“github”以确认').fill('github');
  await expect(confirmButton).toBeEnabled();
  await confirmButton.click();

  await expect(confirmation).toBeHidden();
  await expect(drawer.getByText('已解绑 github 身份。')).toBeVisible();
  await expect(drawer.getByText('未绑定外部身份')).toBeVisible();
  expect(state.adminUserIdentityDeleteCSRF).toBe('csrf-admin');
});

test('provider edits preserve the stored secret when the secret input is empty', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin',
    adminProviders: [externalProvider],
  };
  await installAPIMocks(page, state);
  await page.route('**/.well-known/openid-configuration', (route) => fulfillJSON(route, 200, {
    issuer: 'https://auth.example',
    authorization_endpoint: 'https://auth.example/authorize',
    token_endpoint: 'https://auth.example/token',
    jwks_uri: 'https://auth.example/.well-known/jwks.json',
  }));

  await page.goto('/admin/providers');
  await page.getByRole('button', { name: '编辑配置' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Client ID').fill('provider-client-updated');
  await expect(dialog.getByLabel('Client Secret')).toHaveValue('');
  await dialog.getByLabel('Scopes').fill('openid profile email');
  await dialog.getByRole('button', { name: '保存', exact: true }).click();

  await expect(dialog).toBeHidden();
  expect(state.adminProviderUpdateCSRF).toBe('csrf-admin');
  expect(state.adminProviderUpdateBody).toEqual({
    client_id: 'provider-client-updated',
    scopes: ['openid', 'profile', 'email'],
    discovery_url: 'https://idp.example/.well-known/openid-configuration',
    authorization_url: 'https://idp.example/authorize',
    token_url: 'https://idp.example/token',
    userinfo_url: 'https://idp.example/userinfo',
    enabled: true,
  });
  expect(state.adminProviderUpdateBody).not.toHaveProperty('client_secret');
});

test('provider validation result is cleared when the configuration revision changes', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin',
    adminProviders: [externalProvider],
  };
  await installAPIMocks(page, state);
  await page.route('**/.well-known/openid-configuration', (route) => fulfillJSON(route, 200, {
    issuer: 'https://auth.example',
    authorization_endpoint: 'https://auth.example/authorize',
    token_endpoint: 'https://auth.example/token',
    jwks_uri: 'https://auth.example/.well-known/jwks.json',
  }));

  await page.goto('/admin/providers');
  await page.getByRole('button', { name: '配置校验' }).click();
  await expect(page.getByText('配置有效', { exact: true })).toBeVisible();

  await page.getByRole('button', { name: '编辑配置' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Client ID').fill('provider-client-revision-5');
  await dialog.getByRole('button', { name: '保存', exact: true }).click();

  await expect(dialog).toBeHidden();
  await expect(page.getByText('配置有效', { exact: true })).toHaveCount(0);
  await expect(page.getByText('配置修订 #5', { exact: true })).toBeVisible();
  expect(state.adminProviderTestRequests).toBe(1);
});

test('provider management remains usable when public discovery is unavailable', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin',
    adminProviders: [externalProvider],
  };
  await installAPIMocks(page, state);
  await page.route('**/.well-known/openid-configuration', (route) => fulfillJSON(route, 503, {
    error: 'discovery_unavailable',
  }));

  await page.goto('/admin/providers');

  await expect(page.getByRole('heading', { name: externalProvider.name })).toBeVisible();
  await expect(page.getByRole('alert')).toContainText('暂时不能生成 Callback URL');
  await page.getByRole('button', { name: '编辑配置' }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
});

test('disabled provider creation is a single request with an explicit enabled state', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin',
    adminProviders: [],
  };
  await installAPIMocks(page, state);
  await page.route('**/.well-known/openid-configuration', (route) => fulfillJSON(route, 200, {
    issuer: 'https://auth.example',
    authorization_endpoint: 'https://auth.example/authorize',
    token_endpoint: 'https://auth.example/token',
    jwks_uri: 'https://auth.example/.well-known/jwks.json',
  }));

  await page.goto('/admin/providers');
  await page.getByRole('button', { name: '添加身份提供者' }).first().click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('名称').fill('disabled-github');
  await dialog.getByLabel('Client ID').fill('disabled-client');
  await dialog.getByLabel('Client Secret').fill('disabled-secret');
  await dialog.getByLabel('Scopes').fill('read:user user:email');
  await dialog.getByRole('checkbox', { name: /创建后立即启用/ }).uncheck();
  await dialog.getByRole('button', { name: '添加', exact: true }).click();

  await expect(dialog).toBeHidden();
  expect(state.adminProviderCreateCSRF).toBe('csrf-admin');
  expect(state.adminProviderCreateBody).toEqual({
    name: 'disabled-github',
    type: 'github',
    client_id: 'disabled-client',
    client_secret: 'disabled-secret',
    enabled: false,
    scopes: ['read:user', 'user:email'],
  });
});

test('runtime branding propagates to the sidebar and saves with CSRF', async ({ page }) => {
  let updateCSRF: string | null = null;
  let updateBody: unknown;
  await installAPIMocks(page, {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-brand',
    systemStatus,
  });
  await page.route('**/api/branding', (route) => fulfillJSON(route, 200, { title: 'Acme ID', logo_url: '' }));
  await page.route('**/api/admin/branding', async (route) => {
    updateCSRF = route.request().headers()['x-csrf-token'] ?? null;
    updateBody = route.request().postDataJSON();
    await fulfillJSON(route, 200, { title: 'Acme SSO', logo_url: 'https://cdn.example.com/logo.png' });
  });

  await page.goto('/admin/system');
  const sidebar = page.getByRole('complementary', { name: '管理后台导航' });
  await expect(sidebar.getByText('Acme ID')).toBeVisible();

  await page.getByLabel('站点名称').fill('Acme SSO');
  await page.getByLabel(/Logo URL/).fill('https://cdn.example.com/logo.png');
  await page.getByRole('button', { name: '保存品牌设置' }).click();

  await expect(page.getByText('品牌设置已保存，立即对所有实例生效。')).toBeVisible();
  expect(updateBody).toEqual({ title: 'Acme SSO', logo_url: 'https://cdn.example.com/logo.png' });
  expect(updateCSRF).toBe('csrf-brand');
  await expect(sidebar.getByText('Acme SSO')).toBeVisible();
});

test('admin invites are created with CSRF and the one-time code is shown once', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-invite',
  };
  await installAPIMocks(page, state);
  await page.route('**/api/admin/settings/registration', (route) => fulfillJSON(route, 200, {
    mode: 'invite_only', require_email_verification: true, allowed_email_domains: [],
    pending_registration_ttl: '72h',
    invite_default_ttl: '168h', invite_default_max_uses: 1,
  }));

  const activeInvite = {
    id: '77777777-7777-7777-7777-777777777777',
    created_by: null,
    note: '给测试同学',
    max_uses: 3,
    used_count: 1,
    reserved_count: 1,
    expires_at: '2026-08-30T00:00:00Z',
    revoked_at: null,
    created_at: '2026-07-20T00:00:00Z',
    status: 'active',
  };
  let createBody: unknown;
  const createCSRFs: Array<string | null> = [];
  let createAttempts = 0;
  let revokeCSRF: string | null = null;
  let revokedID = '';
  await page.route('**/api/admin/invites', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJSON(route, 200, [activeInvite]);
      return;
    }
    createBody = route.request().postDataJSON();
    createCSRFs.push(route.request().headers()['x-csrf-token'] ?? null);
    createAttempts += 1;
    if (createAttempts === 1) {
      await fulfillJSON(route, 403, { error: 'recent authentication is required' });
      return;
    }
    await fulfillJSON(route, 201, {
      ...activeInvite,
      id: '88888888-8888-8888-8888-888888888888',
      note: '新同事',
      max_uses: 3,
      used_count: 0,
      reserved_count: 0,
      code: 'one-time-code-abc',
      register_url: 'https://auth.example.test/register?invite=one-time-code-abc',
    });
  });
  await page.route('**/api/admin/invites/*', async (route) => {
    revokeCSRF = route.request().headers()['x-csrf-token'] ?? null;
    revokedID = new URL(route.request().url()).pathname.split('/').pop() ?? '';
    await route.fulfill({ status: 204 });
  });

  await page.goto('/admin/invites');
  await expect(page.getByRole('link', { name: '邀请管理' })).toHaveAttribute('aria-current', 'page');
  await expect(page.getByText('给测试同学')).toBeVisible();
  await expect(page.getByText(/已使用 1 \/ 待验证 1 \/ 总次数 3/)).toBeVisible();

  await page.getByRole('button', { name: '创建邀请' }).click();
  await page.getByLabel('备注（可选）').fill('新同事');
  await page.getByLabel('可用次数（可选）').fill('3');
  await page.getByRole('button', { name: '创建', exact: true }).click();

  await expect(page.getByRole('dialog', { name: '重新验证身份' })).toBeVisible();
  await page.getByLabel('当前密码').fill('current-password');
  await page.getByRole('button', { name: '使用密码验证' }).click();

  await expect(page.getByText('邀请已创建 — 请立即保存，关闭后无法再次查看')).toBeVisible();
  await expect(page.getByText('one-time-code-abc', { exact: true })).toBeVisible();
  expect(createBody).toEqual({ note: '新同事', max_uses: 3 });
  expect(createCSRFs).toEqual(['csrf-invite', 'csrf-reauthenticated']);
  expect(state.reauthBody).toEqual({ password: 'current-password' });
  expect(state.reauthCSRF).toBe('csrf-invite');

  await page.getByRole('button', { name: `吊销邀请 给测试同学` }).click();
  await page.getByRole('dialog').getByRole('button', { name: '吊销' }).click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(revokedID).toBe(activeInvite.id);
  expect(revokeCSRF).toBe('csrf-reauthenticated');
});

test('registration settings save with CSRF and open mode forces verification', async ({ page }) => {
  await installAPIMocks(page, {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-reg-settings',
    systemStatus,
  });
  let putBody: unknown;
  let putCSRF: string | null = null;
  await page.route('**/api/admin/settings/registration', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJSON(route, 200, {
        mode: 'closed', require_email_verification: true, allowed_email_domains: [],
        pending_registration_ttl: '72h',
        invite_default_ttl: '168h', invite_default_max_uses: 1,
      });
      return;
    }
    putBody = route.request().postDataJSON();
    putCSRF = route.request().headers()['x-csrf-token'] ?? null;
    await fulfillJSON(route, 200, {
      mode: 'open', require_email_verification: true, allowed_email_domains: ['corp.example.com'],
      pending_registration_ttl: '72h',
      invite_default_ttl: '168h', invite_default_max_uses: 1,
    });
  });

  await page.goto('/admin/system');
  await expect(page.getByRole('heading', { name: '注册设置' })).toBeVisible();

  await page.getByRole('radio', { name: /开放/ }).check();
  await expect(page.getByRole('checkbox', { name: /要求邮箱验证/ })).toBeDisabled();
  await page.getByLabel('允许的邮箱域名（每行一个，留空不限制）').fill('corp.example.com');
  await page.getByRole('button', { name: '保存注册设置' }).click();

  await expect(page.getByText('注册设置已保存，立即对所有实例生效。')).toBeVisible();
  expect(putBody).toEqual({
    mode: 'open',
    require_email_verification: true,
    allowed_email_domains: ['corp.example.com'],
    pending_registration_ttl: '72h',
    invite_default_ttl: '168h',
    invite_default_max_uses: 1,
  });
  expect(putCSRF).toBe('csrf-reg-settings');
});

test('provider reauthentication restores registration settings and retries the save once', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-provider-settings',
    hasPassword: false,
    identities: [githubIdentity],
    systemStatus,
  };
  await installAPIMocks(page, state);
  let putAttempts = 0;
  let putBody: unknown;
  const putCSRFs: Array<string | null> = [];
  await page.route('**/api/admin/settings/registration', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJSON(route, 200, {
        mode: 'closed', require_email_verification: true, allowed_email_domains: [],
        pending_registration_ttl: '72h', invite_default_ttl: '168h', invite_default_max_uses: 1,
      });
      return;
    }
    putAttempts += 1;
    putBody = route.request().postDataJSON();
    putCSRFs.push(route.request().headers()['x-csrf-token'] ?? null);
    if (putAttempts === 1) {
      await fulfillJSON(route, 403, { error: 'recent authentication is required' });
      return;
    }
    await fulfillJSON(route, 200, putBody);
  });

  await page.goto('/admin/system');
  await page.getByRole('radio', { name: /开放/ }).check();
  await page.getByLabel('允许的邮箱域名（每行一个，留空不限制）').fill('corp.example.com');
  await page.getByLabel('待验证注册有效期').fill('48h');
  await page.getByRole('button', { name: '保存注册设置' }).click();

  await expect(page.getByRole('dialog', { name: '重新验证身份' })).toBeVisible();
  await page.getByRole('button', { name: '使用 github 验证' }).click();
  await expect(page.getByText('注册设置已保存，立即对所有实例生效。')).toBeVisible();

  expect(putAttempts).toBe(2);
  expect(putBody).toEqual({
    mode: 'open',
    require_email_verification: true,
    allowed_email_domains: ['corp.example.com'],
    pending_registration_ttl: '48h',
    invite_default_ttl: '168h',
    invite_default_max_uses: 1,
  });
  expect(putCSRFs).toEqual(['csrf-provider-settings', 'csrf-provider-reauthenticated']);
  expect(state.providerReauthBody).toEqual({ return_to: '/admin/system' });
  expect(state.providerReauthCSRF).toBe('csrf-provider-settings');
  expect(await page.evaluate(() => sessionStorage.getItem('nyauth:reauth:registration-settings'))).toBeNull();
});

test('provider reauthentication denial restores the unsaved registration form', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-provider-denied',
    hasPassword: false,
    identities: [githubIdentity],
    providerReauthError: 'provider_denied',
    systemStatus,
  };
  await installAPIMocks(page, state);
  let putAttempts = 0;
  await page.route('**/api/admin/settings/registration', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJSON(route, 200, {
        mode: 'closed', require_email_verification: true, allowed_email_domains: [],
        pending_registration_ttl: '72h', invite_default_ttl: '168h', invite_default_max_uses: 1,
      });
      return;
    }
    putAttempts += 1;
    await fulfillJSON(route, 403, { error: 'recent authentication is required' });
  });

  await page.goto('/admin/system');
  await page.getByRole('radio', { name: /开放/ }).check();
  await page.getByLabel('允许的邮箱域名（每行一个，留空不限制）').fill('lab.example.org');
  await page.getByLabel('待验证注册有效期').fill('24h');
  await page.getByRole('button', { name: '保存注册设置' }).click();
  await page.getByRole('button', { name: '使用 github 验证' }).click();

  await expect(page.getByRole('alert')).toHaveText('你取消了外部身份提供商的授权。');
  await expect(page.getByRole('radio', { name: /开放/ })).toBeChecked();
  await expect(page.getByLabel('允许的邮箱域名（每行一个，留空不限制）')).toHaveValue('lab.example.org');
  await expect(page.getByLabel('待验证注册有效期')).toHaveValue('24h');
  await expect(page).toHaveURL(/\/admin\/system$/);
  expect(putAttempts).toBe(1);
  expect(await page.evaluate(() => sessionStorage.getItem('nyauth:reauth:registration-settings'))).toBeNull();
});

test('SMTP candidate is saved, tested, activated, rolled back and disabled with CSRF', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-mail',
    systemStatus,
  };
  await installAPIMocks(page, state);
  await page.route('**/api/admin/settings/registration', (route) => fulfillJSON(route, 200, {
    mode: 'closed', require_email_verification: true, allowed_email_domains: [],
    pending_registration_ttl: '72h', invite_default_ttl: '168h', invite_default_max_uses: 1,
  }));

  const active: MailConfig = {
    ...mailSettings.active!,
    source: 'database',
    id: '10000000-0000-0000-0000-000000000001',
    revision: 4,
    created_at: '2026-07-25T10:00:00Z',
  };
  const candidateID = '10000000-0000-0000-0000-000000000002';
  let runtimeSettings: MailSettings = {
    ...mailSettings,
    mode: 'active',
    state_revision: 10,
    active,
  };
  let saveAttempts = 0;
  const saveBodies: unknown[] = [];
  const saveCSRFs: Array<string | null> = [];
  let testBody: unknown;
  let activateBody: unknown;
  let rollbackBody: unknown;
  let disableBody: unknown;

  await page.route('**/api/admin/settings/mail**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/admin/settings/mail' && request.method() === 'GET') {
      await fulfillJSON(route, 200, runtimeSettings);
      return;
    }
    if (path === '/api/admin/settings/mail/candidate' && request.method() === 'PUT') {
      saveAttempts += 1;
      saveBodies.push(request.postDataJSON());
      saveCSRFs.push(await request.headerValue('x-csrf-token'));
      if (saveAttempts === 1) {
        await fulfillJSON(route, 403, { error: 'recent authentication is required' });
        return;
      }
      const body = request.postDataJSON() as Record<string, unknown>;
      const candidate: MailConfig = {
        source: 'database', id: candidateID, revision: 5,
        host: String(body.host), port: Number(body.port), username: String(body.username),
        tls_mode: String(body.tls_mode) as MailConfig['tls_mode'],
        from_address: String(body.from_address), from_name: String(body.from_name),
        public_base_url: String(body.public_base_url), connect_timeout: String(body.connect_timeout),
        send_timeout: String(body.send_timeout), password_configured: body.password !== '',
        created_at: '2026-07-26T12:00:00Z',
      };
      runtimeSettings = { ...runtimeSettings, state_revision: 11, candidate };
      await fulfillJSON(route, 201, { candidate, state_revision: 11 });
      return;
    }
    if (path === '/api/admin/settings/mail/candidate/test' && request.method() === 'POST') {
      testBody = request.postDataJSON();
      runtimeSettings = { ...runtimeSettings, state_revision: 12 };
      await fulfillJSON(route, 200, {
        result: 'success', tested_at: '2026-07-26T12:01:00Z', state_revision: 12,
      });
      return;
    }
    if (path === '/api/admin/settings/mail/activate' && request.method() === 'POST') {
      activateBody = request.postDataJSON();
      runtimeSettings = {
        ...runtimeSettings,
        mode: 'active', configured: true, available: true, state_revision: 13,
        active: runtimeSettings.candidate, previous: runtimeSettings.active, candidate: undefined,
      };
      await fulfillJSON(route, 200, { status: 'activated', state_revision: 13 });
      return;
    }
    if (path === '/api/admin/settings/mail/rollback' && request.method() === 'POST') {
      rollbackBody = request.postDataJSON();
      const previous = runtimeSettings.previous;
      runtimeSettings = {
        ...runtimeSettings,
        state_revision: 14,
        active: previous,
        previous: runtimeSettings.active,
      };
      await fulfillJSON(route, 200, { status: 'rolled_back', state_revision: 14 });
      return;
    }
    if (path === '/api/admin/settings/mail/disable' && request.method() === 'POST') {
      disableBody = request.postDataJSON();
      runtimeSettings = {
        ...runtimeSettings,
        mode: 'disabled', configured: false, available: false, state_revision: 15, active: undefined,
      };
      await fulfillJSON(route, 200, { status: 'disabled', state_revision: 15 });
      return;
    }
    await fulfillJSON(route, 404, { error: `unmocked mail endpoint: ${path}` });
  });

  await page.goto('/admin/system');
  await expect(page.getByRole('heading', { name: 'SMTP 动态配置' })).toBeVisible();
  await page.getByLabel('SMTP 主机').fill('smtp.dynamic.example.com');
  await page.getByLabel('SMTP 密码（留空继承）').fill('smtp-runtime-secret');
  await page.getByRole('button', { name: '保存候选配置' }).click();

  await expect(page.getByRole('dialog', { name: '重新验证身份' })).toBeVisible();
  await page.getByLabel('当前密码').fill('current-password');
  await page.getByRole('button', { name: '使用密码验证' }).click();
  await expect(page.getByText(/候选配置已保存/)).toBeVisible();

  await page.getByLabel('测试邮件收件地址').fill('operator@example.com');
  await page.getByRole('button', { name: '发送真实测试' }).click();
  await expect(page.getByText(/测试邮件已成功发送/)).toBeVisible();
  await page.getByRole('button', { name: '激活候选版本' }).click();
  await expect(page.getByText(/候选配置已激活/)).toBeVisible();
  await expect(page.getByText('smtp.dynamic.example.com:587')).toBeVisible();

  await page.getByRole('button', { name: '回滚到上一版本' }).click();
  await expect(page.getByText('邮件配置已回滚到上一版本。')).toBeVisible();
  await page.getByRole('button', { name: '禁用邮件服务' }).click();
  await page.getByLabel('输入“禁用邮件”以确认').fill('禁用邮件');
  await page.getByRole('button', { name: '确认禁用' }).click();
  await expect(page.getByText(/邮件服务已禁用/)).toBeVisible();
  await expect(page.getByText('已禁用', { exact: true }).first()).toBeVisible();

  expect(saveAttempts).toBe(2);
  expect(saveBodies).toEqual([
    expect.objectContaining({ host: 'smtp.dynamic.example.com', password: 'smtp-runtime-secret', expected_revision: 10 }),
    expect.objectContaining({ host: 'smtp.dynamic.example.com', password: 'smtp-runtime-secret', expected_revision: 10 }),
  ]);
  expect(saveCSRFs).toEqual(['csrf-mail', 'csrf-reauthenticated']);
  expect(testBody).toEqual({ expected_revision: 11, version_id: candidateID, email: 'operator@example.com' });
  expect(activateBody).toEqual({ expected_revision: 12, version_id: candidateID });
  expect(rollbackBody).toEqual({ expected_revision: 13 });
  expect(disableBody).toEqual({ expected_revision: 14 });
});

test('provider reauthentication restores SMTP fields once without retaining or replaying the password', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-mail-provider',
    hasPassword: false,
    identities: [githubIdentity],
    systemStatus,
  };
  await installAPIMocks(page, state);
  await page.route('**/api/admin/settings/registration', (route) => fulfillJSON(route, 200, {
    mode: 'closed', require_email_verification: true, allowed_email_domains: [],
    pending_registration_ttl: '72h', invite_default_ttl: '168h', invite_default_max_uses: 1,
  }));

  let runtimeSettings: MailSettings = { ...mailSettings, state_revision: 20 };
  let saveAttempts = 0;
  const saveBodies: Array<Record<string, unknown>> = [];
  await page.route('**/api/admin/settings/mail**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/admin/settings/mail' && request.method() === 'GET') {
      await fulfillJSON(route, 200, runtimeSettings);
      return;
    }
    if (path === '/api/admin/settings/mail/candidate' && request.method() === 'PUT') {
      saveAttempts += 1;
      const body = request.postDataJSON() as Record<string, unknown>;
      saveBodies.push(body);
      if (saveAttempts === 1) {
        await fulfillJSON(route, 403, { error: 'recent authentication is required' });
        return;
      }
      const candidate: MailConfig = {
        ...mailSettings.active!, source: 'database', id: '20000000-0000-0000-0000-000000000001', revision: 1,
        host: String(body.host), password_configured: true, created_at: '2026-07-26T13:00:00Z',
      };
      runtimeSettings = { ...runtimeSettings, state_revision: 21, candidate };
      await fulfillJSON(route, 201, { candidate, state_revision: 21 });
      return;
    }
    await fulfillJSON(route, 404, { error: `unmocked mail endpoint: ${path}` });
  });

  await page.goto('/admin/system');
  await page.getByLabel('SMTP 主机').fill('smtp.provider.example.com');
  await page.getByLabel('SMTP 密码（留空继承）').fill('must-not-enter-session-storage');
  await page.getByRole('button', { name: '保存候选配置' }).click();
  await page.getByRole('button', { name: '使用 github 验证' }).click();

  await expect(page.getByText(/出于安全原因密码未保存/)).toBeVisible();
  await expect(page.getByLabel('SMTP 主机')).toHaveValue('smtp.provider.example.com');
  await expect(page.getByLabel('SMTP 密码（留空继承）')).toHaveValue('');
  expect(saveAttempts).toBe(1);
  expect(await page.evaluate(() => sessionStorage.getItem('nyauth:reauth:mail-settings'))).toBeNull();

  await page.getByLabel('SMTP 密码（留空继承）').fill('reentered-after-provider');
  await page.getByRole('button', { name: '保存候选配置' }).click();
  await expect(page.getByText(/候选配置已保存/)).toBeVisible();
  expect(saveAttempts).toBe(2);
  expect(saveBodies[0].password).toBe('must-not-enter-session-storage');
  expect(saveBodies[1].password).toBe('reentered-after-provider');
  expect(state.providerReauthBody).toEqual({ return_to: '/admin/system' });
  expect(state.providerReauthCSRF).toBe('csrf-mail-provider');
});

test('the system status page renders the backend status DTO and admin navigation entry', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin',
    systemStatus,
  };
  await installAPIMocks(page, state);

  await page.goto('/admin/system');

  await expect(page.getByRole('heading', { name: '系统状态', exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: '系统状态' })).toHaveAttribute('aria-current', 'page');
  await expect(page.getByText('0.3.0-test')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'PostgreSQL' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Redis' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'JWK' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Provider 快照' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'SMTP 邮件' })).toBeVisible();
  await expect(page.getByText('signing-key-2026-07')).toBeVisible();
  await expect(page.getByText('12', { exact: true })).toBeVisible();
});
