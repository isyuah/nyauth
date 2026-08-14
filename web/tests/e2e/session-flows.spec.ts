import { expect, test, type Locator, type Page, type Route } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import type {
  AdminUserClientSummary,
  AdminUserOverview,
  AdminUserSecurity,
  AuditLog,
  AuditLogOptions,
  DashboardStats,
  LoginTrend,
  MailConfig,
  MailSettings,
  MailTrend,
  OAuthClient,
  OAuthSettings,
  RegistrationTrend,
  StatsTrendDays,
  User,
} from '../../src/lib/api';
import { DEFAULT_CLAIM_ASSIGNMENT_POLICIES, DEFAULT_SCOPE_DEFINITIONS } from '../../src/lib/oauth-catalog';

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
  myClientUpdateBody?: unknown;
  myClientUpdateCSRF?: string | null;
  myClientLogoMethod?: string;
  myClientLogoCSRF?: string | null;
  myClientLogoContentType?: string | null;
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
  adminClientPublisherReviewCSRFs?: Array<string | null>;
  adminClientPublisherReviewMethods?: string[];
  adminClientPublisherReviewRecentAuthenticationFailures?: number;
  adminUsers?: Array<typeof user>;
  adminUserQueries?: string[];
  adminUserIdentities?: Array<typeof githubIdentity>;
  adminUserUpdateBody?: unknown;
  adminUserUpdateCSRF?: string | null;
  adminUserUpdateRequests?: number;
  adminUserUpdateRecentAuthenticationFailures?: number;
  adminUserIdentityDeleteCSRF?: string | null;
  adminUserRoleUpdateError?: string;
  adminProviders?: Array<typeof externalProvider>;
  adminProviderCreateBody?: unknown;
  adminProviderCreateCSRF?: string | null;
  adminProviderUpdateBody?: unknown;
  adminProviderUpdateCSRF?: string | null;
  adminProviderTestRequests?: number;
  systemStatus?: typeof systemStatus;
  avatarURL?: string | null;
  avatarUploadCSRF?: string | null;
  avatarUploadContentType?: string | null;
  avatarDeleteCSRF?: string | null;
  meRequests?: number;
	selfUpdateBody?: unknown;
  mfaStatusRequests?: number;
  passkeyListRequests?: number;
  sessionListRequests?: number;
  trustedDeviceListRequests?: number;
  loginHistoryRequests?: number;
  trustedDeviceDeleteCSRF?: string | null;
  authorizationListRequests?: number;
  authorizationQueries?: string[];
  authorizations?: Array<typeof oauthAuthorization>;
  adminUserOverviewRequests?: Record<string, number>;
  adminUserSecurityRequests?: Record<string, number>;
  adminUserSessionRequests?: Record<string, number>;
  adminUserIdentityRequests?: Record<string, number>;
  adminUserAuthorizationRequests?: Record<string, number>;
  adminUserClientRequests?: Record<string, number>;
  adminUserActivityRequests?: Record<string, number>;
  adminUserSessionDeleteCSRF?: string | null;
  adminUserSessionDeletedID?: string;
  auditLogs?: AuditLog[];
  auditLogQueries?: string[];
  auditLogOptionsRequests?: number;
  auditExportQueries?: string[];
}

const user: User = {
  id: '11111111-1111-1111-1111-111111111111',
  username: 'alice',
  email: 'alice@example.com',
  display_name: 'Alice',
  avatar_url: null as string | null,
  metadata: { department: 'engineering' },
  status: 'active',
  role: 'user' as Role,
  created_at: '2026-01-01T00:00:00Z',
  last_login_at: '2026-01-02T00:00:00Z',
};

const ownerUser: User = {
  ...user,
  id: '55555555-5555-5555-5555-555555555555',
  username: 'bob',
  email: 'bob@example.com',
  display_name: 'Bob',
};

const suspendedOwnerUser: User = {
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
    session_idle_expires_at: '2026-01-03T00:00:00Z',
    session_expires_at: '2026-01-04T00:00:00Z',
    recent_authentication_expires_at: '2026-01-01T00:10:00Z',
  },
  {
    id: 'session-other',
    current: false,
    ip_address: '198.51.100.24',
    user_agent: 'Mozilla/5.0 (Android 15) Firefox/128.0',
    created_at: '2026-01-01T01:00:00Z',
    last_seen_at: '2026-01-02T01:00:00Z',
    authenticated_at: '2026-01-01T01:00:00Z',
    session_idle_expires_at: '2026-01-03T01:00:00Z',
    session_expires_at: '2026-01-04T01:00:00Z',
    recent_authentication_expires_at: '2026-01-01T01:10:00Z',
  },
];

const trustedDevices = [
  {
    id: 'trusted-current', current: true, ip_address: '192.0.2.10',
    user_agent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/126.0',
    created_at: '2026-01-01T00:00:00Z', last_used_at: '2026-01-02T00:00:00Z', expires_at: '2026-02-01T00:00:00Z',
  },
  {
    id: 'trusted-other', current: false, ip_address: '198.51.100.24',
    user_agent: 'Mozilla/5.0 (Android 15) Firefox/128.0',
    created_at: '2026-01-01T01:00:00Z', last_used_at: '2026-01-02T01:00:00Z', expires_at: '2026-02-01T01:00:00Z',
  },
];

const loginHistory = [
  {
    id: 'history-success', result: 'success', authentication_method: 'password', second_factor: 'trusted_device',
    ip_address: '192.0.2.10', user_agent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/126.0', created_at: '2026-01-02T00:00:00Z',
  },
  {
    id: 'history-failure', result: 'failure', authentication_method: 'password', second_factor: 'totp',
    ip_address: '198.51.100.24', user_agent: 'Mozilla/5.0 (Android 15) Firefox/128.0', created_at: '2026-01-01T23:00:00Z',
  },
];

const oauthAuthorization = {
  id: '22222222-2222-2222-2222-222222222222',
  client_id: 'example-client',
  client_name: 'Example App',
  client_name_at_grant: 'Example App',
  logo_url: '/media/client-logos/99999999-9999-4999-8999-999999999999/128.webp',
  homepage_uri: 'https://app.example',
  privacy_policy_uri: 'https://app.example/privacy',
  terms_of_service_uri: 'https://app.example/terms',
  homepage_uri_at_grant: 'https://app.example',
  privacy_policy_uri_at_grant: 'https://app.example/privacy',
  terms_of_service_uri_at_grant: 'https://app.example/terms',
  client_identity_revision: 1,
  current_identity_revision: 1,
  client_authorization_revision: 1,
  current_authorization_revision: 1,
  application_changed: false,
  reauthorization_required: false,
  scopes: ['openid', 'profile', 'offline_access'],
  optional_scopes: [],
  allowed_claims: ['sub', 'preferred_username', 'name', 'picture'],
  granted_at: '2026-01-01T00:00:00Z',
  last_used_at: '2026-01-02T00:00:00Z',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-02T00:00:00Z',
};

const oauthClient: OAuthClient = {
  id: 'example-client',
  name: 'Example App',
  homepage_uri: 'https://app.example',
  privacy_policy_uri: 'https://app.example/privacy',
  terms_of_service_uri: 'https://app.example/terms',
  current_logo_id: null,
  logo_url: null,
  identity_revision: 1,
  authorization_revision: 1,
  redirect_uris: ['https://app.example/callback'],
  post_logout_redirect_uris: ['https://app.example/signed-out'],
  grants: ['authorization_code', 'refresh_token'],
  scopes: ['openid', 'profile', 'offline_access'],
  optional_scopes: [],
  allowed_claims: ['sub', 'preferred_username', 'name', 'picture'],
  is_public: false,
  secret_hint: 'abcd1234',
  secret_version: 1,
  secret_rotated_at: '2026-01-01T00:00:00Z',
  owner_id: user.id as string | null,
  publisher_type: 'user_registered',
  publisher_verification_status: 'unverified',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

const oauthSettings: OAuthSettings = {
  revision: 1,
  self_service_client_creation_enabled: true,
  public_clients_enabled: true,
  allowed_grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
  allowed_scopes: ['openid', 'profile', 'email', 'offline_access'],
  scope_definitions: DEFAULT_SCOPE_DEFINITIONS,
  claim_assignment_policies: DEFAULT_CLAIM_ASSIGNMENT_POLICIES,
  max_redirect_uris: 20,
  max_post_logout_redirect_uris: 20,
};

const externalProvider = {
  id: '44444444-4444-4444-4444-444444444444',
  name: 'company-sso',
  display_name: 'Company SSO',
  icon_key: 'globe',
  type: 'generic',
  client_id: 'provider-client',
  scopes: ['openid', 'profile'],
  discovery_url: 'https://idp.example/.well-known/openid-configuration',
  authorization_url: 'https://idp.example/authorize',
  token_url: 'https://idp.example/token',
  userinfo_url: 'https://idp.example/userinfo',
  enabled: true,
  import_avatar: false,
  avatar_allowed_hosts: [],
  revision: 4,
  metadata: { environment: 'production' },
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-02T00:00:00Z',
};

const systemStatus = {
  status: 'ok',
  operating_state: 'normal',
  version: '0.3.0-test',
  disabled_rate_limit_groups: [],
  schema: {
    status: 'ok',
    version: 2,
    required_version: 2,
  },
  services: {
    postgresql: { status: 'ok', latency_ms: 3 },
    redis: { status: 'ok', latency_ms: 2 },
    providers: { status: 'degraded', latency_ms: 8, snapshot_revision: 12 },
    jwk: { status: 'ok', latency_ms: 1 },
    mail: { status: 'ok', mode: 'fallback', configured: true, available: true, circuit_state: 'closed' },
    media: { status: 'ok', backend: 'local', configured: true },
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

const dashboardStats = {
  user_count: 12,
  app_count: 3,
  login_count_7d: 41,
  active_sessions: 5,
  failed_logins_7d: 4,
  pending_registrations: 6,
  completed_registrations_7d: 18,
  registration_completion_rate_30d: 0.825,
  mail_backlog: 7,
  mail_failures_24h: 2,
  smtp_circuit_state: 'closed',
  mail_stats_available_from: '2026-07-27T00:00:00Z',
  refreshed_at: '2026-07-27T00:05:00Z',
} satisfies DashboardStats;

const dashboardLoginTrend = {
  labels: ['07-20', '07-21', '07-22', '07-23', '07-24', '07-25', '07-26'],
  values: [3, 5, 2, 8, 6, 4, 7],
} satisfies LoginTrend;

function trendDaysEndingAtFixture(days: StatsTrendDays): string[] {
  const end = Date.UTC(2026, 6, 26);
  return Array.from({ length: days }, (_, index) =>
    new Date(end - (days - 1 - index) * 24 * 60 * 60 * 1000).toISOString().slice(0, 10),
  );
}

function registrationTrendFor(days: StatsTrendDays): RegistrationTrend {
  return {
    timezone: 'UTC',
    points: trendDaysEndingAtFixture(days).map((day, index) => {
      const daysFromEnd = days - 1 - index;
      if (daysFromEnd === 1) return {
        day,
        registrations_started: Math.max(1, Math.floor(days / 7)),
        registrations_completed: 2,
        registrations_expired: 1,
        invites_reserved: 0,
        invites_consumed: 0,
        invites_released: 0,
      };
      if (daysFromEnd === 0) return {
        day,
        registrations_started: 4,
        registrations_completed: 3,
        registrations_expired: 0,
        invites_reserved: 0,
        invites_consumed: 0,
        invites_released: 0,
      };
      return {
        day,
        registrations_started: 0,
        registrations_completed: 0,
        registrations_expired: 0,
        invites_reserved: 0,
        invites_consumed: 0,
        invites_released: 0,
      };
    }),
  } satisfies RegistrationTrend;
}

function mailTrendFor(days: StatsTrendDays): MailTrend {
  return {
    timezone: 'UTC',
    available_from: '2026-07-25T00:00:00Z',
    points: trendDaysEndingAtFixture(days).map((day, index) => {
      const daysFromEnd = days - 1 - index;
      if (daysFromEnd === 1) return {
        day,
        enqueued: Math.max(2, Math.floor(days / 3)),
        sent: 6,
        other_failures: 2,
        rejected: 1,
        expired: 0,
      };
      if (daysFromEnd === 0) return {
        day,
        enqueued: 5,
        sent: 4,
        other_failures: 1,
        rejected: 0,
        expired: 1,
      };
      return { day, enqueued: 0, sent: 0, other_failures: 0, rejected: 0, expired: 0 };
    }),
  } satisfies MailTrend;
}

const githubIdentity = {
  id: '33333333-3333-3333-3333-333333333333',
  user_id: user.id,
  provider: 'github',
  provider_type: 'github',
  provider_display_name: 'GitHub',
  provider_icon_key: 'auto',
  external_id: 'github-123',
  external_username: 'alice-gh',
  external_email: 'alice@example.com',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

const adminUserActivity: AuditLog = {
  id: '99999999-9999-9999-9999-999999999999',
  event: 'user.profile_updated',
  actor_id: user.id,
  actor_name: user.username,
  target_type: 'user',
  target_id: user.id,
  ip_address: '192.0.2.10',
  user_agent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/126.0',
  result: 'success',
  risk_level: 'low',
  details: { fields: ['display_name'] },
  created_at: '2026-01-03T00:00:00Z',
};

const auditLogOptions: AuditLogOptions = {
  events: ['user.login', 'user.profile_updated', 'client.updated', 'provider.updated'],
  results: ['success', 'failure'],
  risks: ['low', 'medium', 'high', 'critical'],
  target_types: ['user', 'client', 'provider'],
};

type AdminUserRequestCounterKey =
  | 'adminUserOverviewRequests'
  | 'adminUserSecurityRequests'
  | 'adminUserSessionRequests'
  | 'adminUserIdentityRequests'
  | 'adminUserAuthorizationRequests'
  | 'adminUserClientRequests'
  | 'adminUserActivityRequests';

function incrementRequestCounter(state: MockState, key: AdminUserRequestCounterKey, id: string) {
  const counterState = state as Record<AdminUserRequestCounterKey, Record<string, number> | undefined>;
  const counters = (counterState[key] ||= {});
  counters[id] = (counters[id] || 0) + 1;
}

function adminUserOverviewFor(candidate: typeof user): AdminUserOverview {
  return {
    user: {
      ...candidate,
      email_verified_at: candidate.status === 'active' ? '2026-01-01T00:10:00Z' : null,
      last_login_ip: candidate.last_login_at ? '192.0.2.10' : null,
      updated_at: '2026-01-03T00:00:00Z',
    },
    creation_source: candidate.id === user.id ? 'bootstrap' : 'admin',
    created_by: candidate.id === user.id ? null : {
      id: user.id,
      username: user.username,
      display_name: user.display_name,
    },
    self_registration: null,
  };
}

function adminUserSecurityFor(candidate: typeof user): AdminUserSecurity {
  return {
    has_password: true,
    password_changed_at: '2026-01-01T00:30:00Z',
    must_change_password: false,
    totp_available: true,
    totp_enrolled: candidate.role === 'admin',
    recovery_codes_remaining: candidate.role === 'admin' ? 8 : 0,
    passkeys_available: true,
    passkeys_enrolled: candidate.role === 'admin' ? 1 : 0,
    passkey_clone_warnings: 0,
    last_passkey_used_at: candidate.role === 'admin' ? '2026-01-02T00:00:00Z' : null,
    mfa_required_for_admin: true,
    mfa_requirement_satisfied: true,
  };
}

function adminClientSummaryFor(client: typeof oauthClient): AdminUserClientSummary {
  return {
    id: client.id,
    name: client.name,
    is_public: client.is_public,
    access_policy: 'open',
    grants: client.grants,
    scopes: client.scopes,
    optional_scopes: client.optional_scopes,
    allowed_claims: client.allowed_claims,
    secret_hint: client.secret_hint,
    secret_last_used_at: null,
    created_at: client.created_at,
    updated_at: client.updated_at,
  };
}

function sessionResponse(state: MockState) {
  const authenticatedAt = state.authenticatedAt || '2026-01-02T00:00:00Z';
  return {
    user: { ...user, role: state.role },
    csrf_token: state.csrfToken,
    must_change_password: state.mustChangePassword,
    has_password: state.hasPassword ?? true,
    email_verified: true,
    authenticated_at: authenticatedAt,
    session_expires_at: new Date(Date.parse(authenticatedAt) + 24 * 60 * 60_000).toISOString(),
    recent_authentication_expires_at: new Date(Date.parse(authenticatedAt) + 10 * 60_000).toISOString(),
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

async function countPaintedPixels(canvas: Locator): Promise<number> {
  return canvas.evaluate((element: HTMLCanvasElement) => {
    const data = element.getContext('2d')!.getImageData(0, 0, element.width, element.height).data;
    let painted = 0;
    for (let index = 3; index < data.length; index += 4) if (data[index] > 0) painted += 1;
    return painted;
  });
}

async function installDashboardCoreMocks(page: Page) {
  await page.route('**/api/admin/stats', (route) => fulfillJSON(route, 200, dashboardStats));
  await page.route('**/api/admin/stats/login-trend**', (route) => fulfillJSON(route, 200, dashboardLoginTrend));
  await page.route('**/api/admin/stats/recent-logins**', (route) => fulfillJSON(route, 200, []));
  await page.route('**/.well-known/openid-configuration', (route) => fulfillJSON(route, 200, {
    issuer: 'https://auth.example',
    authorization_endpoint: 'https://auth.example/authorize',
    token_endpoint: 'https://auth.example/token',
    jwks_uri: 'https://auth.example/.well-known/jwks.json',
    userinfo_endpoint: 'https://auth.example/userinfo',
  }));
}

async function installAPIMocks(page: Page, state: MockState) {
  await page.route('**/media/avatars/**', (route) => route.fulfill({
    status: 200,
    contentType: 'image/webp',
    body: Buffer.from('UklGRiIAAABXRUJQVlA4IBYAAAAwAQCdASoBAAEAAUAmJaQAA3AA/v89WAAAAA==', 'base64'),
    headers: { 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'public, max-age=86400, immutable' },
  }));

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
      await fulfillJSON(route, 200, [{ name: 'github', display_name: 'GitHub', icon_key: 'auto', type: 'github' }]);
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

    if (path === '/api/me/mfa' && request.method() === 'GET') {
      state.mfaStatusRequests = (state.mfaStatusRequests || 0) + 1;
      await fulfillJSON(route, 200, {
        login_mfa_enabled: false,
        login_mfa_required: false,
        can_enable_login_mfa: false,
        totp_available: true,
        totp_enrolled: false,
        can_disable_totp: true,
        passkeys_available: true,
        passkeys_enrolled: 0,
        recovery_codes_remaining: 0,
        require_mfa_for_admins: false,
        required_for_current_user: false,
      });
      return;
    }

    if (path === '/api/me/passkeys' && request.method() === 'GET') {
      state.passkeyListRequests = (state.passkeyListRequests || 0) + 1;
      await fulfillJSON(route, 200, { passkeys: [] });
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
      state.sessionListRequests = (state.sessionListRequests || 0) + 1;
      await fulfillJSON(route, 200, browserSessions);
      return;
    }

    if (path === '/api/me/sessions/revoke-others' && request.method() === 'POST') {
      state.revokeOthersCSRF = await request.headerValue('x-csrf-token');
      await fulfillJSON(route, 200, { revoked: 1 });
      return;
    }

    if (path === '/api/me/trusted-devices' && request.method() === 'GET') {
      state.trustedDeviceListRequests = (state.trustedDeviceListRequests || 0) + 1;
      await fulfillJSON(route, 200, { enabled: true, items: trustedDevices });
      return;
    }

    if (path === '/api/me/login-history' && request.method() === 'GET') {
      state.loginHistoryRequests = (state.loginHistoryRequests || 0) + 1;
      await fulfillJSON(route, 200, { items: loginHistory, total: 2, page: 1, page_size: 20, total_pages: 1 });
      return;
    }

    if (path === `/api/me/trusted-devices/${trustedDevices[1].id}` && request.method() === 'DELETE') {
      state.trustedDeviceDeleteCSRF = await request.headerValue('x-csrf-token');
      await route.fulfill({ status: 204 });
      return;
    }

    if (path === '/api/me/authorizations' && request.method() === 'GET') {
      state.authorizationListRequests = (state.authorizationListRequests || 0) + 1;
      state.authorizationQueries ||= [];
      state.authorizationQueries.push(requestURL.search);
      const search = (requestURL.searchParams.get('q') || '').toLowerCase();
      const status = requestURL.searchParams.get('status') || '';
      const pageNumber = Math.max(1, Number(requestURL.searchParams.get('page')) || 1);
      const pageSize = Math.max(1, Number(requestURL.searchParams.get('page_size')) || 20);
      const filtered = (state.authorizations ?? [oauthAuthorization]).filter((authorization) => {
        const matchesSearch = !search || authorization.client_name.toLowerCase().includes(search)
          || authorization.client_id.toLowerCase().includes(search);
        const currentStatus = authorization.reauthorization_required
          ? 'reauthorization_required'
          : authorization.application_changed ? 'changed' : authorization.last_used_at ? 'valid' : 'unused';
        return matchesSearch && (!status || currentStatus === status);
      });
      const start = (pageNumber - 1) * pageSize;
      await fulfillJSON(route, 200, {
        items: filtered.slice(start, start + pageSize),
        total: filtered.length,
        page: pageNumber,
        page_size: pageSize,
        total_pages: Math.ceil(filtered.length / pageSize),
      });
      return;
    }

    if (path === `/api/me/authorizations/${oauthAuthorization.client_id}` && request.method() === 'DELETE') {
      state.authorizationRevokeCSRF = await request.headerValue('x-csrf-token');
      state.authorizations = [];
      await route.fulfill({ status: 204 });
      return;
    }

    if (path === '/api/me/identities/github/bind' && request.method() === 'POST') {
      state.bindCSRF = await request.headerValue('x-csrf-token');
      state.bindBody = request.postDataJSON();
      await fulfillJSON(route, 200, { redirect_url: 'https://provider.example/authorize' });
      return;
    }

    if (path === '/api/me/avatar' && request.method() === 'POST') {
      state.avatarUploadCSRF = await request.headerValue('x-csrf-token');
      state.avatarUploadContentType = await request.headerValue('content-type');
      state.avatarURL = '/media/avatars/77777777-7777-7777-7777-777777777777/256.webp';
      await fulfillJSON(route, 200, { ...user, role: state.role, avatar_url: state.avatarURL });
      return;
    }

    if (path === '/api/me/avatar' && request.method() === 'DELETE') {
      state.avatarDeleteCSRF = await request.headerValue('x-csrf-token');
      state.avatarURL = null;
      await fulfillJSON(route, 200, { ...user, role: state.role, avatar_url: null });
      return;
    }

    if (path === '/api/me') {
      state.meRequests = (state.meRequests || 0) + 1;
	  if (request.method() === 'PUT') state.selfUpdateBody = request.postDataJSON();
	  await fulfillJSON(route, 200, { ...user, role: state.role, avatar_url: state.avatarURL ?? user.avatar_url, ...(state.selfUpdateBody as object || {}) });
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

    if (path === `/api/my/clients/${oauthClient.id}` && request.method() === 'PUT') {
      state.myClientUpdateCSRF = await request.headerValue('x-csrf-token');
      state.myClientUpdateBody = request.postDataJSON();
      await fulfillJSON(route, 200, { ...oauthClient, ...(state.myClientUpdateBody as object), updated_at: '2026-01-03T00:00:00Z' });
      return;
    }

    if (path === `/api/my/clients/${oauthClient.id}/logo` && (request.method() === 'POST' || request.method() === 'DELETE')) {
      state.myClientLogoMethod = request.method();
      state.myClientLogoCSRF = await request.headerValue('x-csrf-token');
      state.myClientLogoContentType = await request.headerValue('content-type');
      await fulfillJSON(route, 200, {
        ...oauthClient,
        logo_url: request.method() === 'POST' ? '/media/client-logos/99999999-9999-4999-8999-999999999999/256.webp' : null,
        current_logo_id: request.method() === 'POST' ? '99999999-9999-4999-8999-999999999999' : null,
      });
      return;
    }

    if (path === '/api/my/clients') {
      await fulfillJSON(route, 200, {
        items: [oauthClient],
        total: 1,
        page: 1,
        page_size: 50,
        total_pages: 1,
        quota_used: 1,
        quota_limit: 10,
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
      });
      return;
    }

    if (path === '/api/admin/settings/oauth' && request.method() === 'GET' && state.adminClients) {
      await fulfillJSON(route, 200, oauthSettings);
      return;
    }

    if (path === '/api/admin/audit-logs/options' && request.method() === 'GET') {
      state.auditLogOptionsRequests = (state.auditLogOptionsRequests || 0) + 1;
      await fulfillJSON(route, 200, auditLogOptions);
      return;
    }

    if (path === '/api/admin/audit-logs' && request.method() === 'GET') {
      const pageNumber = Math.max(1, Number(requestURL.searchParams.get('page')) || 1);
      const pageSize = Math.max(1, Number(requestURL.searchParams.get('page_size')) || 20);
      const auditLogs = state.auditLogs || [adminUserActivity];
      const start = (pageNumber - 1) * pageSize;
      state.auditLogQueries ||= [];
      state.auditLogQueries.push(requestURL.search);
      await fulfillJSON(route, 200, {
        items: auditLogs.slice(start, start + pageSize),
        total: auditLogs.length,
        page: pageNumber,
        page_size: pageSize,
        total_pages: Math.ceil(auditLogs.length / pageSize),
      });
      return;
    }

    if (path === '/api/admin/audit-logs/export' && request.method() === 'GET') {
      state.auditExportQueries ||= [];
      state.auditExportQueries.push(requestURL.search);
      await route.fulfill({
        status: 200,
        contentType: 'application/x-ndjson',
        body: `${JSON.stringify(adminUserActivity)}\n`,
        headers: { 'Content-Disposition': 'attachment; filename="audit.ndjson"' },
      });
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
        optional_scopes: string[];
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
      await fulfillJSON(route, 200, {
        ...oauthClient,
        owner_id: body.owner_id,
        owner_username: body.owner_id === ownerUser.id ? ownerUser.username : null,
        updated_at: '2026-01-05T00:00:00Z',
      });
      return;
    }

    if (path === `/api/admin/clients/${oauthClient.id}/publisher-verification`
      && (request.method() === 'POST' || request.method() === 'DELETE') && state.adminClients) {
      state.adminClientPublisherReviewCSRFs ||= [];
      state.adminClientPublisherReviewCSRFs.push(await request.headerValue('x-csrf-token'));
      state.adminClientPublisherReviewMethods ||= [];
      state.adminClientPublisherReviewMethods.push(request.method());
      if ((state.adminClientPublisherReviewRecentAuthenticationFailures || 0) > 0) {
        state.adminClientPublisherReviewRecentAuthenticationFailures = (state.adminClientPublisherReviewRecentAuthenticationFailures || 0) - 1;
        await fulfillJSON(route, 403, {
          error: 'recent authentication is required',
          code: 'auth.recent_authentication_required',
        });
        return;
      }
      const status = request.method() === 'POST' ? 'verified' : 'unverified';
      const updated = {
        ...state.adminClients[0],
        publisher_verification_status: status,
        publisher_verified_at: status === 'verified' ? '2026-07-31T08:00:00Z' : null,
        updated_at: '2026-07-31T08:00:00Z',
      } as OAuthClient;
      state.adminClients = [updated];
      await fulfillJSON(route, 200, updated);
      return;
    }

    const adminUserMatch = path.match(/^\/api\/admin\/users\/([^/]+)(?:\/(.*))?$/);
    if (adminUserMatch && state.adminUsers) {
      const userID = decodeURIComponent(adminUserMatch[1]);
      const endpoint = adminUserMatch[2] || '';
      const userIndex = state.adminUsers.findIndex((candidate) => candidate.id === userID);
      if (userIndex < 0) {
        await fulfillJSON(route, 404, { error: 'user not found' });
        return;
      }
      const candidate = state.adminUsers[userIndex];

      if (endpoint === 'overview' && request.method() === 'GET') {
        incrementRequestCounter(state, 'adminUserOverviewRequests', userID);
        await fulfillJSON(route, 200, adminUserOverviewFor(candidate));
        return;
      }
      if (endpoint === 'security' && request.method() === 'GET') {
        incrementRequestCounter(state, 'adminUserSecurityRequests', userID);
        await fulfillJSON(route, 200, adminUserSecurityFor(candidate));
        return;
      }
      if (endpoint === 'authorizations' && request.method() === 'GET') {
        incrementRequestCounter(state, 'adminUserAuthorizationRequests', userID);
        await fulfillJSON(route, 200, [{
          id: oauthAuthorization.id,
          client_id: oauthAuthorization.client_id,
          client_name: oauthAuthorization.client_name,
          scopes: oauthAuthorization.scopes,
          allowed_claims: oauthAuthorization.allowed_claims,
          granted_at: oauthAuthorization.granted_at,
          last_used_at: oauthAuthorization.last_used_at,
        }]);
        return;
      }
      if (endpoint === 'clients' && request.method() === 'GET') {
        incrementRequestCounter(state, 'adminUserClientRequests', userID);
        const pageNumber = Math.max(1, Number(requestURL.searchParams.get('page')) || 1);
        const pageSize = Math.max(1, Number(requestURL.searchParams.get('page_size')) || 20);
        const ownedClients = (state.adminClients || [oauthClient])
          .filter((client) => client.owner_id === userID)
          .map(adminClientSummaryFor);
        const start = (pageNumber - 1) * pageSize;
        await fulfillJSON(route, 200, {
          items: ownedClients.slice(start, start + pageSize),
          total: ownedClients.length,
          page: pageNumber,
          page_size: pageSize,
          total_pages: Math.ceil(ownedClients.length / pageSize),
        });
        return;
      }
      if (endpoint === 'activity' && request.method() === 'GET') {
        incrementRequestCounter(state, 'adminUserActivityRequests', userID);
        const pageNumber = Math.max(1, Number(requestURL.searchParams.get('page')) || 1);
        const pageSize = Math.max(1, Number(requestURL.searchParams.get('page_size')) || 20);
        const activity = [{ ...adminUserActivity, actor_id: userID, actor_name: candidate.username, target_id: userID }];
        await fulfillJSON(route, 200, {
          items: activity,
          total: activity.length,
          page: pageNumber,
          page_size: pageSize,
          total_pages: 1,
        });
        return;
      }
      if (endpoint === 'identities' && request.method() === 'GET') {
        incrementRequestCounter(state, 'adminUserIdentityRequests', userID);
        await fulfillJSON(route, 200, (state.adminUserIdentities || []).map((identity) => ({ ...identity, user_id: userID })));
        return;
      }
      if (endpoint.startsWith('identities/') && request.method() === 'DELETE') {
        state.adminUserIdentityDeleteCSRF = await request.headerValue('x-csrf-token');
        const identityID = decodeURIComponent(endpoint.slice('identities/'.length));
        state.adminUserIdentities = (state.adminUserIdentities || []).filter((identity) => identity.id !== identityID);
        await route.fulfill({ status: 204 });
        return;
      }
      if (endpoint === 'sessions' && request.method() === 'GET') {
        incrementRequestCounter(state, 'adminUserSessionRequests', userID);
        await fulfillJSON(route, 200, browserSessions.map((session) => ({ ...session, current: false })));
        return;
      }
      if (endpoint === 'sessions' && request.method() === 'DELETE') {
        await fulfillJSON(route, 200, { revoked: browserSessions.length });
        return;
      }
      if (endpoint.startsWith('sessions/') && request.method() === 'DELETE') {
        state.adminUserSessionDeleteCSRF = await request.headerValue('x-csrf-token');
        state.adminUserSessionDeletedID = decodeURIComponent(endpoint.slice('sessions/'.length));
        await route.fulfill({ status: 204 });
        return;
      }
      if (endpoint === 'reset-password' && request.method() === 'POST') {
        await route.fulfill({ status: 204 });
        return;
      }
      if (endpoint === 'avatar' && (request.method() === 'POST' || request.method() === 'DELETE')) {
        const updated = {
          ...candidate,
          avatar_url: request.method() === 'POST'
            ? '/media/avatars/88888888-8888-8888-8888-888888888888/256.webp'
            : null,
        };
        state.adminUsers = state.adminUsers.map((item, index) => index === userIndex ? updated : item);
        await fulfillJSON(route, 200, updated);
        return;
      }
      if (endpoint === 'role' && request.method() === 'PUT') {
        if (state.adminUserRoleUpdateError) {
          await fulfillJSON(route, 409, { error: state.adminUserRoleUpdateError });
          return;
        }
        const body = request.postDataJSON() as { role: Role };
        const updated = { ...candidate, role: body.role };
        state.adminUsers = state.adminUsers.map((item, index) => index === userIndex ? updated : item);
        await fulfillJSON(route, 200, updated);
        return;
      }
      if (!endpoint && request.method() === 'PUT') {
        state.adminUserUpdateCSRF = await request.headerValue('x-csrf-token');
        state.adminUserUpdateBody = request.postDataJSON();
        state.adminUserUpdateRequests = (state.adminUserUpdateRequests || 0) + 1;
        const updateBody = state.adminUserUpdateBody as { username?: string };
        if (updateBody.username && (state.adminUserUpdateRecentAuthenticationFailures || 0) > 0) {
          state.adminUserUpdateRecentAuthenticationFailures = (state.adminUserUpdateRecentAuthenticationFailures || 0) - 1;
          await fulfillJSON(route, 403, {
            error: 'recent authentication is required',
            code: 'auth.recent_authentication_required',
          });
          return;
        }
        const updated = {
          ...candidate,
          ...(state.adminUserUpdateBody as object),
          updated_at: '2026-01-03T00:00:00Z',
        };
        state.adminUsers = state.adminUsers.map((item, index) => index === userIndex ? updated : item);
        await fulfillJSON(route, 200, updated);
        return;
      }
    }

    if (path === `/api/admin/clients/${oauthClient.id}` && request.method() === 'GET' && state.adminClients) {
      const current = state.adminClients.find((client) => client.id === oauthClient.id);
      await fulfillJSON(route, current ? 200 : 404, current || { error: 'client not found' });
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
        scopes: ['openid', 'email', 'profile'],
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

    if (path === '/api/admin/settings/security' && request.method() === 'GET') {
      await fulfillJSON(route, 200, { totp_enabled: true, passkeys_enabled: true, require_mfa_for_admins: false });
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
  await expect(page.getByRole('button', { name: /返回/ })).toHaveCount(0);
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
  await expect(page.getByRole('button', { name: '返回个人资料' })).toBeVisible();
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

  const providerButton = page.getByRole('button', { name: 'GitHub' });
  await expect(providerButton).toBeVisible();
  await expect(providerButton.locator('svg')).toHaveCount(1);
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

test('administrator profile deep links stay in the user center and mark profile navigation active', async ({ page }) => {
  await installAPIMocks(page, {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin-profile',
  });

  await page.goto('/profile/security');

  const sidebar = page.getByRole('complementary', { name: '用户中心导航' });
  await expect(sidebar).toBeVisible();
  await expect(page.getByRole('complementary', { name: '管理后台导航' })).toHaveCount(0);
  await expect(sidebar.getByRole('link', { name: '个人资料', exact: true })).toHaveAttribute('aria-current', 'page');
  await expect(sidebar.getByRole('link', { name: '管理后台', exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: '安全', exact: true })).toHaveAttribute('aria-current', 'page');
});

test('all profile deep links load only their own account data', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-profile-routes',
    identities: [githubIdentity],
  };
  await installAPIMocks(page, state);

  function resetRequestCounts() {
    state.meRequests = 0;
    state.mfaStatusRequests = 0;
    state.passkeyListRequests = 0;
    state.sessionListRequests = 0;
    state.trustedDeviceListRequests = 0;
    state.loginHistoryRequests = 0;
    state.authorizationListRequests = 0;
    state.identityLoadRequests = 0;
    state.providerListRequests = 0;
  }

  await page.goto('/profile');
  await expect(page.getByRole('heading', { name: '个人资料', exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: '基本资料', exact: true })).toHaveAttribute('aria-current', 'page');
  await expect.poll(() => state.meRequests || 0).toBeGreaterThan(0);
  expect(state.sessionListRequests || 0).toBe(0);
  expect(state.authorizationListRequests || 0).toBe(0);
  expect(state.identityLoadRequests || 0).toBe(0);

  resetRequestCounts();
  await page.goto('/profile/security');
  await expect(page.getByRole('heading', { name: '账户安全', exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: '安全', exact: true })).toHaveAttribute('aria-current', 'page');
  await expect.poll(() => state.mfaStatusRequests || 0).toBeGreaterThan(0);
  await expect.poll(() => state.passkeyListRequests || 0).toBeGreaterThan(0);
  await expect.poll(() => state.identityLoadRequests || 0).toBeGreaterThan(0);
  expect(state.meRequests || 0).toBe(0);
  expect(state.sessionListRequests || 0).toBe(0);
  expect(state.authorizationListRequests || 0).toBe(0);

  resetRequestCounts();
  await page.goto('/profile/sessions');
  await expect(page.getByRole('heading', { name: '设备会话', exact: true }).first()).toBeVisible();
  await expect(page.getByRole('link', { name: '设备会话', exact: true })).toHaveAttribute('aria-current', 'page');
  await expect.poll(() => state.sessionListRequests || 0).toBeGreaterThan(0);
  await expect.poll(() => state.trustedDeviceListRequests || 0).toBeGreaterThan(0);
  await expect.poll(() => state.loginHistoryRequests || 0).toBeGreaterThan(0);
  expect(state.meRequests || 0).toBe(0);
  expect(state.mfaStatusRequests || 0).toBe(0);
  expect(state.authorizationListRequests || 0).toBe(0);
  expect(state.identityLoadRequests || 0).toBe(0);

  resetRequestCounts();
  await page.goto('/profile/authorizations');
  await expect(page.getByRole('heading', { name: 'OAuth 应用授权', exact: true, level: 1 })).toBeVisible();
  await expect(page.getByRole('link', { name: '应用授权', exact: true })).toHaveAttribute('aria-current', 'page');
  await page.getByRole('button', { name: '查看详情' }).click();
  await expect(page.getByText('允许返回的 Claim', { exact: true })).toBeVisible();
  await expect(page.getByText('稳定用户 ID', { exact: false })).toBeVisible();
  await expect.poll(() => state.authorizationListRequests || 0).toBeGreaterThan(0);
  expect(state.meRequests || 0).toBe(0);
  expect(state.mfaStatusRequests || 0).toBe(0);
  expect(state.sessionListRequests || 0).toBe(0);
  expect(state.identityLoadRequests || 0).toBe(0);

  resetRequestCounts();
  await page.goto('/profile/identities');
  await expect(page.getByRole('heading', { name: '外部身份', exact: true }).first()).toBeVisible();
  await expect(page.getByRole('link', { name: '外部身份', exact: true })).toHaveAttribute('aria-current', 'page');
  await expect.poll(() => state.identityLoadRequests || 0).toBeGreaterThan(0);
  await expect.poll(() => state.providerListRequests || 0).toBeGreaterThan(0);
  expect(state.meRequests || 0).toBe(0);
  expect(state.mfaStatusRequests || 0).toBe(0);
  expect(state.sessionListRequests || 0).toBe(0);
  expect(state.authorizationListRequests || 0).toBe(0);
});

test('users crop, upload, and remove a managed avatar with CSRF', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-avatar',
    avatarURL: null,
  };
  await installAPIMocks(page, state);
  await page.goto('/profile');

  const avatarFixture = await readFile(new URL('../../static/logo.png', import.meta.url));

  await page.locator('input[type="file"][accept*="image/webp"]').setInputFiles({
    name: 'avatar.png',
    mimeType: 'image/png',
    buffer: avatarFixture,
  });
  const cropDialog = page.getByRole('dialog', { name: '裁剪头像' });
  await expect(cropDialog).toBeVisible();
  await cropDialog.getByRole('button', { name: '上传头像' }).click();

  await expect(cropDialog).toBeHidden();
  await expect(page.getByAltText('用户头像')).toBeVisible();
  expect(state.avatarUploadCSRF).toBe('csrf-avatar');
  expect(state.avatarUploadContentType).toMatch(/^multipart\/form-data; boundary=/);

  await page.getByRole('button', { name: '删除头像' }).click();
  await expect(page.getByAltText('用户头像')).toHaveCount(0);
  expect(state.avatarDeleteCSRF).toBe('csrf-avatar');
});

test('theme preference is browser-local, applies immediately, and survives reload', async ({ page }) => {
	const state: MockState = {
		authenticated: true,
		mustChangePassword: false,
		role: 'user',
		csrfToken: 'csrf-theme',
	};
	await installAPIMocks(page, state);
	await page.goto('/profile');
	await page.getByRole('button', { name: '深色主题' }).first().click();

	await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
	expect(await page.evaluate(() => localStorage.getItem('nyauth:theme'))).toBe('dark');
	await page.reload();
	await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
	await page.getByRole('button', { name: '保存更改' }).click();

	expect(state.selfUpdateBody).toEqual({ display_name: 'Alice' });
});

test('owned applications show the used quota as a compact fraction', async ({ page }) => {
  await installAPIMocks(page, {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-client-quota',
  });

  await page.goto('/dashboard/apps');

  await expect(page.getByText('1/10', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '创建应用' }).first()).toBeEnabled();
});

test('owners can edit application identity and upload a cropped logo', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-owned-client',
  };
  await installAPIMocks(page, state);
  await page.goto('/dashboard/apps');

  await page.getByRole('button', { name: '编辑', exact: true }).click();
  const editor = page.getByRole('dialog', { name: /编辑应用/ });
  await editor.getByRole('textbox', { name: '应用主页' }).fill('https://new-app.example');
  await editor.getByRole('textbox', { name: '隐私政策' }).fill('https://new-app.example/privacy');
  await editor.getByRole('textbox', { name: '服务条款' }).fill('https://new-app.example/terms');

  const logoFixture = await readFile(new URL('../../static/logo.png', import.meta.url));
  await editor.locator('input[type="file"][accept*="image/webp"]').setInputFiles({
    name: 'application-logo.png',
    mimeType: 'image/png',
    buffer: logoFixture,
  });
  const cropDialog = page.getByRole('dialog', { name: '裁剪应用 Logo' });
  await cropDialog.getByRole('button', { name: '上传应用 Logo' }).click();
  await expect(cropDialog).toBeHidden();
  await expect(editor.getByAltText('Example App Logo')).toBeVisible();

  await editor.getByRole('button', { name: '保存更改' }).click();
  await expect(editor).toBeHidden();
  expect(state.myClientUpdateCSRF).toBe('csrf-owned-client');
  expect(state.myClientUpdateBody).toMatchObject({
    homepage_uri: 'https://new-app.example',
    privacy_policy_uri: 'https://new-app.example/privacy',
    terms_of_service_uri: 'https://new-app.example/terms',
  });
  expect(state.myClientLogoMethod).toBe('POST');
  expect(state.myClientLogoCSRF).toBe('csrf-owned-client');
  expect(state.myClientLogoContentType).toMatch(/^multipart\/form-data; boundary=/);
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

  await page.goto('/profile/identities');
  const bindRequest = page.waitForRequest((request) => new URL(request.url()).pathname === '/api/me/identities/github/bind');
  await page.getByRole('button', { name: /github/i }).click();
  await bindRequest;

  expect(state.bindCSRF).toBe('csrf-user');
  expect(state.bindBody).toEqual({ return_to: '/profile/identities' });
});

test('revoking other device sessions sends CSRF and preserves the current session', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
  };
  await installAPIMocks(page, state);

  await page.goto('/profile/sessions');
  await page.getByRole('button', { name: '退出其他设备' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('button', { name: '退出其他设备' }).click();

  await expect(dialog).toBeHidden();
  await expect(page.getByText('当前设备')).toBeVisible();
  const sessionsSection = page.locator('section').filter({ has: page.getByRole('heading', { name: '设备会话', exact: true }) });
  await expect(sessionsSection.getByText('Firefox · Android')).toBeHidden();
  expect(state.revokeOthersCSRF).toBe('csrf-user');
});

test('trusted browsers and restricted login history are visible and revocable', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
  };
  await installAPIMocks(page, state);

  await page.goto('/profile/sessions');
  await expect(page.getByRole('heading', { name: '可信浏览器' })).toBeVisible();
  await expect(page.getByText('密码 + 可信浏览器')).toBeVisible();
  await expect(page.getByText('密码 + 动态验证码')).toBeVisible();
  const trustedSection = page.locator('section').filter({ has: page.getByRole('heading', { name: '可信浏览器' }) });
  await trustedSection.getByRole('button', { name: '撤销信任' }).last().click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText(/当前已登录会话不会退出/)).toBeVisible();
  await dialog.getByRole('button', { name: '撤销可信浏览器' }).click();

  await expect(dialog).toBeHidden();
  expect(state.trustedDeviceDeleteCSRF).toBe('csrf-user');
});

test('revoking an OAuth authorization sends CSRF and removes the grant', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
  };
  await installAPIMocks(page, state);

  await page.goto('/profile/authorizations');
  await expect(page.getByText('授权有效', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: '查看详情' }).click();
  await expect(page.getByRole('link', { name: '应用主页' })).toHaveAttribute('href', 'https://app.example');
  await expect(page.getByText('尚无使用记录')).toHaveCount(0);
  await page.getByRole('button', { name: '撤销此应用授权' }).click();
  const dialog = page.getByRole('dialog', { name: '撤销 OAuth 应用授权' });
  await dialog.getByRole('button', { name: '撤销授权' }).click();

  await expect(dialog).toBeHidden();
  await expect(page.getByText('没有符合条件的 OAuth 应用授权。')).toBeVisible();
  expect(state.authorizationRevokeCSRF).toBe('csrf-user');
});

test('OAuth authorizations remain searchable and paginated as the list grows', async ({ page }) => {
  const authorizations = Array.from({ length: 17 }, (_, index) => ({
    ...oauthAuthorization,
    id: `authorization-${index + 1}`,
    client_id: `application-${index + 1}`,
    client_name: `Application ${index + 1}`,
    application_changed: index === 3,
    reauthorization_required: index === 3,
  }));
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
    authorizations,
  };
  await installAPIMocks(page, state);

  await page.goto('/profile/authorizations');
  await expect(page.getByText('显示 1-15，共 17 条')).toBeVisible();
  await page.getByRole('button', { name: '下一页' }).click();
  await expect(page.getByText('Application 16', { exact: true })).toBeVisible();
  await expect(page).toHaveURL(/page=2/);

  await page.getByLabel('搜索应用').fill('Application 17');
  await page.getByRole('button', { name: '筛选' }).click();
  await expect(page.getByText('Application 17', { exact: true })).toBeVisible();
  await expect(page.getByText('Application 16', { exact: true })).toHaveCount(0);
  await expect(page).toHaveURL(/q=Application(?:\+|%20)17/);

  await page.getByRole('button', { name: '清除' }).click();
  await page.getByLabel('授权状态').click();
  await page.getByRole('option', { name: '需要重新授权' }).click();
  await page.getByRole('button', { name: '筛选' }).click();
  await expect(page.getByText('Application 4', { exact: true })).toBeVisible();
  await expect(page.getByText('Application 1', { exact: true })).toHaveCount(0);
  expect(state.authorizationQueries?.some((query) => query.includes('status=reauthorization_required'))).toBe(true);
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

  await page.goto('/profile/security');
  await page.getByRole('button', { name: '选择认证方式' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel(/^当前密码/).fill('current-password');
  await dialog.getByRole('button', { name: '使用密码验证' }).click();

  await expect(dialog).toBeHidden();
  await expect(page.getByText('认证有效', { exact: true })).toBeVisible();
  expect(state.reauthCSRF).toBe('csrf-user');
  expect(state.reauthBody).toEqual({ password: 'current-password' });
});

test('password reauthentication completes MFA inline and promotes the formal CSRF only after verification', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-formal-before-mfa',
  };
  await installAPIMocks(page, state);
  const challenge = {
    status: 'mfa_required',
    purpose: 'reauthentication',
    username: 'alice',
    methods: ['totp', 'recovery_code'],
    csrf_token: 'csrf-mfa-pending',
    expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
  };
  let primaryCSRF: string | null = null;
  let verificationCSRF: string | null = null;
  let verificationBody: unknown;
  let restoreRequests = 0;
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/me/reauth/password' && request.method() === 'POST') {
      primaryCSRF = await request.headerValue('x-csrf-token');
      await fulfillJSON(route, 202, challenge);
      return;
    }
    if (path === '/api/login/mfa' && request.method() === 'GET') {
      restoreRequests += 1;
      await fulfillJSON(route, 200, challenge);
      return;
    }
    if (path === '/api/login/mfa' && request.method() === 'POST') {
      verificationCSRF = await request.headerValue('x-csrf-token');
      verificationBody = request.postDataJSON();
      state.authenticatedAt = new Date().toISOString();
      state.csrfToken = 'csrf-formal-after-mfa';
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }
    await route.fallback();
  });

  await page.goto('/profile/security');
  await page.getByRole('button', { name: '选择认证方式' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel(/^当前密码/).fill('current-password');
  await dialog.getByRole('button', { name: '使用密码验证' }).click();
  await expect(dialog.getByText('密码已通过，请完成第二项验证')).toBeVisible();
  expect(restoreRequests).toBe(0);
  await dialog.getByLabel('6 位动态验证码').fill('123456');
  await dialog.getByRole('button', { name: '完成重新认证' }).click();

  await expect(dialog).toBeHidden();
  await expect(page.getByText('认证有效', { exact: true })).toBeVisible();
  await page.goto('/profile/sessions');
  await page.getByRole('button', { name: '退出其他设备' }).click();
  const revokeDialog = page.getByRole('dialog');
  await revokeDialog.getByRole('button', { name: '退出其他设备' }).click();

  expect(primaryCSRF).toBe('csrf-formal-before-mfa');
  expect(verificationCSRF).toBe('csrf-mfa-pending');
  expect(verificationBody).toEqual({ method: 'totp', code: '123456', trust_device: false });
  expect(state.revokeOthersCSRF).toBe('csrf-formal-after-mfa');
});

test('cancelling reauthentication MFA preserves the existing formal-session CSRF', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-formal-preserved',
  };
  await installAPIMocks(page, state);
  const challenge = {
    status: 'mfa_required',
    purpose: 'reauthentication',
    username: 'alice',
    methods: ['totp'],
    csrf_token: 'csrf-cancel-pending',
    expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
  };
  let cancellationCSRF: string | null = null;
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/me/reauth/password' && request.method() === 'POST') {
      await fulfillJSON(route, 202, challenge);
      return;
    }
    if (path === '/api/login/mfa' && request.method() === 'GET') {
      await fulfillJSON(route, 200, challenge);
      return;
    }
    if (path === '/api/login/mfa' && request.method() === 'DELETE') {
      cancellationCSRF = await request.headerValue('x-csrf-token');
      await route.fulfill({ status: 204 });
      return;
    }
    await route.fallback();
  });

  await page.goto('/profile/security');
  await page.getByRole('button', { name: '选择认证方式' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel(/^当前密码/).fill('current-password');
  await dialog.getByRole('button', { name: '使用密码验证' }).click();
  await expect(dialog.getByText('密码已通过，请完成第二项验证')).toBeVisible();
  await dialog.getByRole('button', { name: '取消', exact: true }).click();
  await expect(dialog).toBeHidden();

  await page.goto('/profile/sessions');
  await page.getByRole('button', { name: '退出其他设备' }).click();
  const revokeDialog = page.getByRole('dialog');
  await revokeDialog.getByRole('button', { name: '退出其他设备' }).click();

  expect(cancellationCSRF).toBe('csrf-cancel-pending');
  expect(state.revokeOthersCSRF).toBe('csrf-formal-preserved');
});

test('users can enroll TOTP, replace recovery codes, and disable the factor', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-before-totp',
    authenticatedAt: new Date().toISOString(),
  };
  await installAPIMocks(page, state);
  let enrolled = false;
  let loginMFAEnabled = false;
  let enrollCSRF: string | null = null;
  let confirmCSRF: string | null = null;
  let regenerateCSRF: string | null = null;
  let disableCSRF: string | null = null;
  const loginMFAUpdates: boolean[] = [];
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/me/mfa' && request.method() === 'GET') {
      await fulfillJSON(route, 200, {
        login_mfa_enabled: loginMFAEnabled,
        login_mfa_required: loginMFAEnabled,
        can_enable_login_mfa: enrolled,
        totp_available: true,
        totp_enrolled: enrolled,
        can_disable_totp: !loginMFAEnabled,
        passkeys_available: true,
        passkeys_enrolled: 0,
        recovery_codes_remaining: enrolled ? 10 : 0,
        require_mfa_for_admins: false,
        required_for_current_user: false,
      });
      return;
    }
    if (path === '/api/me/mfa/totp/enroll' && request.method() === 'POST') {
      enrollCSRF = await request.headerValue('x-csrf-token');
      await fulfillJSON(route, 200, {
        secret: 'JBSWY3DPEHPK3PXP',
        otpauth_uri: 'otpauth://totp/Nyauth%3Aalice?secret=JBSWY3DPEHPK3PXP&issuer=Nyauth&algorithm=SHA1&digits=6&period=30',
      });
      return;
    }
    if (path === '/api/me/mfa/totp/enroll/confirm' && request.method() === 'POST') {
      confirmCSRF = await request.headerValue('x-csrf-token');
      enrolled = true;
      state.csrfToken = 'csrf-after-totp-enroll';
      await fulfillJSON(route, 200, {
        ...sessionResponse(state),
        recovery_codes: ['AAAA2222-BBBB2222CCCC2222', 'DDDD2222-EEEE2222FFFF2222'],
      });
      return;
    }
    if (path === '/api/me/mfa/recovery-codes' && request.method() === 'POST') {
      regenerateCSRF = await request.headerValue('x-csrf-token');
      await fulfillJSON(route, 200, {
        recovery_codes: ['GGGG2222-HHHH2222IIII2222', 'JJJJ2222-KKKK2222LLLL2222'],
      });
      return;
    }
    if (path === '/api/me/mfa/login-requirement' && request.method() === 'PUT') {
      const body = request.postDataJSON() as { enabled: boolean };
      loginMFAEnabled = body.enabled;
      loginMFAUpdates.push(body.enabled);
      state.csrfToken = body.enabled ? 'csrf-after-login-mfa-enable' : 'csrf-after-login-mfa-disable';
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }
    if (path === '/api/me/mfa/totp' && request.method() === 'DELETE') {
      disableCSRF = await request.headerValue('x-csrf-token');
      enrolled = false;
      state.csrfToken = 'csrf-after-totp-disable';
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }
    await route.fallback();
  });

  await page.goto('/profile/security');
  await page.getByRole('button', { name: '启用动态验证码' }).click();
  const enrollmentDialog = page.getByRole('dialog', { name: '启用动态验证码' });
  await expect(enrollmentDialog.getByText('JBSWY3DPEHPK3PXP')).toBeVisible();
  await enrollmentDialog.getByLabel('6 位动态验证码').fill('123456');
  await enrollmentDialog.getByRole('button', { name: '确认并启用' }).click();

  const recoveryDialog = page.getByRole('dialog', { name: '保存恢复码' });
  await expect(recoveryDialog.getByText('AAAA2222-BBBB2222CCCC2222')).toBeVisible();
  await expect(recoveryDialog.getByRole('button', { name: '关闭对话框' })).toHaveCount(0);
  await page.keyboard.press('Escape');
  await expect(recoveryDialog).toBeVisible();
  await recoveryDialog.getByRole('button', { name: '我已安全保存' }).click();
  await expect(page.getByText('动态验证码已添加')).toBeVisible();

  await page.getByRole('button', { name: '重新生成恢复码' }).click();
  const regeneratedDialog = page.getByRole('dialog', { name: '新的恢复码' });
  await expect(regeneratedDialog.getByText('GGGG2222-HHHH2222IIII2222')).toBeVisible();
  await regeneratedDialog.getByRole('button', { name: '我已安全保存' }).click();

  await page.getByRole('switch', { name: '已关闭' }).click();
  await expect(page.getByRole('switch', { name: '已开启' })).toBeVisible();
  await page.getByRole('switch', { name: '已开启' }).click();
  await expect(page.getByRole('switch', { name: '已关闭' })).toBeVisible();

  await page.getByRole('button', { name: '停用', exact: true }).click();
  const disableDialog = page.getByRole('dialog', { name: '停用动态验证码' });
  await disableDialog.getByRole('button', { name: '确认停用' }).click();
  await expect(page.getByText('尚未启用动态验证码')).toBeVisible();

  expect(enrollCSRF).toBe('csrf-before-totp');
  expect(confirmCSRF).toBe('csrf-before-totp');
  expect(regenerateCSRF).toBe('csrf-after-totp-enroll');
  expect(disableCSRF).toBe('csrf-after-login-mfa-disable');
  expect(loginMFAUpdates).toEqual([true, false]);
});

test('provider reauthentication denial does not replay a pending TOTP action', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-provider-totp-denied',
    hasPassword: false,
    identities: [githubIdentity],
    providerReauthError: 'provider_denied',
  };
  await installAPIMocks(page, state);
  let enrollmentAttempts = 0;
  await page.route('**/api/me/mfa/totp/enroll', async (route) => {
    enrollmentAttempts += 1;
    await fulfillJSON(route, 403, {
      error: 'recent authentication is required',
      code: 'auth.recent_authentication_required',
    });
  });

  await page.goto('/profile/security');
  await page.getByRole('button', { name: '启用动态验证码' }).click();
  const reauthentication = page.getByRole('dialog', { name: '重新验证身份' });
  await expect(reauthentication).toBeVisible();
  await reauthentication.getByRole('button', { name: '使用 github 验证' }).click();

  await expect(page.getByText('你取消了外部身份提供商的授权。')).toBeVisible();
  expect(enrollmentAttempts).toBe(1);
  expect(state.providerReauthBody).toEqual({ return_to: '/profile/security' });
  expect(await page.evaluate(() => sessionStorage.getItem('nyauth:reauth:mfa-action'))).toBeNull();
});

test('provider reauthentication completes MFA before replaying a pending TOTP action once', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-provider-mfa-before',
    hasPassword: false,
    identities: [githubIdentity],
  };
  await installAPIMocks(page, state);
  const challenge = {
    status: 'mfa_required',
    purpose: 'reauthentication',
    username: 'alice',
    methods: ['totp'],
    csrf_token: 'csrf-provider-mfa-pending',
    expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
  };
  const enrollmentCSRFs: Array<string | null> = [];
  let providerCSRF: string | null = null;
  let providerBody: unknown;
  let verificationCSRF: string | null = null;
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/me/mfa/totp/enroll' && request.method() === 'POST') {
      enrollmentCSRFs.push(await request.headerValue('x-csrf-token'));
      if (enrollmentCSRFs.length === 1) {
        await fulfillJSON(route, 403, {
          error: 'recent authentication is required',
          code: 'auth.recent_authentication_required',
        });
      } else {
        await fulfillJSON(route, 200, {
          secret: 'JBSWY3DPEHPK3PXP',
          otpauth_uri: 'otpauth://totp/Nyauth%3Aalice?secret=JBSWY3DPEHPK3PXP&issuer=Nyauth&algorithm=SHA1&digits=6&period=30',
        });
      }
      return;
    }
    if (path === '/api/me/reauth/github' && request.method() === 'POST') {
      providerCSRF = await request.headerValue('x-csrf-token');
      providerBody = request.postDataJSON();
      await fulfillJSON(route, 200, {
        redirect_url: new URL('/login/mfa?purpose=reauthentication&return_to=%2Fprofile%2Fsecurity', request.url()).toString(),
      });
      return;
    }
    if (path === '/api/login/mfa' && request.method() === 'GET') {
      await fulfillJSON(route, 200, challenge);
      return;
    }
    if (path === '/api/login/mfa' && request.method() === 'POST') {
      verificationCSRF = await request.headerValue('x-csrf-token');
      state.authenticatedAt = new Date().toISOString();
      state.csrfToken = 'csrf-provider-mfa-after';
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }
    await route.fallback();
  });

  await page.goto('/profile/security');
  await page.getByRole('button', { name: '启用动态验证码' }).click();
  const reauthentication = page.getByRole('dialog', { name: '重新验证身份' });
  await reauthentication.getByRole('button', { name: '使用 github 验证' }).click();

  await expect(page).toHaveURL(/\/login\/mfa/);
  await page.getByLabel('6 位动态验证码').fill('123456');
  await page.getByRole('button', { name: '验证并返回' }).click();

  await expect(page).toHaveURL(/\/profile\/security$/);
  await expect(page.getByRole('dialog', { name: '启用动态验证码' })).toBeVisible();
  expect(providerCSRF).toBe('csrf-provider-mfa-before');
  expect(providerBody).toEqual({ return_to: '/profile/security' });
  expect(verificationCSRF).toBe('csrf-provider-mfa-pending');
  expect(enrollmentCSRFs).toEqual(['csrf-provider-mfa-before', 'csrf-provider-mfa-after']);
  expect(await page.evaluate(() => sessionStorage.getItem('nyauth:reauth:mfa-action'))).toBeNull();
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

  await page.goto('/profile/security');
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

  await page.goto('/profile/security');
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

  await page.goto('/profile/identities');
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

  await page.goto('/profile/identities');
  const identitySection = page.locator('section').filter({
    has: page.getByRole('heading', { name: '外部身份' }),
  });
  await expect(identitySection.getByText('外部身份服务暂时不可用')).toBeVisible();
  await expect(page.getByText('可绑定的提供商')).toBeVisible();

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
    fulfillJSON(route, 403, { error: 'email verification is required before signing in', code: 'account.email_verification_required' }));

  await page.goto('/login');
  await page.getByLabel('用户名').fill('pending-user');
  await page.getByLabel('密码').fill('a-valid-password-123');
  await page.getByRole('button', { name: '登录', exact: true }).click();

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
  await installDashboardCoreMocks(page);
  await page.route('**/api/admin/stats/registration-trend**', (route) => fulfillJSON(route, 200, registrationTrendFor(30)));
  await page.route('**/api/admin/stats/mail-trend**', (route) => fulfillJSON(route, 200, mailTrendFor(30)));

  await page.goto('/admin');

  // The canvas existing is not enough: a chart initialization failure leaves
  // a mounted but blank canvas. Assert that pixels were actually painted.
  const canvas = page.locator('canvas[aria-label="过去 7 天登录趋势"]');
  await expect(canvas).toBeVisible();
  await expect.poll(() => countPaintedPixels(canvas)).toBeGreaterThan(100);
  expect(pageErrors).toEqual([]);
});

test('the dashboard renders registration, invitation, and mail trends and switches time ranges', async ({ page }) => {
  const pageErrors: string[] = [];
  const registrationDays: number[] = [];
  const mailDays: number[] = [];
  page.on('pageerror', (error) => pageErrors.push(String(error)));

  await installAPIMocks(page, {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin-stats',
  });
  await installDashboardCoreMocks(page);
  await page.route('**/api/admin/stats/registration-trend**', async (route) => {
    const requestedDays = Number(new URL(route.request().url()).searchParams.get('days')) as StatsTrendDays;
    registrationDays.push(requestedDays);
    await fulfillJSON(route, 200, registrationTrendFor(requestedDays));
  });
  await page.route('**/api/admin/stats/mail-trend**', async (route) => {
    const requestedDays = Number(new URL(route.request().url()).searchParams.get('days')) as StatsTrendDays;
    mailDays.push(requestedDays);
    await fulfillJSON(route, 200, mailTrendFor(requestedDays));
  });

  await page.goto('/admin');

  await expect(page.getByText('待验证注册')).toBeVisible();
  await expect(page.getByText('82.5%')).toBeVisible();
  await expect(page.getByText('SMTP 熔断')).toBeVisible();
  const availableFrom = await page.evaluate((value) => new Intl.DateTimeFormat('zh-CN', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value)), mailTrendFor(30).available_from);
  await expect(page.getByText(`邮件统计自 ${availableFrom} 起可用，早于该时间的数据可能不完整。`)).toBeVisible();

  const registrationCanvas = page.locator('canvas[aria-label="注册趋势（30 天）"]');
  const invitationCanvas = page.locator('canvas[aria-label="邀请趋势（30 天）"]');
  const mailCanvas = page.locator('canvas[aria-label="邮件趋势（30 天）"]');
  const registrationTable = page.getByRole('table', { name: '注册趋势（30 天）数据明细' });
  await expect(registrationCanvas).toBeVisible();
  await expect(invitationCanvas).toBeVisible();
  await expect(mailCanvas).toBeVisible();
  await expect(registrationTable.getByRole('row')).toHaveCount(31);
  await expect.poll(() => countPaintedPixels(registrationCanvas)).toBeGreaterThan(100);
  // Invitation values are deliberately all zero. The chart must still render
  // its axes and zero baseline instead of reporting an empty dataset.
  await expect.poll(() => countPaintedPixels(invitationCanvas)).toBeGreaterThan(100);
  await expect.poll(() => countPaintedPixels(mailCanvas)).toBeGreaterThan(100);
  expect(registrationDays).toEqual([30]);
  expect(mailDays).toEqual([30]);

  await page.getByRole('button', { name: '7 天', exact: true }).click();
  await expect(page.locator('canvas[aria-label="注册趋势（7 天）"]')).toBeVisible();
  await expect(page.getByRole('table', { name: '注册趋势（7 天）数据明细' }).getByRole('row')).toHaveCount(8);
  await expect.poll(() => registrationDays).toEqual([30, 7]);
  await expect.poll(() => mailDays).toEqual([30, 7]);

  await page.getByRole('button', { name: '90 天', exact: true }).click();
  await expect(page.locator('canvas[aria-label="邮件趋势（90 天）"]')).toBeVisible();
  await expect(page.getByRole('table', { name: '邮件趋势（90 天）数据明细' }).getByRole('row')).toHaveCount(91);
  await expect.poll(() => registrationDays).toEqual([30, 7, 90]);
  await expect.poll(() => mailDays).toEqual([30, 7, 90]);
  expect(pageErrors).toEqual([]);
});

test('a failed registration trend does not hide mail or existing dashboard data and can recover', async ({ page }) => {
  const pageErrors: string[] = [];
  let registrationRequests = 0;
  page.on('pageerror', (error) => pageErrors.push(String(error)));

  await installAPIMocks(page, {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin-stats-recovery',
  });
  await installDashboardCoreMocks(page);
  await page.route('**/api/admin/stats/registration-trend**', async (route) => {
    registrationRequests += 1;
    if (registrationRequests === 1) {
      await fulfillJSON(route, 503, { error: 'registration trend temporarily unavailable' });
      return;
    }
    await fulfillJSON(route, 200, registrationTrendFor(30));
  });
  await page.route('**/api/admin/stats/mail-trend**', (route) => fulfillJSON(route, 200, mailTrendFor(30)));

  await page.goto('/admin');

  await expect(page.locator('canvas[aria-label="过去 7 天登录趋势"]')).toBeVisible();
  await expect(page.getByText('用户总数')).toBeVisible();
  await expect(page.locator('canvas[aria-label="邮件趋势（30 天）"]')).toBeVisible();
  await expect(page.getByRole('alert')).toContainText('注册与邀请趋势加载失败');

  await page.getByRole('button', { name: '重试注册与邀请趋势' }).click();
  const recoveredRegistration = page.locator('canvas[aria-label="注册趋势（30 天）"]');
  const recoveredInvitation = page.locator('canvas[aria-label="邀请趋势（30 天）"]');
  await expect(recoveredRegistration).toBeVisible();
  await expect(recoveredInvitation).toBeVisible();
  await expect.poll(() => countPaintedPixels(recoveredRegistration)).toBeGreaterThan(100);
  expect(registrationRequests).toBe(2);
  expect(pageErrors).toEqual([]);
});

test('administrators can edit OAuth clients without mutating immutable ownership fields', async ({ page }) => {
  const clientWithLegacyClaim = { ...oauthClient, allowed_claims: [...oauthClient.allowed_claims, 'role'] };
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin',
    adminClients: [clientWithLegacyClaim],
  };
  await installAPIMocks(page, state);

  await page.goto('/admin/clients');
  await page.getByRole('button', { name: '编辑', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText('现有 · 当前 Scope 不返回')).toBeVisible();
  await dialog.getByLabel('应用名称').fill('Renamed App');
  await dialog.locator('#edit-client-redirects').fill([
    'https://new.example/callback',
    'https://backup.example/callback',
  ].join('\n'));
  await dialog.locator('#edit-client-logouts').fill('https://new.example/signed-out');
  await expect(dialog.getByLabel('Scopes（空格、逗号或换行分隔）')).toHaveCount(0);
  await dialog.locator('#edit-client-scope-email').check();
  await dialog.locator('#edit-client-scope-offline_access').uncheck();
  await dialog.getByLabel('profile 允许用户拒绝').check();
  await dialog.getByLabel('Metadata（JSON 字符串键值）').fill(JSON.stringify({
    environment: 'production',
    team: 'identity',
  }));
  await dialog.getByRole('button', { name: '保存更改' }).click();

  await expect(dialog).toBeHidden();
  expect(state.adminClientUpdateCSRF).toBe('csrf-admin');
  expect(state.adminClientUpdateBody).toEqual({
    name: 'Renamed App',
    homepage_uri: 'https://app.example',
    privacy_policy_uri: 'https://app.example/privacy',
    terms_of_service_uri: 'https://app.example/terms',
    redirect_uris: ['https://new.example/callback', 'https://backup.example/callback'],
    post_logout_redirect_uris: ['https://new.example/signed-out'],
    grants: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email'],
    optional_scopes: ['profile'],
    allowed_claims: ['sub', 'preferred_username', 'name', 'picture', 'email', 'email_verified', 'role'],
    metadata: { environment: 'production', team: 'identity' },
    access_policy: 'open',
  });
  expect(state.adminClientUpdateBody).not.toHaveProperty('is_public');
  expect(state.adminClientUpdateBody).not.toHaveProperty('owner_id');
});

test('administrators can review and revoke a user-registered OAuth publisher after recent authentication', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-publisher-review',
    hasPassword: true,
    adminClients: [{ ...oauthClient }],
    adminClientPublisherReviewRecentAuthenticationFailures: 1,
  };
  await installAPIMocks(page, state);

  await page.goto('/admin/clients');
  await expect(page.getByText('发布者未验证', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: '审核发布者' }).click();
  const confirmation = page.getByRole('dialog', { name: '审核应用发布者' });
  await expect(confirmation.getByText(/不会验证域名所有权/)).toBeVisible();
  await confirmation.getByRole('button', { name: '标记为已验证' }).click();

  const reauthentication = page.getByRole('dialog', { name: '重新验证身份' });
  await reauthentication.getByLabel('当前密码').fill('correct-password');
  await reauthentication.getByRole('button', { name: '使用密码验证' }).click();
  await expect(page.getByText('发布者已验证', { exact: true })).toBeVisible();
  expect(state.adminClientPublisherReviewMethods).toEqual(['POST', 'POST']);
  expect(state.adminClientPublisherReviewCSRFs).toEqual(['csrf-publisher-review', 'csrf-reauthenticated']);

  await page.getByRole('button', { name: '撤销审核' }).click();
  const revocation = page.getByRole('dialog', { name: '撤销发布者审核' });
  await revocation.getByRole('button', { name: '撤销审核' }).click();
  await expect(page.getByText('发布者未验证', { exact: true })).toBeVisible();
  expect(state.adminClientPublisherReviewMethods).toEqual(['POST', 'POST', 'DELETE']);
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
  expect(state.adminClientQueries).toContain('?page=2&page_size=20&sort=activity_desc');

  await page.getByRole('button', { name: '上一页' }).click();
  await expect(page).toHaveURL(/\/admin\/clients$/);
  await expect(page.getByRole('heading', { name: 'Client 1', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Client 21' })).toHaveCount(0);
  expect(state.adminClientQueries).toContain('?page=1&page_size=20&sort=activity_desc');
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
    homepage_uri: '',
    privacy_policy_uri: '',
    terms_of_service_uri: '',
    redirect_uris: ['https://owner.example/callback'],
    post_logout_redirect_uris: [],
    grants: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    optional_scopes: [],
    allowed_claims: ['sub', 'preferred_username', 'name', 'picture', 'email', 'email_verified'],
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
  await expect(page.getByText(`@${ownerUser.username}`, { exact: true })).toBeVisible();
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
  await expect(page.getByText('未分配', { exact: true })).toBeVisible();
  expect(state.adminClientOwnerUpdateBodies).toEqual([{ owner_id: ownerUser.id }, { owner_id: null }]);
  expect(state.adminClientOwnerUpdateCSRFs).toEqual(['csrf-admin', 'csrf-admin']);
});

test('user role update errors remain visible on the user detail route', async ({ page }) => {
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

  await page.goto(`/admin/users/${user.id}?return_to=%2Fadmin%2Fusers`);
  await page.getByLabel('角色').click();
  await page.getByRole('option', { name: '管理员' }).click();
  await page.getByRole('button', { name: '保存', exact: true }).click();

  await expect(page.getByRole('alert')).toContainText('不能降级最后一个有效管理员');
  await expect(page).toHaveURL(new RegExp(`/admin/users/${user.id}`));
});

test('administrators can update user profiles and remove a confirmed identity from the access route', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin',
    adminUsers: [user],
    adminUserIdentities: [githubIdentity],
  };
  await installAPIMocks(page, state);

  await page.goto(`/admin/users/${user.id}?return_to=%2Fadmin%2Fusers`);
  await page.getByLabel('邮箱', { exact: true }).fill('alice.updated@example.com');
  await page.getByLabel('显示名称', { exact: true }).fill('Alice Updated');
  await page.getByLabel('高级扩展属性（JSON 字符串键值）').fill(JSON.stringify({
    department: 'security',
    region: 'apac',
  }));
  await page.getByRole('button', { name: '保存资料' }).click();

  await expect(page.getByText('用户资料已更新。')).toBeVisible();
  expect(state.adminUserUpdateCSRF).toBe('csrf-admin');
  expect(state.adminUserUpdateBody).toEqual({
    email: 'alice.updated@example.com',
    display_name: 'Alice Updated',
    metadata: { department: 'security', region: 'apac' },
  });

  await page.getByRole('link', { name: '访问', exact: true }).click();
  await page.getByRole('button', { name: '解绑 github 身份' }).click();
  const confirmation = page.getByRole('dialog', { name: '解绑外部身份' });
  const confirmButton = confirmation.getByRole('button', { name: '确认解绑' });
  await expect(confirmButton).toBeDisabled();
  await confirmation.getByLabel('输入“github”以确认').fill('GitHub');
  await expect(confirmButton).toBeDisabled();
  await confirmation.getByLabel('输入“github”以确认').fill('github');
  await expect(confirmButton).toBeEnabled();
  await confirmButton.click();

  await expect(confirmation).toBeHidden();
  await expect(page.getByText('已解绑 github 身份。')).toBeVisible();
  await expect(page.getByText('未绑定外部身份')).toBeVisible();
  expect(state.adminUserIdentityDeleteCSRF).toBe('csrf-admin');
});

test('administrators can rename an account after recent authentication and self-renames refresh the shell', async ({ page }) => {
  const selfAdmin = { ...user, role: 'admin' as const, display_name: null };
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin-rename',
    adminUsers: [selfAdmin],
    adminUserIdentities: [],
    adminUserUpdateRecentAuthenticationFailures: 1,
  };
  await installAPIMocks(page, state);

  await page.goto(`/admin/users/${selfAdmin.id}?return_to=%2Fadmin%2Fusers`);
  await page.getByLabel('登录名').fill('owner-admin');
  await page.getByRole('button', { name: '保存资料' }).click();

  const reauthentication = page.getByRole('dialog', { name: '重新验证身份' });
  await expect(reauthentication).toBeVisible();
  await reauthentication.getByLabel('当前密码').fill('correct-password');
  await reauthentication.getByRole('button', { name: '使用密码验证' }).click();

  await expect(reauthentication).toBeHidden();
  await expect(page.getByText('用户资料已更新。')).toBeVisible();
  await expect(page.getByText('@owner-admin')).toBeVisible();
  await expect(page.locator('header').getByLabel('打开个人资料')).toContainText('owner-admin');
  expect(state.adminUserUpdateRequests).toBe(2);
  expect(state.adminUserUpdateBody).toEqual({
    username: 'owner-admin',
    email: selfAdmin.email,
    display_name: '',
    metadata: selfAdmin.metadata,
  });
  expect(state.adminUserUpdateCSRF).toBe('csrf-reauthenticated');
  expect(state.reauthBody).toEqual({ password: 'correct-password' });
});

test('admin user details preserve the filtered list return path across every deep-link tab', async ({ page }) => {
  const adminUsers: User[] = Array.from({ length: 21 }, (_, index) => ({
    ...user,
    id: `70000000-0000-0000-0000-${String(index + 1).padStart(12, '0')}`,
    username: `member-${index + 1}`,
    email: `member-${index + 1}@example.com`,
    display_name: `Member ${index + 1}`,
    role: 'user',
    status: 'active',
  }));
  const target = adminUsers[20];
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-admin-detail-routes',
    adminUsers,
    adminUserIdentities: [githubIdentity],
    adminClients: [{ ...oauthClient, owner_id: target.id }],
  };
  await installAPIMocks(page, state);

  await page.goto('/admin/users?q=member&page=2');
  await page.getByRole('link', { name: `查看用户 ${target.username}` }).click();

  async function expectReturnToPreserved(pathname: string) {
    await expect.poll(() => {
      const current = new URL(page.url());
      return `${current.pathname}|${current.searchParams.get('return_to')}`;
    }).toBe(`${pathname}|/admin/users?q=member&page=2`);
  }

  await expectReturnToPreserved(`/admin/users/${target.id}`);
  await expect(page.getByRole('heading', { name: target.display_name || target.username })).toBeVisible();
  await expect(page.getByRole('link', { name: '资料', exact: true })).toHaveAttribute('aria-current', 'page');
  await expect(page.getByRole('link', { name: '资料', exact: true })).toHaveClass(/border-nya-primary/);
  await expect(page.getByRole('link', { name: '资料', exact: true })).not.toHaveClass(/border-transparent/);

  await page.getByRole('link', { name: '安全', exact: true }).click();
  await expectReturnToPreserved(`/admin/users/${target.id}/security`);
  await expect(page.getByRole('heading', { name: '安全摘要' })).toBeVisible();

  await page.getByRole('link', { name: '会话', exact: true }).click();
  await expectReturnToPreserved(`/admin/users/${target.id}/sessions`);
  await expect(page.getByRole('heading', { name: '设备会话' })).toBeVisible();
  await page.getByRole('button', { name: '撤销会话' }).first().click();
  await page.getByRole('dialog').getByRole('button', { name: '撤销会话' }).click();
  await expect(page.getByText('已撤销该设备会话。')).toBeVisible();
  expect(state.adminUserSessionDeleteCSRF).toBe('csrf-admin-detail-routes');
  expect(state.adminUserSessionDeletedID).toBe(browserSessions[0].id);

  await page.getByRole('link', { name: '访问', exact: true }).click();
  await expectReturnToPreserved(`/admin/users/${target.id}/access`);
  await expect(page.getByRole('heading', { name: 'OAuth 授权' })).toBeVisible();
  await expect(page.getByText('Claim：sub preferred_username name picture')).toBeVisible();

  await page.getByRole('link', { name: '活动', exact: true }).click();
  await expectReturnToPreserved(`/admin/users/${target.id}/activity`);
  await expect(page.getByRole('heading', { name: '审计活动' })).toBeVisible();

  expect(state.adminUserOverviewRequests?.[target.id]).toBeGreaterThan(0);
  expect(state.adminUserSecurityRequests?.[target.id]).toBe(1);
  expect(state.adminUserSessionRequests?.[target.id]).toBe(1);
  expect(state.adminUserIdentityRequests?.[target.id]).toBe(1);
  expect(state.adminUserAuthorizationRequests?.[target.id]).toBe(1);
  expect(state.adminUserClientRequests?.[target.id]).toBe(1);
  expect(state.adminUserActivityRequests?.[target.id]).toBe(1);
  expect(state.adminUserOverviewRequests?.[user.id]).toBeUndefined();

  await page.getByRole('link', { name: '返回用户列表' }).click();
  await expect(page).toHaveURL(/\/admin\/users\?q=member&page=2$/);
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
  await dialog.getByLabel('显示名称').fill('Company Identity');
  await dialog.getByLabel('图标').click();
  await page.getByRole('option', { name: '链接' }).click();
  await dialog.getByLabel('Client ID').fill('provider-client-updated');
  await expect(dialog.getByLabel('Client Secret')).toHaveValue('');
  await dialog.getByLabel('Scopes').fill('openid profile email');
  await dialog.getByRole('button', { name: '保存', exact: true }).click();

  await expect(dialog).toBeHidden();
  expect(state.adminProviderUpdateCSRF).toBe('csrf-admin');
  expect(state.adminProviderUpdateBody).toEqual({
    display_name: 'Company Identity',
    icon_key: 'link',
    client_id: 'provider-client-updated',
    scopes: ['openid', 'profile', 'email'],
    discovery_url: 'https://idp.example/.well-known/openid-configuration',
    authorization_url: 'https://idp.example/authorize',
    token_url: 'https://idp.example/token',
    userinfo_url: 'https://idp.example/userinfo',
    import_avatar: false,
    avatar_allowed_hosts: [],
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

  await expect(page.getByRole('heading', { name: externalProvider.display_name })).toBeVisible();
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
  await dialog.getByLabel('技术标识').fill('disabled-github');
  await dialog.getByLabel('显示名称').fill('Disabled GitHub');
  await dialog.getByLabel('Client ID').fill('disabled-client');
  await dialog.getByLabel('Client Secret').fill('disabled-secret');
  await dialog.getByLabel('Scopes').fill('read:user user:email');
  await dialog.getByRole('checkbox', { name: /创建后立即启用/ }).uncheck();
  await dialog.getByRole('button', { name: '添加', exact: true }).click();

  await expect(dialog).toBeHidden();
  expect(state.adminProviderCreateCSRF).toBe('csrf-admin');
  expect(state.adminProviderCreateBody).toEqual({
    name: 'disabled-github',
    display_name: 'Disabled GitHub',
    icon_key: 'auto',
    type: 'github',
    client_id: 'disabled-client',
    client_secret: 'disabled-secret',
    enabled: false,
    scopes: ['read:user', 'user:email'],
    import_avatar: false,
    avatar_allowed_hosts: [],
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
	const initialBranding = {
		title: 'Acme ID', primary_color: '#704DE8', primary_text_color: 'auto',
		light_logo_url: '', dark_logo_url: '', favicon_url: '',
	};
	await page.route('**/api/branding', (route) => fulfillJSON(route, 200, initialBranding));
  await page.route('**/api/admin/settings/branding', async (route) => {
    if (route.request().method() === 'GET') {
	  await fulfillJSON(route, 200, { revision: 1, ...initialBranding });
      return;
    }
    updateCSRF = route.request().headers()['x-csrf-token'] ?? null;
    updateBody = route.request().postDataJSON();
	await fulfillJSON(route, 200, {
		revision: 2, title: 'Acme SSO', primary_color: '#2367D1', primary_text_color: 'white',
		light_logo_url: 'https://cdn.example.com/light.png', dark_logo_url: 'https://cdn.example.com/dark.png',
		favicon_url: 'https://cdn.example.com/favicon.ico',
	});
  });

  await page.goto('/admin/settings/branding');
  const sidebar = page.getByRole('complementary', { name: '管理后台导航' });
  await expect(sidebar.getByText('Acme ID')).toBeVisible();
  await expect(sidebar.getByRole('link', { name: '系统设置' })).toHaveAttribute('aria-current', 'page');
  await expect(sidebar.getByRole('link', { name: '系统状态' })).not.toHaveAttribute('aria-current', 'page');
  await expect(page.getByRole('link', { name: '品牌', exact: true })).toHaveAttribute('aria-current', 'page');
  await expect(page.getByRole('link', { name: '品牌', exact: true })).toHaveClass(/border-nya-primary/);
  await expect(page.getByRole('link', { name: '品牌', exact: true })).not.toHaveClass(/border-transparent/);

	await page.getByRole('textbox', { name: '站点名称', exact: true }).fill('Acme SSO');
	await page.getByRole('textbox', { name: '主色', exact: true }).fill('#2367D1');
	await page.getByLabel('主色文字').click();
	await page.getByRole('option', { name: '始终使用白色文字' }).click();
	await page.getByRole('textbox', { name: '浅色主题 Logo', exact: true }).fill('https://cdn.example.com/light.png');
	await page.getByRole('textbox', { name: '深色主题 Logo', exact: true }).fill('https://cdn.example.com/dark.png');
	await page.getByRole('textbox', { name: 'Favicon', exact: true }).fill('https://cdn.example.com/favicon.ico');
  await page.getByRole('button', { name: '保存品牌设置' }).click();

	await expect(page.getByText('品牌与主题设置已保存，立即对所有实例生效。')).toBeVisible();
	expect(updateBody).toEqual({
		expected_revision: 1, title: 'Acme SSO', primary_color: '#2367D1', primary_text_color: 'white',
		light_logo_url: 'https://cdn.example.com/light.png', dark_logo_url: 'https://cdn.example.com/dark.png',
		favicon_url: 'https://cdn.example.com/favicon.ico',
	});
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
      await fulfillJSON(route, 403, {
        error: 'recent authentication is required',
        code: 'auth.recent_authentication_required',
      });
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

  await page.goto('/admin/settings/registration');
  await expect(page.getByRole('heading', { name: '注册设置', level: 1 })).toBeVisible();
  await expect(page.getByRole('link', { name: '注册', exact: true })).toHaveAttribute('aria-current', 'page');

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
      await fulfillJSON(route, 403, {
        error: 'recent authentication is required',
        code: 'auth.recent_authentication_required',
      });
      return;
    }
    await fulfillJSON(route, 200, putBody);
  });

  await page.goto('/admin/settings/registration');
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
  expect(state.providerReauthBody).toEqual({ return_to: '/admin/settings/registration' });
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
    await fulfillJSON(route, 403, {
      error: 'recent authentication is required',
      code: 'auth.recent_authentication_required',
    });
  });

  await page.goto('/admin/settings/registration');
  await page.getByRole('radio', { name: /开放/ }).check();
  await page.getByLabel('允许的邮箱域名（每行一个，留空不限制）').fill('lab.example.org');
  await page.getByLabel('待验证注册有效期').fill('24h');
  await page.getByRole('button', { name: '保存注册设置' }).click();
  await page.getByRole('button', { name: '使用 github 验证' }).click();

  await expect(page.getByRole('alert')).toHaveText('你取消了外部身份提供商的授权。');
  await expect(page.getByRole('radio', { name: /开放/ })).toBeChecked();
  await expect(page.getByLabel('允许的邮箱域名（每行一个，留空不限制）')).toHaveValue('lab.example.org');
  await expect(page.getByLabel('待验证注册有效期')).toHaveValue('24h');
  await expect(page).toHaveURL(/\/admin\/settings\/registration$/);
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
        await fulfillJSON(route, 403, {
          error: 'recent authentication is required',
          code: 'auth.recent_authentication_required',
        });
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

  await page.goto('/admin/settings/mail');
  await expect(page.getByRole('heading', { name: 'SMTP 动态配置' })).toBeVisible();
  await expect(page.getByRole('link', { name: '邮件', exact: true })).toHaveAttribute('aria-current', 'page');
  await page.getByLabel('SMTP 主机').fill('smtp.dynamic.example.com');
  await page.getByLabel('端口').fill('2525');
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
  await expect(page.getByText('smtp.dynamic.example.com:2525')).toBeVisible();

  await page.getByRole('button', { name: '回滚到上一版本' }).click();
  await expect(page.getByText('邮件配置已回滚到上一版本。')).toBeVisible();
  await page.getByRole('button', { name: '禁用邮件服务' }).click();
  await page.getByLabel('输入“禁用邮件”以确认').fill('禁用邮件');
  await page.getByRole('button', { name: '确认禁用' }).click();
  await expect(page.getByText(/邮件服务已禁用/)).toBeVisible();
  await expect(page.getByText('已禁用', { exact: true }).first()).toBeVisible();

  expect(saveAttempts).toBe(2);
  expect(saveBodies).toEqual([
    expect.objectContaining({ host: 'smtp.dynamic.example.com', port: 2525, password: 'smtp-runtime-secret', expected_revision: 10 }),
    expect.objectContaining({ host: 'smtp.dynamic.example.com', port: 2525, password: 'smtp-runtime-secret', expected_revision: 10 }),
  ]);
  expect(saveCSRFs).toEqual(['csrf-mail', 'csrf-reauthenticated']);
  expect(testBody).toEqual({ expected_revision: 11, version_id: candidateID, email: 'operator@example.com' });
  expect(activateBody).toEqual({ expected_revision: 12, version_id: candidateID });
  expect(rollbackBody).toEqual({ expected_revision: 13 });
  expect(disableBody).toEqual({ expected_revision: 14 });
});

test('SMTP rate limiting disables only the affected operation and shows a retry countdown', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-mail-rate-limit',
    systemStatus,
  };
  await installAPIMocks(page, state);
  await page.route('**/api/admin/settings/registration', (route) => fulfillJSON(route, 200, {
    mode: 'closed', require_email_verification: true, allowed_email_domains: [],
    pending_registration_ttl: '72h', invite_default_ttl: '168h', invite_default_max_uses: 1,
  }));

  const candidateID = '10000000-0000-0000-0000-000000000099';
  const candidate: MailConfig = {
    ...mailSettings.active!,
    source: 'database',
    id: candidateID,
    revision: 9,
    created_at: '2026-07-27T01:00:00Z',
  };
  const runtimeSettings: MailSettings = {
    ...mailSettings,
    mode: 'active',
    state_revision: 30,
    candidate,
  };
  let testAttempts = 0;

  await page.route('**/api/admin/settings/mail**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/admin/settings/mail' && request.method() === 'GET') {
      await fulfillJSON(route, 200, runtimeSettings);
      return;
    }
    if (path === '/api/admin/settings/mail/candidate/test' && request.method() === 'POST') {
      testAttempts += 1;
      if (testAttempts === 1) {
        await fulfillJSON(
          route,
          429,
          { error: 'too many mail settings operations' },
          { 'Retry-After': '2' },
        );
        return;
      }
      await fulfillJSON(route, 200, {
        result: 'success', tested_at: '2026-07-27T01:01:00Z', state_revision: 31,
      });
      return;
    }
    await fulfillJSON(route, 404, { error: `unmocked mail endpoint: ${path}` });
  });

  await page.goto('/admin/settings/mail');
  await page.getByLabel('测试邮件收件地址').fill('operator@example.com');
  const testButton = page.getByRole('button', { name: /发送真实测试/ });
  await testButton.click();

  await expect(page.getByRole('alert')).toContainText('请在 2 秒后重试');
  await expect(testButton).toBeDisabled();
  await expect(testButton).toContainText(/发送真实测试（[12] 秒）/);
  await expect(page.getByRole('button', { name: '保存候选配置' })).toBeEnabled();

  await expect(testButton).toBeEnabled({ timeout: 5_000 });
  await testButton.click();
  await expect(page.getByText(/测试邮件已成功发送/)).toBeVisible();
  expect(testAttempts).toBe(2);
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
        await fulfillJSON(route, 403, {
          error: 'recent authentication is required',
          code: 'auth.recent_authentication_required',
        });
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

  await page.goto('/admin/settings/mail');
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
  expect(state.providerReauthBody).toEqual({ return_to: '/admin/settings/mail' });
  expect(state.providerReauthCSRF).toBe('csrf-mail-provider');
});

test('audit filters use backend options, exact URL parameters, quick ranges and removable chips', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-audit',
    auditLogs: [adminUserActivity],
  };
  await installAPIMocks(page, state);

  await page.goto('/admin/audit?from=2026-07-01T00%3A00%3A00.000Z&to=2026-07-31T23%3A59%3A00.000Z');
  await expect(page.getByRole('heading', { name: '审计日志' })).toBeVisible();
  await expect.poll(() => state.auditLogOptionsRequests || 0).toBe(1);
  await page.getByRole('combobox', { name: '事件', exact: true }).fill('user.');
  await expect(page.locator('#audit-event-tree')).toBeVisible();
  await page.getByRole('checkbox', { name: 'user.login', exact: true }).check();
  await page.getByRole('checkbox', { name: 'user.profile_updated', exact: true }).check();
  await expect(page.getByText('user.login', { exact: true }).first()).toBeVisible();

  await page.getByRole('button', { name: '时间范围', exact: true }).click();
  const rangeDialog = page.getByRole('dialog', { name: '选择时间范围' });
  await expect(rangeDialog).toBeVisible();
  await expect(rangeDialog.getByRole('heading', { name: '2026 年 7 月' })).toBeVisible();
  await rangeDialog.getByRole('button', { name: '下一年' }).click();
  await expect(rangeDialog.getByRole('heading', { name: '2027 年 7 月' })).toBeVisible();
  await rangeDialog.getByRole('button', { name: '上一年' }).click();
  await rangeDialog.getByRole('button', { name: '下个月' }).click();
  await expect(rangeDialog.getByRole('heading', { name: '2026 年 8 月' })).toBeVisible();
  await rangeDialog.getByRole('button', { name: '上个月' }).click();
  await rangeDialog.getByRole('gridcell', { name: '2026年7月5日' }).click();
  await rangeDialog.getByRole('gridcell', { name: '2026年7月20日' }).click();
  const startHour = rangeDialog.getByLabel('起始时间小时');
  const startMinute = rangeDialog.getByLabel('起始时间分钟');
  const originalStartHour = await startHour.inputValue();
  await startHour.fill('ab');
  await expect(startHour).toHaveValue(originalStartHour);
  await expect(startHour).not.toHaveAttribute('aria-invalid', 'true');
  await startHour.fill('99');
  await expect(startHour).toHaveAttribute('aria-invalid', 'true');
  await startHour.fill('08');
  await expect(startMinute).toBeFocused();
  await startMinute.fill('15');
  await rangeDialog.getByRole('button', { name: '选择结束时间' }).click();
  const endTimeDialog = page.getByRole('dialog', { name: '选择结束时间' });
  await endTimeDialog.getByRole('option', { name: '小时 21' }).click();
  await endTimeDialog.getByRole('option', { name: '分钟 45' }).click();
  await endTimeDialog.getByRole('button', { name: '完成' }).click();
  await expect(rangeDialog.locator('input[type="time"]')).toHaveCount(0);
  await rangeDialog.getByRole('button', { name: '确认并应用' }).click();

  const preciseRangeURL = new URL(page.url());
  expect(preciseRangeURL.searchParams.get('from')).toBe(new Date('2026-07-05T08:15').toISOString());
  expect(preciseRangeURL.searchParams.get('to')).toBe(new Date('2026-07-20T21:45').toISOString());

  await page.getByRole('button', { name: '时间范围', exact: true }).click();
  await rangeDialog.getByRole('button', { name: '最近 1 天' }).click();
  await rangeDialog.getByRole('checkbox', { name: '结束时间使用确认时刻' }).check();
  await expect(rangeDialog.getByLabel('结束时间小时')).toBeDisabled();
  await expect(rangeDialog.getByLabel('结束时间分钟')).toBeDisabled();
  const confirmationStartedAt = Date.now();
  await rangeDialog.getByRole('button', { name: '确认并应用' }).click();
  const confirmationFinishedAt = Date.now();
  await expect(page).toHaveURL(/from=.*&to=/);
  const quickRangeURL = new URL(page.url());
  const quickFrom = new Date(quickRangeURL.searchParams.get('from') || '').getTime();
  const quickTo = new Date(quickRangeURL.searchParams.get('to') || '').getTime();
  expect(quickFrom).not.toBeNaN();
  expect(quickTo).not.toBeNaN();
  expect(quickTo - quickFrom).toBeGreaterThanOrEqual(24 * 60 * 60 * 1000);
  expect(quickTo - quickFrom).toBeLessThanOrEqual((24 * 60 + 2) * 60 * 1000);
  expect(quickTo).toBeGreaterThanOrEqual(confirmationStartedAt - 60 * 1000);
  expect(quickTo).toBeLessThanOrEqual(confirmationFinishedAt);
  expect(quickRangeURL.searchParams.get('from')).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00\.000Z$/);

  await page.getByLabel('结果').click();
  await page.getByRole('option', { name: '失败', exact: true }).click();
  await page.getByLabel('风险').click();
  await page.getByRole('option', { name: '高', exact: true }).click();
  await page.getByLabel('操作者（模糊）').fill('alice');
  await page.getByLabel('目标（模糊）').fill('oauth');
  await page.getByLabel('主体用户 ID（精确）').fill(user.id);
  await page.getByLabel('目标类型（精确）').click();
  await page.getByRole('option', { name: '客户端', exact: true }).click();
  await page.getByLabel('目标 ID（精确）').fill('client-123');
  await page.getByLabel('IP 地址').fill('192.0.2.10');
  for (const field of ['事件', '操作者（模糊）', '目标（模糊）', '主体用户 ID（精确）', '目标 ID（精确）', 'IP 地址']) {
    await expect(page.getByLabel(field, { exact: true })).toHaveAttribute('autocomplete', 'off');
    await expect(page.getByLabel(field, { exact: true })).toHaveAttribute('data-bwignore', 'true');
  }
  await page.getByRole('button', { name: '应用筛选' }).click();

  await expect(page).toHaveURL(/subject_user_id=/);
  const filteredURL = new URL(page.url());
  expect(Object.fromEntries([
    'result', 'risk', 'actor', 'target', 'subject_user_id', 'target_type', 'target_id', 'ip',
  ].map((key) => [key, filteredURL.searchParams.get(key)]))).toEqual({
    result: 'failure',
    risk: 'high',
    actor: 'alice',
    target: 'oauth',
    subject_user_id: user.id,
    target_type: 'client',
    target_id: 'client-123',
    ip: '192.0.2.10',
  });
  expect(filteredURL.searchParams.getAll('event')).toEqual(['user.login', 'user.profile_updated']);
  const latestListQuery = new URLSearchParams((state.auditLogQueries?.at(-1) || '').replace(/^\?/, ''));
  expect(latestListQuery.get('subject_user_id')).toBe(user.id);
  expect(latestListQuery.get('target_type')).toBe('client');
  expect(latestListQuery.get('target_id')).toBe('client-123');
  expect(latestListQuery.getAll('event')).toEqual(['user.login', 'user.profile_updated']);
  await expect(page.getByRole('button', { name: `移除筛选：主体用户 ID：${user.id}` })).toBeVisible();
  await expect(page.getByRole('button', { name: '移除筛选：目标 ID：client-123' })).toBeVisible();

  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'NDJSON' }).click();
  const download = await downloadPromise;
  await expect.poll(() => state.auditExportQueries?.length || 0).toBe(1);
  const exportQuery = new URLSearchParams((state.auditExportQueries?.[0] || '').replace(/^\?/, ''));
  expect(exportQuery.get('subject_user_id')).toBe(user.id);
  expect(exportQuery.get('target_type')).toBe('client');
  expect(exportQuery.get('target_id')).toBe('client-123');
  expect(exportQuery.getAll('event')).toEqual(['user.login', 'user.profile_updated']);
  expect(exportQuery.get('from')).toBe(filteredURL.searchParams.get('from'));
  expect(exportQuery.get('to')).toBe(filteredURL.searchParams.get('to'));
  await download.cancel();

  await page.getByRole('button', { name: '清除时间范围筛选' }).click();
  const withoutTimeRangeURL = new URL(page.url());
  expect(withoutTimeRangeURL.searchParams.has('from')).toBe(false);
  expect(withoutTimeRangeURL.searchParams.has('to')).toBe(false);
  await expect(page.getByRole('button', { name: '清除时间范围筛选' })).toHaveCount(0);

  await page.getByRole('button', { name: '移除筛选：目标 ID：client-123' }).click();
  await expect(page).not.toHaveURL(/target_id=/);
  await page.getByRole('button', { name: '清除全部筛选' }).click();
  await expect(page).toHaveURL(/\/admin\/audit$/);
  await expect(page.getByLabel('已启用筛选')).toHaveCount(0);
});

test('audit details show protected request context and real management links', async ({ page }) => {
  const clientTarget = 'client-123';
  const providerTarget = 'github';
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'admin',
    csrfToken: 'csrf-audit-details',
    auditLogs: [
      {
        ...adminUserActivity,
        details: {
          fields: ['display_name'],
          password: 'must-not-render',
          nested: { access_token: 'also-must-not-render', note: 'kept' },
        },
      },
      {
        ...adminUserActivity,
        id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
        event: 'client.updated',
        target_type: 'client',
        target_id: clientTarget,
      },
      {
        ...adminUserActivity,
        id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
        event: 'provider.updated',
        target_type: 'provider',
        target_id: providerTarget,
      },
    ],
  };
  await installAPIMocks(page, state);

  await page.goto('/admin/audit');
  await page.getByRole('button', { name: '查看审计详情：user.profile_updated' }).click();
  const drawer = page.getByRole('dialog', { name: '审计记录详情' });
  await expect(drawer).toBeVisible();
  await expect(drawer.getByText(adminUserActivity.user_agent!)).toBeVisible();
  const details = drawer.getByTestId('audit-details-json');
  await expect(details).toContainText('"password": "[已脱敏]"');
  await expect(details).toContainText('"access_token": "[已脱敏]"');
  await expect(drawer.getByText('must-not-render')).toHaveCount(0);
  await expect(drawer.getByText('also-must-not-render')).toHaveCount(0);
  await expect(details).toContainText('"note": "kept"');
  await expect(drawer.getByRole('link', { name: '打开目标管理入口' })).toHaveAttribute('href', `/admin/users/${user.id}`);

  await drawer.getByRole('button', { name: '关闭侧边栏' }).click();
  await page.getByRole('button', { name: '查看审计详情：client.updated' }).click();
  await expect(page.getByRole('dialog', { name: '审计记录详情' }).getByRole('link', { name: '打开目标管理入口' })).toHaveAttribute('href', '/admin/clients');

  await page.getByRole('dialog', { name: '审计记录详情' }).getByRole('button', { name: '关闭侧边栏' }).click();
  await page.getByRole('button', { name: '查看审计详情：provider.updated' }).click();
  await expect(page.getByRole('dialog', { name: '审计记录详情' }).getByRole('link', { name: '打开目标管理入口' })).toHaveAttribute('href', '/admin/providers');
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
  await expect(page.getByRole('link', { name: '系统设置' })).not.toHaveAttribute('aria-current', 'page');
  await expect(page.getByText('0.3.0-test')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'PostgreSQL' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Redis' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'JWK' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Provider 快照' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'SMTP 邮件' })).toBeVisible();
  await expect(page.getByText('signing-key-2026-07')).toBeVisible();
  await expect(page.getByText('12', { exact: true })).toBeVisible();
});
