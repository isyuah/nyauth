import { expect, test, type CDPSession, type Page, type Route } from '@playwright/test';
import type { ExternalIdentity, MFAMethod, PasskeyCredential, SecuritySettings } from '../../src/lib/api';

type Role = 'admin' | 'user';

interface PasskeyMockState {
  authenticated: boolean;
  role: Role;
  csrfToken: string;
  authenticatedAt: string;
  identities: ExternalIdentity[];
  passkeys: PasskeyCredential[];
  credentialRawID: string;
  conditionalRequests: number;
  directLoginRequests: number;
  loginCredentialRawID: string;
  passwordFailuresRemaining: number;
  passwordStartsMFA: boolean;
  mfaPending: boolean;
  mfaMethods: MFAMethod[];
  mfaOptionsCSRF: string | null;
  mfaVerifyCSRF: string | null;
  mfaCredentialRawID: string;
  deleteRequiresReauthentication: boolean;
  reauthenticated: boolean;
  deleteAttempts: number;
  reauthCredentialRawID: string;
  security: SecuritySettings;
  securitySaveAttempts: number;
  securitySaveBodies: SecuritySettings[];
  securitySaveCSRF: Array<string | null>;
}

interface VirtualAuthenticator {
  client: CDPSession;
  id: string;
}

const user = {
  id: '11111111-1111-1111-1111-111111111111',
  username: 'alice',
  email: 'alice@example.com',
  display_name: 'Alice',
  avatar_url: null,
  metadata: {},
  status: 'active',
  role: 'user' as Role,
  created_at: '2026-07-27T00:00:00Z',
  last_login_at: '2026-07-27T01:00:00Z',
};

const passkeyID = '22222222-2222-2222-2222-222222222222';
const webAuthnOrigin = 'http://localhost:4173';
let challengeSequence = 0;

function futureTimestamp(): string {
  return new Date(Date.now() + 5 * 60_000).toISOString();
}

function challenge(): string {
  challengeSequence += 1;
  return Buffer.alloc(32, challengeSequence % 255 || 1).toString('base64url');
}

function newState(overrides: Partial<PasskeyMockState> = {}): PasskeyMockState {
  return {
    authenticated: true,
    role: 'user',
    csrfToken: 'csrf-session',
    authenticatedAt: new Date().toISOString(),
    identities: [],
    passkeys: [],
    credentialRawID: '',
    conditionalRequests: 0,
    directLoginRequests: 0,
    loginCredentialRawID: '',
    passwordFailuresRemaining: 0,
    passwordStartsMFA: false,
    mfaPending: false,
    mfaMethods: ['passkey'],
    mfaOptionsCSRF: null,
    mfaVerifyCSRF: null,
    mfaCredentialRawID: '',
    deleteRequiresReauthentication: false,
    reauthenticated: false,
    deleteAttempts: 0,
    reauthCredentialRawID: '',
    security: { totp_enabled: true, passkeys_enabled: true, require_mfa_for_admins: false },
    securitySaveAttempts: 0,
    securitySaveBodies: [],
    securitySaveCSRF: [],
    ...overrides,
  };
}

function sessionResponse(state: PasskeyMockState) {
  return {
    user: { ...user, role: state.role },
    csrf_token: state.csrfToken,
    must_change_password: false,
    has_password: true,
    email_verified: true,
    authenticated_at: state.authenticatedAt,
  };
}

function mfaStatus(state: PasskeyMockState) {
  return {
    totp_available: true,
    totp_enrolled: false,
    can_disable_totp: true,
    passkeys_available: true,
    passkeys_enrolled: state.passkeys.length,
    recovery_codes_remaining: 0,
    require_mfa_for_admins: false,
    required_for_current_user: false,
  };
}

function creationOptions() {
  return {
    challenge: challenge(),
    rp: { id: 'localhost', name: 'Nyauth E2E' },
    user: {
      id: Buffer.from('nyauth-e2e-user-handle-00000001').toString('base64url'),
      name: user.username,
      displayName: user.display_name,
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 },
    ],
    timeout: 300_000,
    excludeCredentials: [],
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'required',
    },
    attestation: 'none',
    extensions: { credProps: true },
  };
}

function requestOptions(credentialRawID = '') {
  return {
    challenge: challenge(),
    timeout: 300_000,
    rpId: 'localhost',
    userVerification: 'required',
    ...(credentialRawID
      ? { allowCredentials: [{ type: 'public-key', id: credentialRawID, transports: ['internal'] }] }
      : {}),
  };
}

function optionsEnvelope(publicKey: unknown, ceremonyID: string, mediation?: 'conditional' | 'required') {
  return {
    ceremony_id: ceremonyID,
    public_key: publicKey,
    ...(mediation ? { mediation } : {}),
    expires_at: futureTimestamp(),
  };
}

function mfaChallenge(state: PasskeyMockState) {
  return {
    status: 'mfa_required',
    purpose: 'login',
    username: user.username,
    methods: state.mfaMethods,
    csrf_token: 'csrf-mfa-pending',
    expires_at: futureTimestamp(),
  };
}

async function fulfillJSON(route: Route, status: number, body: unknown) {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

async function addVirtualAuthenticator(page: Page): Promise<VirtualAuthenticator> {
  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');
  const result = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      defaultBackupEligibility: false,
      defaultBackupState: false,
    },
  }) as { authenticatorId: string };
  return { client, id: result.authenticatorId };
}

async function removeVirtualAuthenticator(authenticator: VirtualAuthenticator) {
  await authenticator.client.send('WebAuthn.removeVirtualAuthenticator', {
    authenticatorId: authenticator.id,
  }).catch(() => {});
  await authenticator.client.detach().catch(() => {});
}

async function setAutomaticPresenceSimulation(authenticator: VirtualAuthenticator, enabled: boolean) {
  await authenticator.client.send('WebAuthn.setAutomaticPresenceSimulation', {
    authenticatorId: authenticator.id,
    enabled,
  });
}

async function setConditionalMediation(page: Page, available: boolean) {
  await page.addInitScript((isAvailable) => {
    if (typeof PublicKeyCredential === 'undefined') return;
    Object.defineProperty(PublicKeyCredential, 'isConditionalMediationAvailable', {
      configurable: true,
      value: async () => isAvailable,
    });
  }, available);
}

async function installPasskeyMocks(page: Page, state: PasskeyMockState) {
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();

    if (path === '/api/branding' && method === 'GET') {
      await fulfillJSON(route, 200, { title: 'Nyauth', logo_url: '' });
      return;
    }
    if (path === '/api/session' && method === 'GET') {
      if (!state.authenticated) {
        await fulfillJSON(route, 401, { error: 'authentication required' });
      } else {
        await fulfillJSON(route, 200, sessionResponse(state));
      }
      return;
    }
    if (path === '/api/me' && method === 'GET') {
      await fulfillJSON(route, 200, { ...user, role: state.role });
      return;
    }
    if (path === '/api/providers' && method === 'GET') {
      await fulfillJSON(route, 200, []);
      return;
    }
    if (path === '/api/registration' && method === 'GET') {
      await fulfillJSON(route, 200, {
        mode: 'closed',
        require_email_verification: true,
        allowed_email_domains: [],
        available: true,
      });
      return;
    }
    if (path === '/api/me/identities' && method === 'GET') {
      await fulfillJSON(route, 200, state.identities);
      return;
    }
    if (path === '/api/me/sessions' && method === 'GET') {
      await fulfillJSON(route, 200, []);
      return;
    }
    if (path === '/api/me/authorizations' && method === 'GET') {
      await fulfillJSON(route, 200, []);
      return;
    }
    if (path === '/api/me/mfa' && method === 'GET') {
      await fulfillJSON(route, 200, mfaStatus(state));
      return;
    }
    if (path === '/api/me/passkeys' && method === 'GET') {
      await fulfillJSON(route, 200, { passkeys: state.passkeys });
      return;
    }
    if (path === '/api/me/passkeys/registration/options' && method === 'POST') {
      await fulfillJSON(route, 200, optionsEnvelope(creationOptions(), 'ceremony-registration'));
      return;
    }
    if (path === '/api/me/passkeys/registration/verify' && method === 'POST') {
      const body = request.postDataJSON() as { rawId: string; response: { transports?: string[] } };
      state.credentialRawID = body.rawId;
      const passkey: PasskeyCredential = {
        id: passkeyID,
        name: 'Work laptop',
        transports: body.response.transports || ['internal'],
        aaguid: '00000000-0000-0000-0000-000000000000',
        attachment: 'platform',
        backup_eligible: false,
        backup_state: false,
        clone_warning: false,
        created_at: new Date().toISOString(),
        last_used_at: null,
      };
      state.passkeys = [passkey];
      state.csrfToken = 'csrf-passkey-registered';
      await fulfillJSON(route, 200, { ...sessionResponse(state), passkey });
      return;
    }
    if (path === `/api/me/passkeys/${passkeyID}` && method === 'DELETE') {
      state.deleteAttempts += 1;
      if (state.deleteRequiresReauthentication && !state.reauthenticated) {
        await fulfillJSON(route, 403, { error: 'recent authentication is required' });
        return;
      }
      state.passkeys = [];
      state.csrfToken = 'csrf-passkey-removed';
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }
    if (path === '/api/me/reauth/passkey/options' && method === 'POST') {
      await fulfillJSON(route, 200, optionsEnvelope(
        requestOptions(state.credentialRawID),
        'ceremony-reauthentication',
        'required',
      ));
      return;
    }
    if (path === '/api/me/reauth/passkey/verify' && method === 'POST') {
      const body = request.postDataJSON() as { rawId: string };
      state.reauthCredentialRawID = body.rawId;
      state.reauthenticated = true;
      state.authenticatedAt = new Date().toISOString();
      state.csrfToken = 'csrf-passkey-reauthenticated';
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }
    if (path === '/api/login/passkey/options' && method === 'POST') {
      const body = request.postDataJSON() as { conditional: boolean };
      if (body.conditional) state.conditionalRequests += 1;
      else state.directLoginRequests += 1;
      await fulfillJSON(route, 200, optionsEnvelope(
        requestOptions(),
        body.conditional ? 'ceremony-conditional' : 'ceremony-login',
        body.conditional ? 'conditional' : 'required',
      ));
      return;
    }
    if (path === '/api/login/passkey/verify' && method === 'POST') {
      const body = request.postDataJSON() as { rawId: string };
      state.loginCredentialRawID = body.rawId;
      state.authenticated = true;
      state.authenticatedAt = new Date().toISOString();
      state.csrfToken = 'csrf-passkey-login';
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }
    if (path === '/api/login' && method === 'POST') {
      if (state.passwordFailuresRemaining > 0) {
        state.passwordFailuresRemaining -= 1;
        await fulfillJSON(route, 401, { error: 'invalid credentials' });
      } else if (state.passwordStartsMFA) {
        state.mfaPending = true;
        await fulfillJSON(route, 202, mfaChallenge(state));
      } else {
        state.authenticated = true;
        await fulfillJSON(route, 200, sessionResponse(state));
      }
      return;
    }
    if (path === '/api/login/mfa' && method === 'GET') {
      if (!state.mfaPending) {
        await fulfillJSON(route, 401, { error: 'MFA challenge expired' });
      } else {
        await fulfillJSON(route, 200, mfaChallenge(state));
      }
      return;
    }
    if (path === '/api/login/mfa/passkey/options' && method === 'POST') {
      state.mfaOptionsCSRF = await request.headerValue('x-csrf-token');
      await fulfillJSON(route, 200, optionsEnvelope(
        requestOptions(state.credentialRawID),
        'ceremony-mfa',
        'required',
      ));
      return;
    }
    if (path === '/api/login/mfa/passkey/verify' && method === 'POST') {
      state.mfaVerifyCSRF = await request.headerValue('x-csrf-token');
      const body = request.postDataJSON() as { rawId: string };
      state.mfaCredentialRawID = body.rawId;
      state.mfaPending = false;
      state.authenticated = true;
      state.authenticatedAt = new Date().toISOString();
      state.csrfToken = 'csrf-passkey-mfa';
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }
    if (path === '/api/admin/system/status' && method === 'GET') {
      await fulfillJSON(route, 200, {
        status: 'ok',
        version: '0.3.0-test',
        schema: { status: 'ok', version: 8, required_version: 8 },
        services: {
          postgresql: { status: 'ok', latency_ms: 1 },
          redis: { status: 'ok', latency_ms: 1 },
          providers: { status: 'ok', latency_ms: 1, snapshot_revision: 1 },
          jwk: { status: 'ok', latency_ms: 1 },
          mail: { status: 'ok', mode: 'disabled', configured: false, available: false, circuit_state: 'closed' },
          media: { status: 'ok', backend: 'local', configured: true },
        },
        active_signing_key: null,
      });
      return;
    }
    if (path === '/api/admin/settings/registration' && method === 'GET') {
      await fulfillJSON(route, 200, {
        mode: 'closed',
        require_email_verification: true,
        allowed_email_domains: [],
        pending_registration_ttl: '72h',
        invite_default_ttl: '168h',
        invite_default_max_uses: 1,
      });
      return;
    }
    if (path === '/api/admin/settings/mail' && method === 'GET') {
      await fulfillJSON(route, 200, {
        mode: 'disabled',
        configured: false,
        available: false,
        state_revision: 0,
        circuit: { state: 'closed', transport_failure_count: 0 },
      });
      return;
    }
    if (path === '/api/admin/settings/security' && method === 'GET') {
      await fulfillJSON(route, 200, state.security);
      return;
    }
    if (path === '/api/admin/settings/security' && method === 'PUT') {
      const body = request.postDataJSON() as SecuritySettings;
      state.securitySaveAttempts += 1;
      state.securitySaveBodies.push(body);
      state.securitySaveCSRF.push(await request.headerValue('x-csrf-token'));
      if (state.securitySaveAttempts === 1) {
        await fulfillJSON(route, 403, { error: 'recent authentication is required' });
        return;
      }
      state.security = body;
      await fulfillJSON(route, 200, state.security);
      return;
    }
    if (path === '/api/me/reauth/password' && method === 'POST') {
      state.reauthenticated = true;
      state.authenticatedAt = new Date().toISOString();
      state.csrfToken = 'csrf-password-reauthenticated';
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }

    await fulfillJSON(route, 404, { error: `unmocked endpoint: ${path}` });
  });
}

async function registerPasskey(page: Page, state: PasskeyMockState) {
  await page.goto(`${webAuthnOrigin}/profile/security`);
  await expect(page.getByRole('heading', { name: 'Passkey', exact: true })).toBeVisible();
  await page.getByRole('button', { name: '注册 Passkey' }).click();
  const dialog = page.getByRole('dialog', { name: '注册 Passkey' });
  await dialog.getByLabel('Passkey 名称').fill('Work laptop');
  await dialog.getByRole('button', { name: '继续注册' }).click();
  await expect(page.getByText('Passkey“Work laptop”已注册，当前会话已安全轮换。')).toBeVisible();
  await expect(page.getByRole('button', { name: '重命名 Work laptop' })).toBeVisible();
  await expect(page.getByRole('button', { name: '删除 Work laptop' })).toBeVisible();
  expect(state.credentialRawID).not.toBe('');
  expect(state.passkeys).toHaveLength(1);
}

test('login initializes Conditional UI with a WebAuthn autocomplete field', async ({ page }) => {
  const state = newState({ authenticated: false });
  await setConditionalMediation(page, true);
  await installPasskeyMocks(page, state);
  const authenticator = await addVirtualAuthenticator(page);
  try {
    await page.goto(`${webAuthnOrigin}/login`);
    await expect(page.getByLabel('用户名')).toHaveAttribute('autocomplete', 'username webauthn');
    await expect.poll(() => state.conditionalRequests).toBe(1);
  } finally {
    await removeVirtualAuthenticator(authenticator);
  }
});

test('failed password login restores Conditional UI without reloading the page', async ({ page }) => {
  const state = newState({ authenticated: false, passwordFailuresRemaining: 1 });
  await setConditionalMediation(page, true);
  await installPasskeyMocks(page, state);
  const authenticator = await addVirtualAuthenticator(page);
  try {
    await page.goto(`${webAuthnOrigin}/login`);
    await expect.poll(() => state.conditionalRequests).toBe(1);

    await page.getByLabel('用户名').fill(user.username);
    await page.getByLabel('密码').fill('incorrect-password');
    await page.getByRole('button', { name: '登录', exact: true }).click();

    await expect(page.getByRole('alert')).toContainText('认证凭据不正确');
    await expect.poll(() => state.conditionalRequests).toBe(2);
  } finally {
    await removeVirtualAuthenticator(authenticator);
  }
});

test('MFA method switching stays locked while a code verification is pending', async ({ page }) => {
  const state = newState({
    authenticated: false,
    mfaPending: true,
    mfaMethods: ['totp', 'passkey'],
  });
  await setConditionalMediation(page, false);
  await installPasskeyMocks(page, state);

  let markStarted: () => void = () => {};
  const started = new Promise<void>((resolve) => (markStarted = resolve));
  let releaseVerification: () => void = () => {};
  const released = new Promise<void>((resolve) => (releaseVerification = resolve));
  await page.route('**/api/login/mfa', async (route) => {
    if (route.request().method() !== 'POST') {
      await route.fallback();
      return;
    }
    markStarted();
    await released;
    state.mfaPending = false;
    state.authenticated = true;
    await fulfillJSON(route, 200, sessionResponse(state));
  });

  await page.goto(`${webAuthnOrigin}/login/mfa?return_to=/profile/security`);
  await page.getByLabel('6 位动态验证码').fill('123456');
  await page.getByRole('button', { name: '验证并登录' }).click();
  await started;

  await expect(page.getByRole('button', { name: '动态验证码', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Passkey', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: '取消并返回登录' })).toBeDisabled();

  releaseVerification();
  await expect(page).toHaveURL(/\/profile\/security$/);
});

test('a discoverable Passkey can be registered and used for passwordless login', async ({ page }) => {
  const state = newState();
  await setConditionalMediation(page, false);
  await installPasskeyMocks(page, state);
  const authenticator = await addVirtualAuthenticator(page);
  try {
    await registerPasskey(page, state);

    state.authenticated = false;
    await page.goto(`${webAuthnOrigin}/login?return_to=/profile/security`);
    await page.getByRole('button', { name: '使用 Passkey 登录' }).click();

    await expect(page).toHaveURL(/\/profile\/security$/);
    await expect(page.getByText('Work laptop', { exact: true })).toBeVisible();
    expect(state.directLoginRequests).toBe(1);
    expect(state.loginCredentialRawID).toBe(state.credentialRawID);
  } finally {
    await removeVirtualAuthenticator(authenticator);
  }
});

test('a registered Passkey completes the password login MFA challenge', async ({ page }) => {
  const state = newState();
  await setConditionalMediation(page, false);
  await installPasskeyMocks(page, state);
  const authenticator = await addVirtualAuthenticator(page);
  try {
    await registerPasskey(page, state);

    state.authenticated = false;
    state.passwordStartsMFA = true;
    await page.goto(`${webAuthnOrigin}/login?return_to=/profile/security`);
    await page.getByLabel('用户名').fill(user.username);
    await page.getByLabel('密码').fill('password-for-e2e');
    await page.getByRole('button', { name: '登录', exact: true }).click();
    await expect(page).toHaveURL(/\/login\/mfa/);
    await page.getByRole('button', { name: '使用 Passkey 验证' }).click();

    await expect(page).toHaveURL(/\/profile\/security$/);
    expect(state.mfaOptionsCSRF).toBe('csrf-mfa-pending');
    expect(state.mfaVerifyCSRF).toBe('csrf-mfa-pending');
    expect(state.mfaCredentialRawID).toBe(state.credentialRawID);
  } finally {
    await removeVirtualAuthenticator(authenticator);
  }
});

test('Passkey reauthentication retries a protected deletion exactly once', async ({ page }) => {
  const state = newState();
  await setConditionalMediation(page, false);
  await installPasskeyMocks(page, state);
  const authenticator = await addVirtualAuthenticator(page);
  try {
    await registerPasskey(page, state);
    state.deleteRequiresReauthentication = true;

    await page.getByRole('button', { name: '删除 Work laptop' }).click();
    const deleteDialog = page.getByRole('dialog', { name: '删除 Passkey' });
    await deleteDialog.getByLabel('输入“Work laptop”以确认').fill('Work laptop');
    await deleteDialog.getByRole('button', { name: '确认删除' }).click();

    const reauthDialog = page.getByRole('dialog', { name: '重新验证身份' });
    await reauthDialog.getByRole('button', { name: '使用 Passkey 验证' }).click();
    await expect(page.getByText('Passkey 已删除，当前会话已安全轮换。')).toBeVisible();
    await expect(page.getByText('尚未注册 Passkey')).toBeVisible();
    expect(state.deleteAttempts).toBe(2);
    expect(state.reauthCredentialRawID).toBe(state.credentialRawID);
  } finally {
    await removeVirtualAuthenticator(authenticator);
  }
});

test('reauthentication methods stay mutually exclusive while a Passkey request is pending', async ({ page }) => {
  const state = newState({
    identities: [{
      id: '33333333-3333-3333-3333-333333333333',
      user_id: user.id,
      provider: 'github',
      external_id: 'github-alice',
      external_username: 'alice',
      created_at: '2026-07-27T00:00:00Z',
    }],
  });
  await setConditionalMediation(page, false);
  await installPasskeyMocks(page, state);
  const authenticator = await addVirtualAuthenticator(page);
  try {
    await registerPasskey(page, state);
    state.deleteRequiresReauthentication = true;

    await page.getByRole('button', { name: '删除 Work laptop' }).click();
    const deleteDialog = page.getByRole('dialog', { name: '删除 Passkey' });
    await deleteDialog.getByLabel('输入“Work laptop”以确认').fill('Work laptop');
    await deleteDialog.getByRole('button', { name: '确认删除' }).click();

    const reauthDialog = page.getByRole('dialog', { name: '重新验证身份' });
    await reauthDialog.getByLabel('当前密码').fill('password-fallback');
    await setAutomaticPresenceSimulation(authenticator, false);
    await reauthDialog.getByRole('button', { name: '使用 Passkey 验证' }).click();
    await expect(reauthDialog.getByLabel('当前密码')).toBeDisabled();
    await expect(reauthDialog.getByRole('button', { name: '使用密码验证' })).toBeDisabled();
    await expect(reauthDialog.getByRole('button', { name: '使用 github 验证' })).toBeDisabled();
    expect(state.deleteAttempts).toBe(1);
    expect(state.reauthenticated).toBe(false);
    expect(state.reauthCredentialRawID).toBe('');
  } finally {
    await removeVirtualAuthenticator(authenticator);
  }
});

test('reauthentication exposes a retry when Passkey status loading fails', async ({ page }) => {
  const state = newState();
  await setConditionalMediation(page, false);
  await installPasskeyMocks(page, state);
  const authenticator = await addVirtualAuthenticator(page);
  try {
    await registerPasskey(page, state);
    let failStatus = true;
    await page.route('**/api/me/mfa', async (route) => {
      if (failStatus) {
        await fulfillJSON(route, 503, { error: 'MFA status temporarily unavailable' });
      } else {
        await route.fallback();
      }
    });
    state.deleteRequiresReauthentication = true;

    await page.getByRole('button', { name: '删除 Work laptop' }).click();
    const deleteDialog = page.getByRole('dialog', { name: '删除 Passkey' });
    await deleteDialog.getByLabel('输入“Work laptop”以确认').fill('Work laptop');
    await deleteDialog.getByRole('button', { name: '确认删除' }).click();

    const reauthDialog = page.getByRole('dialog', { name: '重新验证身份' });
    await expect(reauthDialog.getByRole('alert')).toContainText('MFA status temporarily unavailable');
    failStatus = false;
    await reauthDialog.getByRole('button', { name: '重试' }).click();
    await expect(reauthDialog.getByRole('button', { name: '使用 Passkey 验证' })).toBeVisible();
  } finally {
    await removeVirtualAuthenticator(authenticator);
  }
});

test('a CSRF 403 is not mistaken for a recent-authentication challenge', async ({ page }) => {
  const state = newState();
  await installPasskeyMocks(page, state);
  await page.route('**/api/me/email/change', async (route) => {
    await fulfillJSON(route, 403, { error: 'csrf_validation_failed' });
  });

  await page.goto(`${webAuthnOrigin}/profile`);
  await page.getByLabel('更换邮箱').fill('alice.new@example.com');
  await page.getByRole('button', { name: '发送确认邮件' }).click();

  await expect(page.getByRole('alert')).toContainText('安全校验失败，请刷新页面后重试');
  await expect(page.getByRole('dialog', { name: '重新验证身份' })).toHaveCount(0);
});

test('administrators can hot-update the Passkey enrollment switch after reauthentication', async ({ page }) => {
  const state = newState({ authenticated: true, role: 'admin' });
  await installPasskeyMocks(page, state);

  await page.goto('/admin/settings/security');
  await expect(page.getByRole('link', { name: '登录安全', exact: true })).toHaveAttribute('aria-current', 'page');
  const securitySection = page.getByRole('heading', { name: '登录安全策略' }).locator('..').locator('..');
  await expect(securitySection.getByRole('switch', { name: '允许 Passkey 注册' })).toHaveAttribute('aria-checked', 'true');
  await securitySection.getByRole('switch', { name: '允许 Passkey 注册' }).click();
  await securitySection.getByRole('button', { name: '保存登录安全策略' }).click();

  const reauthDialog = page.getByRole('dialog', { name: '重新验证身份' });
  await reauthDialog.getByLabel('当前密码').fill('admin-password');
  await reauthDialog.getByRole('button', { name: '使用密码验证' }).click();

  await expect(securitySection.getByText('登录安全策略已保存，立即对所有实例生效。')).toBeVisible();
  expect(state.securitySaveAttempts).toBe(2);
  expect(state.securitySaveBodies).toEqual([
    { totp_enabled: true, passkeys_enabled: false, require_mfa_for_admins: false },
    { totp_enabled: true, passkeys_enabled: false, require_mfa_for_admins: false },
  ]);
  expect(state.securitySaveCSRF).toEqual(['csrf-session', 'csrf-password-reauthenticated']);
});
