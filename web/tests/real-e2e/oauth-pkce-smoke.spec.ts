import { createHash, randomBytes } from 'node:crypto';
import { expect, test } from '@playwright/test';

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function base64URL(value: Buffer): string {
  return value.toString('base64url');
}

test('bootstrap admin changes password and completes Authorization Code + PKCE', async ({ page, request }) => {
  const baseURL = requiredEnvironment('NYAUTH_REAL_E2E_BASE_URL');
  const initialPassword = requiredEnvironment('NYAUTH_REAL_E2E_INITIAL_PASSWORD');
  const changedPassword = requiredEnvironment('NYAUTH_REAL_E2E_CHANGED_PASSWORD');
  const applicationName = `Real PKCE ${Date.now()}`;
  const redirectURI = `${baseURL}/real-e2e/callback`;

  await page.goto('/login');
  await page.getByLabel('用户名').fill('admin');
  await page.getByLabel('密码').fill(initialPassword);
  await page.getByRole('button', { name: '登录', exact: true }).click();

  await expect(page).toHaveURL(/\/change-password(?:\?|$)/);
  await page.getByLabel('当前密码').fill(initialPassword);
  await page.locator('#new-password').fill(changedPassword);
  await page.getByLabel('确认新密码').fill(changedPassword);
  await page.getByRole('button', { name: '确认修改' }).click();
  await expect(page).toHaveURL(/\/dashboard(?:\?|$)/);

  await page.goto('/dashboard/apps');
  await expect(page.getByRole('heading', { name: '我的应用' })).toBeVisible();
  await page.getByRole('button', { name: '创建应用', exact: true }).first().click();

  const dialog = page.getByRole('dialog', { name: '创建应用' });
  await dialog.getByLabel('应用名称').fill(applicationName);
  await dialog.getByLabel(/Redirect URI/).first().fill(redirectURI);
  await dialog.getByRole('checkbox', { name: /公共客户端/ }).check();
  await dialog.getByRole('button', { name: '创建', exact: true }).click();

  const application = page.locator('section').filter({ has: page.getByRole('heading', { name: applicationName }) });
  await expect(application).toBeVisible();
  const clientID = (await application.locator('code').first().textContent())?.trim();
  expect(clientID, 'created OAuth client ID').toBeTruthy();

  const verifier = base64URL(randomBytes(32));
  const challenge = base64URL(createHash('sha256').update(verifier).digest());
  const state = base64URL(randomBytes(18));
  const nonce = base64URL(randomBytes(18));
  const authorizationURL = new URL('/authorize', baseURL);
  authorizationURL.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientID!,
    redirect_uri: redirectURI,
    scope: 'openid profile',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString();

  await page.goto(authorizationURL.toString());
  await expect(page).toHaveURL(/\/consent\?challenge=/);
  await expect(page.getByText(applicationName, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: '授权', exact: true }).click();
  await page.waitForURL((url) => url.pathname === '/real-e2e/callback' && url.searchParams.has('code'));

  const callbackURL = new URL(page.url());
  expect(callbackURL.searchParams.get('state')).toBe(state);
  const authorizationCode = callbackURL.searchParams.get('code');
  expect(authorizationCode, 'authorization code').toBeTruthy();

  const tokenResponse = await request.post(`${baseURL}/token`, {
    form: {
      grant_type: 'authorization_code',
      client_id: clientID!,
      code: authorizationCode!,
      redirect_uri: redirectURI,
      code_verifier: verifier,
    },
  });
  const tokenBody = await tokenResponse.text();
  expect(tokenResponse.status(), tokenBody).toBe(200);
  const tokens = JSON.parse(tokenBody) as { access_token?: string; id_token?: string; token_type?: string };
  expect(tokens.token_type).toBe('Bearer');
  expect(tokens.access_token).toBeTruthy();
  expect(tokens.id_token).toBeTruthy();

  const userInfoResponse = await request.get(`${baseURL}/userinfo`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  const userInfoBody = await userInfoResponse.text();
  expect(userInfoResponse.status(), userInfoBody).toBe(200);
  const userInfo = JSON.parse(userInfoBody) as { sub?: string; preferred_username?: string };
  expect(userInfo.sub).toBeTruthy();
  expect(userInfo.preferred_username).toBe('admin');
});
