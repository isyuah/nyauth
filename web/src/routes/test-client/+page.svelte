<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { api, type OAuthScopeDefinition } from '$lib/api';
  import FieldHelp from '$lib/components/ui/FieldHelp.svelte';
  import DeviceAuthorizationTest from '$lib/components/oauth/DeviceAuthorizationTest.svelte';
  import { scopeHelp } from '$lib/oauth-catalog';

  let { adminMode = false }: { adminMode?: boolean } = $props();
  let flowMode = $state<'authorization_code' | 'device_authorization'>('authorization_code');

  interface TokenResponse {
    access_token?: string;
    id_token?: string;
    refresh_token?: string;
    token_type?: string;
    expires_in?: number;
    [key: string]: unknown;
  }

  type UserInfo = Record<string, unknown>;

  const enabled = $derived(adminMode || import.meta.env.DEV || import.meta.env.VITE_ENABLE_TEST_CLIENT === 'true');
  const consolePath = $derived(adminMode ? '/admin/oauth/test' : '/test-client');
  const pendingClientIDKey = 'nya_oauth_test_client_id';
  const pendingSecretRequiredKey = 'nya_oauth_test_secret_required';

  // Config
  let clientId = $state('nya-test-client');
  let clientSecret = $state('');
  let redirectUri = $state('');
  let scopes = $state(['openid', 'profile', 'email']);

  // Flow state
  let step = $state(0); // 0=config, 1=waiting, 2=code received, 3=tokens, 4=userinfo
  let codeVerifier = $state('');
  let codeChallenge = $state('');
  let oauthState = $state('');
  let oauthNonce = $state('');
  let authCode = $state('');
  let returnedState = $state('');
  let tokens = $state<TokenResponse | null>(null);
  let userInfo = $state<UserInfo | null>(null);
  let error = $state('');
  let logs = $state<string[]>([]);
  let scopeOptions = $state(['openid', 'profile', 'email', 'offline_access']);
  let scopeDefinitions = $state<Record<string, OAuthScopeDefinition>>({});
  let secretRequiredForExchange = $state(false);

  function log(msg: string) {
    logs = [...logs, `[${new Date().toLocaleTimeString()}] ${msg}`];
  }

  function clearPendingAuthorization() {
    sessionStorage.removeItem('nya_pkce_verifier');
    sessionStorage.removeItem('nya_state');
    sessionStorage.removeItem('nya_nonce');
    sessionStorage.removeItem(pendingClientIDKey);
    sessionStorage.removeItem(pendingSecretRequiredKey);
  }

  function secureEqual(left: string, right: string): boolean {
    const length = Math.max(left.length, right.length);
    let difference = left.length ^ right.length;
    for (let i = 0; i < length; i += 1) {
      difference |= (left.charCodeAt(i) || 0) ^ (right.charCodeAt(i) || 0);
    }
    return difference === 0;
  }

  onMount(async () => {
    if (!enabled) {
      goto('/dashboard', { replaceState: true });
      return;
    }
    if (typeof window !== 'undefined') {
      redirectUri = `${window.location.origin}${consolePath}`;
    }
    if (adminMode) {
      try {
        const policy = await api.admin.getOAuthSettings();
        scopeOptions = [...policy.allowed_scopes];
        scopeDefinitions = policy.scope_definitions;
        scopes = scopes.filter((scope) => scopeOptions.includes(scope));
        if (scopes.length === 0 && scopeOptions.includes('openid')) scopes = ['openid'];
      } catch (cause) {
        error = cause instanceof Error ? cause.message : '无法加载 OAuth Scope Catalog';
      }
    }
    // Check if we have a callback (code + state in URL)
    const url = new URL(window.location.href);
    flowMode = url.searchParams.get('flow') === 'device' ? 'device_authorization' : 'authorization_code';
    const code = url.searchParams.get('code');
    const returnedSt = url.searchParams.get('state');
    const err = url.searchParams.get('error');

    if (err) {
      clearPendingAuthorization();
      window.history.replaceState({}, '', consolePath);
      error = `授权失败: ${err} - ${url.searchParams.get('error_description') || ''}`;
      step = 0;
      log(`错误: ${error}`);
      return;
    }

    if (code || returnedSt) {
      window.history.replaceState({}, '', consolePath);
      if (!code || !returnedSt) {
        clearPendingAuthorization();
        error = '授权回调缺少 code 或 state，已拒绝继续。';
        log('错误: 授权回调参数不完整');
        return;
      }
      authCode = code;
      returnedState = returnedSt;
      step = 2;
      log(`收到授权码: ${code.substring(0, 20)}...`);
      log(`收到 state: ${returnedSt}`);

      // Recover and immediately consume the one-time PKCE state.
      const savedVerifier = sessionStorage.getItem('nya_pkce_verifier');
      const savedState = sessionStorage.getItem('nya_state');
      const savedClientID = sessionStorage.getItem(pendingClientIDKey);
      const savedSecretRequired = sessionStorage.getItem(pendingSecretRequiredKey) === 'true';
      clearPendingAuthorization();
      if (!savedVerifier || !savedState || !savedClientID) {
        error = '缺少一次性 OAuth 测试状态，无法安全换取令牌。';
        log('错误: 缺少 PKCE verifier、state 或 Client ID');
        step = 0;
        return;
      }
      codeVerifier = savedVerifier;
      clientId = savedClientID;
      if (!secureEqual(savedState, returnedSt)) {
        error = 'State 不匹配！可能存在 CSRF 攻击。';
        log('错误: state 不匹配');
        step = 0;
        return;
      }

      secretRequiredForExchange = savedSecretRequired;
      if (secretRequiredForExchange) {
        log('Confidential Client 需要重新输入 Secret 后换取 Token');
        return;
      }
      void exchangeCode();
    }
  });

  // PKCE helpers
  function base64url(bytes: Uint8Array): string {
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function generatePKCE() {
    const verifierBytes = new Uint8Array(32);
    crypto.getRandomValues(verifierBytes);
    codeVerifier = base64url(verifierBytes);
    sessionStorage.setItem('nya_pkce_verifier', codeVerifier);

    // S256 challenge
    const encoder = new TextEncoder();
    const hash = await crypto.subtle.digest('SHA-256', encoder.encode(codeVerifier));
    codeChallenge = base64url(new Uint8Array(hash));
    log(`PKCE code_verifier: ${codeVerifier.substring(0, 20)}...`);
    log(`PKCE code_challenge (S256): ${codeChallenge.substring(0, 20)}...`);
  }

  function generateState() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    oauthState = base64url(bytes);
    sessionStorage.setItem('nya_state', oauthState);

    const nonceBytes = new Uint8Array(32);
    crypto.getRandomValues(nonceBytes);
    oauthNonce = base64url(nonceBytes);
    sessionStorage.setItem('nya_nonce', oauthNonce);
  }

  async function startAuth() {
    error = '';
    if (!clientId.trim()) {
      error = '请输入 Client ID';
      return;
    }
    step = 1;

    sessionStorage.setItem(pendingClientIDKey, clientId.trim());
    sessionStorage.setItem(pendingSecretRequiredKey, String(clientSecret.length > 0));

    generateState();
    await generatePKCE();

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scopes.join(' '),
      state: oauthState,
      nonce: oauthNonce,
    });

    params.set('code_challenge', codeChallenge);
    params.set('code_challenge_method', 'S256');

    const url = `/authorize?${params}`;
    log(`跳转到: ${url}`);
    window.location.href = url;
  }

  async function exchangeCode() {
    if (secretRequiredForExchange && !clientSecret) {
      error = '请重新输入 Client Secret 后换取 Token';
      return;
    }
    log('正在用授权码换取 Token...');
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code: authCode,
      redirect_uri: redirectUri,
      client_id: clientId,
    });

    if (!codeVerifier) {
      error = '缺少 PKCE verifier，无法安全换取令牌';
      step = 0;
      return;
    }
    params.set('code_verifier', codeVerifier);
    if (clientSecret) params.set('client_secret', clientSecret);
    clientSecret = '';

    try {
      const res = await fetch('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params,
      });
      const data = await res.json() as TokenResponse & { error?: string; error_description?: string };
      if (res.ok) {
        tokens = data;
        secretRequiredForExchange = false;
        step = 3;
        log('Token 获取成功！');
        log(`Access Token: ${data.access_token?.substring(0, 30)}...`);
        if (data.id_token) log(`ID Token: ${data.id_token.substring(0, 30)}...`);
        if (data.refresh_token) log(`Refresh Token: ${data.refresh_token.substring(0, 16)}...`);
      } else {
        error = `Token 请求失败: ${data.error} - ${data.error_description || ''}`;
        log(`错误: ${error}`);
      }
    } catch (e) {
      error = `请求失败: ${e}`;
      log(`错误: ${error}`);
    }
  }

  async function fetchUserInfo() {
    if (!tokens?.access_token) return;
    log('正在获取用户信息...');
    try {
      const res = await fetch('/userinfo', {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      });
      const data = await res.json() as UserInfo & { error?: string };
      if (!res.ok) {
        error = `UserInfo 请求失败: ${data.error || `HTTP ${res.status}`}`;
        log(`错误: ${error}`);
        return;
      }
      userInfo = data;
      step = 4;
      log('用户信息获取成功！');
    } catch (e) {
      error = `UserInfo 请求失败: ${e}`;
    }
  }

  function reset() {
    step = 0;
    tokens = null;
    userInfo = null;
    authCode = '';
    clientSecret = '';
    secretRequiredForExchange = false;
    error = '';
    logs = [];
    clearPendingAuthorization();
  }

  function toggleScope(s: string) {
    if (scopes.includes(s)) scopes = scopes.filter(x => x !== s);
    else scopes = [...scopes, s];
  }

  function setFlowMode(value: 'authorization_code' | 'device_authorization') {
    flowMode = value;
    const current = new URL(window.location.href);
    if (value === 'device_authorization') current.searchParams.set('flow', 'device');
    else current.searchParams.delete('flow');
    window.history.replaceState(window.history.state, '', `${current.pathname}${current.search}${current.hash}`);
  }
</script>

<svelte:head><title>OAuth 流程测试 - Nya</title></svelte:head>

<div class="min-h-screen bg-[var(--nya-bg)] p-6" style="max-width: 800px; margin: 0 auto;">
  <h1 style="font-size: 24px; font-weight: 700; color: var(--nya-text-primary); margin-bottom: 4px;">OAuth 2.0 流程测试</h1>
  <p style="font-size: 14px; color: var(--nya-text-secondary); margin-bottom: 16px;">使用真实协议端点检查 Consent、Token 和 UserInfo</p>

  <div class="mb-6 inline-flex rounded-nya-sm border border-nya-border bg-nya-surface p-1" role="group" aria-label="OAuth 测试流程">
    <button type="button" onclick={() => setFlowMode('authorization_code')} class="h-8 rounded-nya-xs px-3 text-small font-semibold {flowMode === 'authorization_code' ? 'bg-nya-primary-soft text-nya-primary' : 'text-nya-text-secondary hover:bg-nya-surface-soft'}">Authorization Code + PKCE</button>
    <button type="button" onclick={() => setFlowMode('device_authorization')} class="h-8 rounded-nya-xs px-3 text-small font-semibold {flowMode === 'device_authorization' ? 'bg-nya-primary-soft text-nya-primary' : 'text-nya-text-secondary hover:bg-nya-surface-soft'}">Device Authorization</button>
  </div>

  {#if flowMode === 'device_authorization'}
    <DeviceAuthorizationTest {adminMode} />
  {:else}

  {#if error}
    <div class="mb-4 px-4 py-3 rounded-lg" style="background: var(--nya-danger-soft); color: var(--nya-danger); font-size: 14px;">
      {error}
      <button onclick={() => (error = '')} class="ml-2 underline">清除</button>
    </div>
  {/if}

  <!-- 步骤指示器 -->
  <div class="flex items-center gap-2 mb-6">
    {#each ['配置', '授权', '换取 Token', '用户信息'] as label, i}
      <div class="flex items-center gap-2">
        <div
          class="flex items-center justify-center rounded-full"
          style="width: 28px; height: 28px; font-size: 12px; font-weight: 600;
            background: {step >= i ? 'var(--nya-primary)' : 'var(--nya-surface-muted)'};
            color: {step >= i ? '#fff' : 'var(--nya-text-tertiary)'};"
        >{i + 1}</div>
        <span style="font-size: 12px; color: {step >= i ? 'var(--nya-text-primary)' : 'var(--nya-text-tertiary)'};">{label}</span>
        {#if i < 3}<div style="width: 24px; height: 1px; background: var(--nya-divider);"></div>{/if}
      </div>
    {/each}
  </div>

  <!-- 配置区 -->
  {#if step === 0}
    <div class="bg-[var(--nya-surface)] border border-[var(--nya-border)] rounded-xl p-5 mb-4" style="box-shadow: var(--nya-shadow-card);">
      <h3 style="font-size: 16px; font-weight: 650; margin-bottom: 16px;">客户端配置</h3>
      <div class="space-y-4">
        <div>
          <label for="test-client-id" style="font-size: 13px; font-weight: 500; color: var(--nya-text-secondary); display: block; margin-bottom: 4px;">Client ID</label>
          <input id="test-client-id" bind:value={clientId} style="width: 100%; height: 38px; padding: 0 12px; border: 1px solid var(--nya-border-strong); border-radius: 9px; font-size: 14px; font-family: monospace;" />
        </div>
        <div>
          <label for="test-redirect-uri" style="font-size: 13px; font-weight: 500; color: var(--nya-text-secondary); display: block; margin-bottom: 4px;">Redirect URI</label>
          <input id="test-redirect-uri" bind:value={redirectUri} style="width: 100%; height: 38px; padding: 0 12px; border: 1px solid var(--nya-border-strong); border-radius: 9px; font-size: 14px; font-family: monospace;" />
        </div>
        <div>
          <label for="test-client-secret" style="font-size: 13px; font-weight: 500; color: var(--nya-text-secondary); display: block; margin-bottom: 4px;">Client Secret <span style="font-weight: 400; color: var(--nya-text-tertiary);">（Public Client 留空）</span></label>
          <input id="test-client-secret" type="password" bind:value={clientSecret} autocomplete="off" data-1p-ignore data-bwignore="true" style="width: 100%; height: 38px; padding: 0 12px; border: 1px solid var(--nya-border-strong); border-radius: 9px; font-size: 14px; font-family: monospace;" />
          <p style="margin-top: 4px; font-size: 12px; color: var(--nya-text-tertiary);">Secret 只保存在当前页面内存中，不写入 URL、日志或浏览器存储。</p>
        </div>
        <div>
          <span id="test-scopes-label" style="font-size: 13px; font-weight: 500; color: var(--nya-text-secondary); display: block; margin-bottom: 8px;">Scopes</span>
          <div class="flex flex-wrap gap-2" aria-labelledby="test-scopes-label">
            {#each scopeOptions as s}
              <span class="inline-flex items-center gap-1">
                <button
                  onclick={() => toggleScope(s)}
                  style="padding: 4px 12px; border-radius: var(--nya-radius-pill); font-size: 12px; font-weight: 550;
                    background: {scopes.includes(s) ? 'var(--nya-primary-soft)' : 'var(--nya-surface-muted)'};
                    color: {scopes.includes(s) ? 'var(--nya-primary)' : 'var(--nya-text-tertiary)'};
                    border: 1px solid {scopes.includes(s) ? 'var(--nya-primary-border)' : 'var(--nya-divider)'};"
                >{s}</button>
                {#if scopeDefinitions[s]}<FieldHelp id={`oauth-test-${s}-help`} text={scopeHelp(scopeDefinitions[s])} label={`查看 ${s} Scope 说明`} />{/if}
              </span>
            {/each}
          </div>
        </div>
        <p style="font-size: 13px; color: var(--nya-text-secondary);">PKCE 方法：S256（必需）</p>
      </div>
    </div>
    <button
      onclick={startAuth}
      style="height: 44px; padding: 0 24px; background: var(--nya-primary); color: #fff; border-radius: 9px; font-size: 14px; font-weight: 550; box-shadow: 0 5px 12px rgba(124, 92, 255, 0.20);"
    >开始授权流程</button>
  {/if}

  {#if step === 1}
    <div class="bg-[var(--nya-surface)] border border-[var(--nya-border)] rounded-xl p-5" style="box-shadow: var(--nya-shadow-card);">
      <p style="color: var(--nya-text-secondary);">正在跳转到授权页面...</p>
    </div>
  {/if}

  {#if step === 2}
    <div class="bg-[var(--nya-surface)] border border-[var(--nya-border)] rounded-xl p-5" style="box-shadow: var(--nya-shadow-card);">
      {#if secretRequiredForExchange}
        <h3 style="font-size: 16px; font-weight: 650; margin-bottom: 8px;">重新输入 Client Secret</h3>
        <p style="color: var(--nya-text-secondary); font-size: 13px; margin-bottom: 12px;">为避免持久化 Secret，授权回调后需要再次输入。该值只用于本次 Token 请求。</p>
        <input aria-label="回调后的 Client Secret" type="password" bind:value={clientSecret} autocomplete="off" data-1p-ignore data-bwignore="true" style="width: 100%; height: 38px; padding: 0 12px; border: 1px solid var(--nya-border-strong); border-radius: 9px; font-size: 14px; font-family: monospace;" />
        <button onclick={exchangeCode} style="height: 38px; margin-top: 12px; padding: 0 16px; background: var(--nya-primary); color: #fff; border-radius: 9px; font-size: 13px; font-weight: 550;">换取 Token</button>
      {:else}
        <p style="color: var(--nya-text-secondary);">正在换取 Token...</p>
      {/if}
    </div>
  {/if}

  <!-- Token 结果 -->
  {#if step >= 3 && tokens}
    <div class="bg-[var(--nya-surface)] border border-[var(--nya-border)] rounded-xl p-5 mb-4" style="box-shadow: var(--nya-shadow-card);">
      <h3 style="font-size: 16px; font-weight: 650; margin-bottom: 12px;">Token 响应</h3>
      <pre style="font-size: 12px; background: var(--nya-surface-muted); padding: 12px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; word-break: break-all;">{JSON.stringify(tokens, null, 2)}</pre>
      <div class="flex gap-2 mt-3">
        <button onclick={fetchUserInfo} style="height: 32px; padding: 0 12px; background: var(--nya-primary-soft); color: var(--nya-primary); border-radius: 9px; font-size: 12px; font-weight: 550;">获取用户信息</button>
        <button onclick={reset} style="height: 32px; padding: 0 12px; background: var(--nya-surface-muted); color: var(--nya-text-secondary); border-radius: 9px; font-size: 12px;">重新测试</button>
      </div>
    </div>
  {/if}

  <!-- UserInfo 结果 -->
  {#if step >= 4 && userInfo}
    <div class="bg-[var(--nya-surface)] border border-[var(--nya-border)] rounded-xl p-5 mb-4" style="box-shadow: var(--nya-shadow-card);">
      <h3 style="font-size: 16px; font-weight: 650; margin-bottom: 12px;">用户信息 (UserInfo)</h3>
      <pre style="font-size: 12px; background: var(--nya-surface-muted); padding: 12px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap;">{JSON.stringify(userInfo, null, 2)}</pre>
    </div>
  {/if}

  <!-- 日志 -->
  {#if logs.length > 0}
    <div class="bg-[var(--nya-surface)] border border-[var(--nya-border)] rounded-xl p-5" style="box-shadow: var(--nya-shadow-card);">
      <h3 style="font-size: 16px; font-weight: 650; margin-bottom: 12px;">流程日志</h3>
      <div style="font-size: 12px; font-family: monospace; background: #1e1e2e; color: #cdd6f4; padding: 12px; border-radius: 8px; max-height: 300px; overflow-y: auto;">
        {#each logs as logLine}
          <div style="line-height: 1.8;">{logLine}</div>
        {/each}
      </div>
    </div>
  {/if}
  {/if}
</div>
