<script lang="ts">
  import { onMount } from 'svelte';

  // Config
  let clientId = $state('nya-test-client');
  let redirectUri = $state('');
  let scopes = $state(['openid', 'profile', 'email']);

  // Flow state
  let step = $state(0); // 0=config, 1=waiting, 2=code received, 3=tokens, 4=userinfo
  let codeVerifier = $state('');
  let codeChallenge = $state('');
  let oauthState = $state('');
  let authCode = $state('');
  let returnedState = $state('');
  let tokens = $state<any>(null);
  let userInfo = $state<any>(null);
  let error = $state('');
  let logs = $state<string[]>([]);

  function log(msg: string) {
    logs = [...logs, `[${new Date().toLocaleTimeString()}] ${msg}`];
  }

  function clearPendingAuthorization() {
    sessionStorage.removeItem('nya_pkce_verifier');
    sessionStorage.removeItem('nya_state');
  }

  function secureEqual(left: string, right: string): boolean {
    const length = Math.max(left.length, right.length);
    let difference = left.length ^ right.length;
    for (let i = 0; i < length; i += 1) {
      difference |= (left.charCodeAt(i) || 0) ^ (right.charCodeAt(i) || 0);
    }
    return difference === 0;
  }

  onMount(() => {
    if (typeof window !== 'undefined') {
      redirectUri = `${window.location.origin}/test-client`;
    }
    // Check if we have a callback (code + state in URL)
    const url = new URL(window.location.href);
    const code = url.searchParams.get('code');
    const returnedSt = url.searchParams.get('state');
    const err = url.searchParams.get('error');

    if (err) {
      clearPendingAuthorization();
      window.history.replaceState({}, '', '/test-client');
      error = `授权失败: ${err} - ${url.searchParams.get('error_description') || ''}`;
      step = 0;
      log(`错误: ${error}`);
      return;
    }

    if (code || returnedSt) {
      window.history.replaceState({}, '', '/test-client');
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
      clearPendingAuthorization();
      if (!savedVerifier || !savedState) {
        error = '缺少一次性 PKCE 状态，无法安全换取令牌。';
        log('错误: 缺少 PKCE verifier 或 state');
        step = 0;
        return;
      }
      codeVerifier = savedVerifier;
      if (!secureEqual(savedState, returnedSt)) {
        error = 'State 不匹配！可能存在 CSRF 攻击。';
        log('错误: state 不匹配');
        step = 0;
        return;
      }

      // Auto-exchange
      exchangeCode();
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
  }

  async function startAuth() {
    error = '';
    step = 1;

    generateState();
    await generatePKCE();

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scopes.join(' '),
      state: oauthState,
    });

    params.set('code_challenge', codeChallenge);
    params.set('code_challenge_method', 'S256');

    const url = `/authorize?${params}`;
    log(`跳转到: ${url}`);
    window.location.href = url;
  }

  async function exchangeCode() {
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

    try {
      const res = await fetch('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params,
      });
      const data = await res.json();
      if (res.ok) {
        tokens = data;
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
      userInfo = await res.json();
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
    error = '';
    logs = [];
	clearPendingAuthorization();
  }

  const scopeOptions = ['openid', 'profile', 'email', 'offline_access'];

  function toggleScope(s: string) {
    if (scopes.includes(s)) scopes = scopes.filter(x => x !== s);
    else scopes = [...scopes, s];
  }
</script>

<svelte:head><title>OAuth 测试客户端 - Nya</title></svelte:head>

<div class="min-h-screen bg-[var(--nya-bg)] p-6" style="max-width: 800px; margin: 0 auto;">
  <h1 style="font-size: 24px; font-weight: 700; color: var(--nya-text-primary); margin-bottom: 4px;">OAuth 2.0 测试客户端</h1>
  <p style="font-size: 14px; color: var(--nya-text-secondary); margin-bottom: 24px;">测试完整的 Authorization Code + PKCE 流程</p>

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
          <span id="test-scopes-label" style="font-size: 13px; font-weight: 500; color: var(--nya-text-secondary); display: block; margin-bottom: 8px;">Scopes</span>
          <div class="flex flex-wrap gap-2" aria-labelledby="test-scopes-label">
            {#each scopeOptions as s}
              <button
                onclick={() => toggleScope(s)}
                style="padding: 4px 12px; border-radius: var(--nya-radius-pill); font-size: 12px; font-weight: 550;
                  background: {scopes.includes(s) ? 'var(--nya-primary-soft)' : 'var(--nya-surface-muted)'};
                  color: {scopes.includes(s) ? 'var(--nya-primary)' : 'var(--nya-text-tertiary)'};
                  border: 1px solid {scopes.includes(s) ? 'var(--nya-primary-border)' : 'var(--nya-divider)'};"
              >{s}</button>
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
      <p style="color: var(--nya-text-secondary);">正在换取 Token...</p>
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
</div>
