<script lang="ts">
  import { page } from '$app/stores';
  import { api, ApiError, humanVerificationChallengeFromError, isAPIErrorCode, isMFARequiredResponse, type HumanVerificationChallenge, type HumanVerificationProof, type ProviderSummary } from '$lib/api';
  import { brandingStore, consumeProviderAuthError, safeReturnPath, sessionStore } from '$lib/stores';
  import { capabilityPauseReason, isCapabilityPaused, serviceStatusStore } from '$lib/service-control';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import ProviderIcon from '$lib/components/identity/ProviderIcon.svelte';
  import HumanVerificationWidget from '$lib/components/security/HumanVerificationWidget.svelte';
  import {
    WEBAUTHN_ERROR_CODES,
    authenticationCredentialToJSON,
    classifyWebAuthnError,
    getCredential,
    isConditionalMediationAvailable,
  } from '$lib/webauthn';
  import { Fingerprint } from 'lucide-svelte';

  let username = $state('');
  let password = $state('');
  let error = $state('');
  let loading = $state(false);
  let passkeyLoading = $state(false);
  let passkeySupported = $state(false);
  let providers = $state<ProviderSummary[]>([]);
  let providersLoading = $state(true);
  let providersError = $state('');
  let cleanedReturnTo = $state<string | null>(null);
  let returnTo = $derived(cleanedReturnTo ?? safeReturnPath($page.url.searchParams.get('return_to'), '/dashboard'));
  let authPaused = $derived(isCapabilityPaused($serviceStatusStore.value, 'auth_issuance'));

  let registrationOpen = $state(false);
  let pendingVerification = $state(false);
  let conditionalController: AbortController | null = null;
  let conditionalGeneration = 0;
  let conditionalAvailable = false;
  let conditionalRestartTimer: number | null = null;
  let conditionalRestartAttempts = 0;
  let mounted = false;
  let explicitPasskeyController: AbortController | null = null;
  let explicitPasskeyGeneration = 0;
  let loginChallenge = $state<HumanVerificationChallenge | null>(null);
  let loginProof = $state<HumanVerificationProof | null>(null);
  let loginWidgetKey = $state(0);
  let providerChallenge = $state<HumanVerificationChallenge | null>(null);
  let providerProof = $state<HumanVerificationProof | null>(null);
  let providerWidgetKey = $state(0);
  let providerStarting = $state('');

  async function loadProviders() {
    providersLoading = true;
    providersError = '';
    try {
      providers = await api.getProviders();
    } catch (cause) {
      providers = [];
      providersError = cause instanceof Error ? cause.message : '外部登录方式加载失败';
    } finally {
      providersLoading = false;
    }
  }

  async function loadRegistrationOptions() {
    try {
      const options = await api.getRegistrationOptions();
      registrationOpen = options.mode !== 'closed' && options.available;
    } catch {
      registrationOpen = false;
    }
  }

  onMount(() => {
    mounted = true;
    void initialize();
    return () => {
      mounted = false;
      abortConditional();
      abortExplicitPasskey();
    };
  });

  async function initialize() {
    const providerError = consumeProviderAuthError();
    if (providerError) {
      error = providerError.message;
      const cleanURL = new URL(providerError.cleanPath, window.location.origin);
      cleanedReturnTo = safeReturnPath(cleanURL.searchParams.get('return_to'), '/dashboard');
    }
    try {
      const existing = await sessionStore.initialize(true);
      if (existing) {
        goto(existing.must_change_password
          ? `/change-password?return_to=${encodeURIComponent(returnTo)}`
          : returnTo);
        return;
      }
    } catch (cause) {
      error = cause instanceof Error ? `会话检查失败：${cause.message}` : '暂时无法连接认证服务';
    }
    const [, , loginConfig, providerConfig] = await Promise.all([
      loadProviders(), loadRegistrationOptions(),
      api.getHumanVerification('login').catch(() => null),
      api.getHumanVerification('provider_login').catch(() => null),
    ]);
    loginChallenge = loginConfig?.required ? loginConfig : null;
    providerChallenge = providerConfig?.required ? providerConfig : null;
    if (!mounted) return;
    passkeySupported = typeof PublicKeyCredential !== 'undefined' && navigator.credentials !== undefined;
    conditionalAvailable = passkeySupported && await isConditionalMediationAvailable();
    if (mounted && conditionalAvailable) void startConditionalLogin();
  }

  function clearConditionalRestart() {
    if (conditionalRestartTimer !== null) window.clearTimeout(conditionalRestartTimer);
    conditionalRestartTimer = null;
  }

  function abortConditional() {
    clearConditionalRestart();
    conditionalGeneration += 1;
    conditionalController?.abort();
    conditionalController = null;
  }

  function scheduleConditionalLogin(resetAttempts = false) {
    if (!mounted || !conditionalAvailable) return;
    if (resetAttempts) conditionalRestartAttempts = 0;
    if (conditionalRestartAttempts >= 3) return;
    clearConditionalRestart();
    const delays = [250, 1_000, 5_000];
    const delay = delays[conditionalRestartAttempts] ?? 5_000;
    conditionalRestartAttempts += 1;
    conditionalRestartTimer = window.setTimeout(() => {
      conditionalRestartTimer = null;
      if (mounted && !loading && !passkeyLoading) void startConditionalLogin();
    }, delay);
  }

  function abortExplicitPasskey() {
    explicitPasskeyGeneration += 1;
    explicitPasskeyController?.abort();
    explicitPasskeyController = null;
    passkeyLoading = false;
  }

  async function completeLogin(session: Awaited<ReturnType<typeof api.finishPasskeyLogin>>) {
    sessionStore.setSession(session);
    if (session.must_change_password) {
      await goto(`/change-password?return_to=${encodeURIComponent(returnTo)}`);
    } else if (returnTo.startsWith('/authorize')) {
      window.location.href = returnTo;
    } else {
      await goto(returnTo);
    }
  }

  function passkeyErrorMessage(cause: unknown): string {
    switch (classifyWebAuthnError(cause)) {
      case WEBAUTHN_ERROR_CODES.notAllowed:
        return '未选择 Passkey，或系统验证窗口已关闭。';
      case WEBAUTHN_ERROR_CODES.notSupported:
        return '当前浏览器或设备不支持 Passkey。';
      case WEBAUTHN_ERROR_CODES.security:
        return '当前页面不满足 Passkey 的安全环境要求，请使用 HTTPS 或 localhost。';
      case WEBAUTHN_ERROR_CODES.invalidState:
        return '这枚 Passkey 当前无法使用，请尝试其他登录方式。';
      default:
        return cause instanceof Error ? cause.message : 'Passkey 登录失败';
    }
  }

  async function startConditionalLogin() {
    if (authPaused) return;
    abortConditional();
    const controller = new AbortController();
    const generation = ++conditionalGeneration;
    conditionalController = controller;
    try {
      const options = await api.beginPasskeyLogin(true, returnTo, controller.signal);
      if (controller.signal.aborted || generation !== conditionalGeneration) return;
      const credential = await getCredential(options.public_key, {
        mediation: 'conditional',
        signal: controller.signal,
      });
      if (controller.signal.aborted || generation !== conditionalGeneration) return;
      const session = await api.finishPasskeyLogin(
        options.ceremony_id,
        authenticationCredentialToJSON(credential),
        controller.signal,
      );
      conditionalController = null;
      await completeLogin(session);
    } catch (cause) {
      const code = classifyWebAuthnError(cause);
      if (generation === conditionalGeneration) {
        conditionalController = null;
        if (code !== WEBAUTHN_ERROR_CODES.aborted) scheduleConditionalLogin();
      }
    }
  }

  async function handlePasskeyLogin() {
    if (authPaused) {
      error = capabilityPauseReason($serviceStatusStore.value, 'auth_issuance');
      return;
    }
    abortConditional();
    abortExplicitPasskey();
    error = '';
    pendingVerification = false;
    passkeyLoading = true;
    const controller = new AbortController();
    const generation = ++explicitPasskeyGeneration;
    explicitPasskeyController = controller;
    let completed = false;
    try {
      const options = await api.beginPasskeyLogin(false, returnTo, controller.signal);
      if (controller.signal.aborted || generation !== explicitPasskeyGeneration) return;
      const credential = await getCredential(options.public_key, {
        mediation: options.mediation ?? 'required',
        signal: controller.signal,
      });
      if (controller.signal.aborted || generation !== explicitPasskeyGeneration) return;
      const session = await api.finishPasskeyLogin(
        options.ceremony_id,
        authenticationCredentialToJSON(credential),
        controller.signal,
      );
      if (controller.signal.aborted || generation !== explicitPasskeyGeneration) return;
      await completeLogin(session);
      completed = true;
    } catch (cause) {
      if (classifyWebAuthnError(cause) !== WEBAUTHN_ERROR_CODES.aborted) {
        error = passkeyErrorMessage(cause);
      }
    } finally {
      if (explicitPasskeyController === controller) {
        explicitPasskeyController = null;
        passkeyLoading = false;
      }
      if (!completed && generation === explicitPasskeyGeneration) scheduleConditionalLogin(true);
    }
  }

  async function handleLogin(e: Event) {
    e.preventDefault();
    if (authPaused) {
      error = capabilityPauseReason($serviceStatusStore.value, 'auth_issuance');
      return;
    }
    abortConditional();
    abortExplicitPasskey();
    error = '';
    pendingVerification = false;
    loading = true;
    let completed = false;
    try {
      const result = await api.login(username, password, returnTo, loginProof ?? undefined);
      password = '';
      if (isMFARequiredResponse(result)) {
        completed = true;
        await goto(`/login/mfa?return_to=${encodeURIComponent(returnTo)}`);
        return;
      }
      await completeLogin(result);
      completed = true;
    } catch (err) {
      const requiredChallenge = humanVerificationChallengeFromError(err);
      if (requiredChallenge) {
        loginChallenge = requiredChallenge;
        loginProof = null;
        loginWidgetKey += 1;
      } else if (loginChallenge?.required) {
        loginProof = null;
        loginWidgetKey += 1;
      }
      pendingVerification = err instanceof ApiError
        && err.status === 403
        && isAPIErrorCode(err, 'account.email_verification_required');
      if (err instanceof ApiError && err.status === 429 && err.retryAfter) {
        error = `尝试次数过多，请在 ${err.retryAfter} 秒后重试`;
      } else {
        error = err instanceof Error ? err.message : '登录失败';
      }
    } finally {
      loading = false;
      if (!completed) scheduleConditionalLogin(true);
    }
  }

  async function handleOAuth(name: string) {
    if (authPaused) {
      error = capabilityPauseReason($serviceStatusStore.value, 'auth_issuance');
      return;
    }
    abortConditional();
    abortExplicitPasskey();
    if (providerChallenge?.required && !providerProof) {
      error = '请先完成外部登录所需的人机验证。';
      return;
    }
    if (!providerChallenge?.required) {
      window.location.href = `/auth/${encodeURIComponent(name)}/authorize?return_to=${encodeURIComponent(returnTo)}`;
      return;
    }
    providerStarting = name;
    try {
      const result = await api.startProviderLogin(name, returnTo, providerProof ?? undefined);
      window.location.href = result.redirect_url;
    } catch (cause) {
      providerProof = null;
      providerWidgetKey += 1;
      error = cause instanceof Error ? cause.message : '无法启动外部登录';
      providerStarting = '';
    }
  }
</script>

<svelte:head><title>登录 - Nya</title></svelte:head>

<main class="min-h-screen flex items-center justify-center px-4" style="background: var(--nya-gradient-soft)">
  <div class="w-full max-w-[400px]">
    <!-- 品牌区 -->
    <div class="text-center mb-8">
      <img src={$brandingStore.logo_url || '/logo.png'} alt="" class="mx-auto mb-3 h-16 w-16 select-none" draggable="false" />
      <h1 class="text-[38px] font-bold leading-none text-nya-primary">{$brandingStore.title}</h1>
      <p class="text-body text-nya-text-secondary mt-2">欢迎回来，今天也要元气满满喵～</p>
    </div>

    <!-- 登录卡片 -->
    <div class="bg-nya-surface rounded-nya-lg shadow-nya-sm border border-nya-border p-8">
      {#if error}
        <div role="alert" class="mb-5 px-4 py-3 bg-nya-danger-soft border border-nya-danger/20 rounded-nya-sm text-small text-nya-danger">
          {error}
          {#if pendingVerification}<a href="/resend-verification" class="mt-2 block font-semibold text-nya-primary hover:underline">重发验证邮件</a>{/if}
        </div>
      {/if}

      <form onsubmit={handleLogin} class="space-y-4">
        <Input id="username" label="用户名" bind:value={username} required autocomplete="username webauthn" placeholder="输入用户名" />
        <Input id="password" type="password" label="密码" bind:value={password} required autocomplete="current-password" placeholder="输入密码" />

        {#if loginChallenge?.required}
          {#key loginWidgetKey}<HumanVerificationWidget challenge={loginChallenge} bind:proof={loginProof} onerror={(message) => (error = message)} />{/key}
        {/if}

        <div class="flex items-center justify-between">
          {#if registrationOpen}<a href="/register" class="text-small text-nya-primary hover:underline">注册账号</a>{:else}<span></span>{/if}
          <a href="/forgot-password" class="text-small text-nya-primary hover:underline">忘记密码？</a>
        </div>

        <Button type="submit" {loading} disabled={passkeyLoading} requiredCapability="auth_issuance" size="lg" variant="primary" fullWidth>
          {loading ? '登录中...' : '登录'}
        </Button>
      </form>

      {#if passkeySupported}
        <div class="mt-4">
          <Button variant="secondary" size="lg" fullWidth loading={passkeyLoading} disabled={loading} requiredCapability="auth_issuance" onclick={handlePasskeyLogin}>
            <Fingerprint size={18} /> 使用 Passkey 登录
          </Button>
        </div>
      {/if}

      {#if providersLoading}
        <p class="mt-5 text-center text-small text-nya-text-tertiary" role="status">正在加载外部登录方式…</p>
      {:else if providersError}
        <div class="mt-5 flex items-center justify-between gap-3 rounded-nya-sm bg-nya-warning-soft px-3 py-2">
          <p class="text-small text-nya-warning" role="alert">外部登录方式暂时不可用</p>
          <Button variant="ghost" size="sm" onclick={loadProviders}>重试</Button>
        </div>
      {:else if providers.length > 0}
        <div class="mt-6">
          <div class="relative my-4">
            <div class="absolute inset-0 flex items-center"><div class="w-full border-t border-nya-divider"></div></div>
            <div class="relative flex justify-center text-small"><span class="px-3 bg-nya-surface text-nya-text-tertiary">或使用以下方式登录</span></div>
          </div>
          <div class="space-y-2">
            {#if providerChallenge?.required}
              {#key providerWidgetKey}<HumanVerificationWidget challenge={providerChallenge} bind:proof={providerProof} onerror={(message) => (error = message)} />{/key}
            {/if}
            {#each providers as p}
              <button
                type="button"
                disabled={authPaused || providerStarting !== ''}
                title={authPaused ? capabilityPauseReason($serviceStatusStore.value, 'auth_issuance') : undefined}
                onclick={() => void handleOAuth(p.name)}
                class="w-full h-10 flex items-center justify-center gap-2 border border-nya-border rounded-nya-sm text-body-medium text-nya-text-primary hover:bg-nya-surface-hover transition-colors duration-fast disabled:cursor-not-allowed disabled:opacity-50"
              >
                <ProviderIcon type={p.type} iconKey={p.icon_key} size={18} />
                <span>{providerStarting === p.name ? '正在跳转…' : (p.display_name || p.name)}</span>
              </button>
            {/each}
          </div>
        </div>
      {/if}
    </div>
  </div>
</main>
