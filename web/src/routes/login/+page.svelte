<script lang="ts">
  import { page } from '$app/stores';
  import { api, ApiError } from '$lib/api';
  import { brandingStore, consumeProviderAuthError, safeReturnPath, sessionStore } from '$lib/stores';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';

  let username = $state('');
  let password = $state('');
  let error = $state('');
  let loading = $state(false);
  let providers = $state<Array<{ name: string; type: string }>>([]);
  let providersLoading = $state(true);
  let providersError = $state('');
  let cleanedReturnTo = $state<string | null>(null);
  let returnTo = $derived(cleanedReturnTo ?? safeReturnPath($page.url.searchParams.get('return_to'), '/dashboard'));

  let registrationOpen = $state(false);
  let pendingVerification = $state(false);

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
      registrationOpen = options.mode !== 'closed';
    } catch {
      registrationOpen = false;
    }
  }

  onMount(async () => {
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
    await Promise.all([loadProviders(), loadRegistrationOptions()]);
  });

  async function handleLogin(e: Event) {
    e.preventDefault();
    error = '';
    pendingVerification = false;
    loading = true;
    try {
      const session = await api.login(username, password);
      sessionStore.setSession(session);
      if (session.must_change_password) {
        goto(`/change-password?return_to=${encodeURIComponent(returnTo)}`);
      } else if (returnTo.startsWith('/authorize')) {
        window.location.href = returnTo;
      } else {
        goto(returnTo);
      }
    } catch (err) {
      pendingVerification = err instanceof ApiError
        && err.status === 403
        && err.serverMessage.toLowerCase() === 'email verification is required before signing in';
      if (err instanceof ApiError && err.status === 429 && err.retryAfter) {
        error = `尝试次数过多，请在 ${err.retryAfter} 秒后重试`;
      } else {
        error = err instanceof Error ? err.message : '登录失败';
      }
    } finally {
      loading = false;
    }
  }

  function handleOAuth(name: string) {
    window.location.href = `/auth/${encodeURIComponent(name)}/authorize?return_to=${encodeURIComponent(returnTo)}`;
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
        <Input id="username" label="用户名" bind:value={username} required autocomplete="username" placeholder="输入用户名" />
        <Input id="password" type="password" label="密码" bind:value={password} required autocomplete="current-password" placeholder="输入密码" />

        <div class="flex items-center justify-between">
          {#if registrationOpen}<a href="/register" class="text-small text-nya-primary hover:underline">注册账号</a>{:else}<span></span>{/if}
          <a href="/forgot-password" class="text-small text-nya-primary hover:underline">忘记密码？</a>
        </div>

        <Button type="submit" {loading} size="lg" variant="primary" fullWidth>
          {loading ? '登录中...' : '登录'}
        </Button>
      </form>

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
            {#each providers as p}
              <button
                onclick={() => handleOAuth(p.name)}
                class="w-full h-10 flex items-center justify-center gap-2 border border-nya-border rounded-nya-sm text-body-medium text-nya-text-primary hover:bg-nya-surface-hover transition-colors duration-fast"
              >
                <span class="capitalize">{p.name}</span>
              </button>
            {/each}
          </div>
        </div>
      {/if}
    </div>
  </div>
</main>
