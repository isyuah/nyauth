<script lang="ts">
  import { page } from '$app/stores';
  import { api, ApiError } from '$lib/api';
  import { consumeProviderAuthError, safeReturnPath, sessionStore } from '$lib/stores';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';

  let username = $state('');
  let password = $state('');
  let error = $state('');
  let loading = $state(false);
  let providers = $state<Array<{ name: string; type: string }>>([]);
  let returnTo = $derived(safeReturnPath($page.url.searchParams.get('return_to'), '/dashboard'));

  onMount(async () => {
    const providerError = consumeProviderAuthError();
    if (providerError) error = providerError;
    const existing = await sessionStore.initialize();
    if (existing) {
      goto(existing.must_change_password ? '/change-password' : returnTo);
      return;
    }
    try { providers = await api.getProviders(); } catch {}
  });

  async function handleLogin(e: Event) {
    e.preventDefault();
    error = '';
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

<div class="min-h-screen flex items-center justify-center px-4" style="background: var(--nya-gradient-soft)">
  <div class="w-full max-w-[400px]">
    <!-- 品牌区 -->
    <div class="text-center mb-8">
      <div class="relative inline-block">
        <span class="text-display bg-nya-gradient-brand bg-clip-text text-transparent">Nya</span>
        <svg class="absolute -top-3 -left-2 w-8 h-5" viewBox="0 0 24 16" fill="none">
          <path d="M2 16L8 2L12 10L16 2L22 16" stroke="var(--nya-primary)" stroke-width="2" stroke-linecap="round" fill="var(--nya-primary-soft)"/>
        </svg>
      </div>
      <p class="text-body text-nya-text-secondary mt-2">欢迎回来，今天也要元气满满喵～</p>
    </div>

    <!-- 登录卡片 -->
    <div class="bg-nya-surface rounded-nya-lg shadow-nya-sm border border-nya-border p-8">
      {#if error}
        <div class="mb-5 px-4 py-3 bg-nya-danger-soft border border-nya-danger/20 rounded-nya-sm text-small text-nya-danger">
          {error}
        </div>
      {/if}

      <form onsubmit={handleLogin} class="space-y-4">
        <Input id="username" label="用户名" bind:value={username} required placeholder="输入用户名" />
        <Input id="password" type="password" label="密码" bind:value={password} required placeholder="输入密码" />

        <Button type="submit" {loading} size="lg" variant="primary">
          {loading ? '登录中...' : '登录'}
        </Button>
      </form>

      {#if providers.length > 0}
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
</div>
