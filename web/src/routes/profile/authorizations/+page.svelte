<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type OAuthAuthorization } from '$lib/api';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import { AppWindow } from 'lucide-svelte';

  let authorizations = $state<OAuthAuthorization[]>([]);
  let loading = $state(true);
  let error = $state('');
  let target = $state<OAuthAuthorization | null>(null);
  let confirmOpen = $state(false);
  let actionError = $state('');

  async function loadAuthorizations() {
    loading = true;
    error = '';
    try {
      authorizations = await api.getMyAuthorizations();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'OAuth 授权加载失败';
    } finally {
      loading = false;
    }
  }

  onMount(loadAuthorizations);

  function requestRevocation(authorization: OAuthAuthorization) {
    target = authorization;
    actionError = '';
    confirmOpen = true;
  }

  async function revokeAuthorization() {
    const authorization = target;
    if (!authorization) return;
    actionError = '';
    try {
      await api.revokeMyAuthorization(authorization.client_id);
      authorizations = authorizations.filter((item) => item.client_id !== authorization.client_id);
      target = null;
    } catch (cause) {
      actionError = cause instanceof Error ? cause.message : '无法撤销 OAuth 授权';
      throw cause;
    }
  }
</script>

<svelte:head><title>OAuth 应用授权 - Nya</title></svelte:head>

<section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
  <div class="border-b border-nya-divider px-7 py-5">
    <h2 class="text-card-title text-nya-text-primary">OAuth 应用授权</h2>
    <p class="mt-1 text-body text-nya-text-secondary">查看已获准访问账户信息的应用，并立即撤销其 Token 与后续刷新能力。</p>
  </div>
  <div class="px-7 py-6">
    {#if loading}
      <p class="text-body text-nya-text-tertiary" role="status">正在加载应用授权…</p>
    {:else if error}
      <div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2"><p class="text-small text-nya-danger">{error}</p><Button variant="ghost" size="sm" onclick={loadAuthorizations}>重试</Button></div>
    {:else if authorizations.length === 0}
      <p class="text-body text-nya-text-tertiary">当前没有活动的 OAuth 应用授权。</p>
    {:else}
      <div class="divide-y divide-nya-divider">
        {#each authorizations as authorization}
          <div class="flex flex-col justify-between gap-3 py-4 sm:flex-row sm:items-center">
            <div class="flex min-w-0 items-start gap-3">
              <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-blue-soft"><AppWindow size={19} class="text-nya-blue" /></span>
              <div class="min-w-0">
                <p class="text-body-medium font-semibold text-nya-text-primary">{authorization.client_name}</p>
                <p class="mt-1 text-small text-nya-text-tertiary">授权于 {new Date(authorization.granted_at).toLocaleString()}{#if authorization.last_used_at} · 最近使用 {new Date(authorization.last_used_at).toLocaleString()}{/if}</p>
                <div class="mt-2 flex flex-wrap gap-1.5">{#each authorization.scopes as scope}<Badge variant={scope === 'offline_access' ? 'warning' : 'default'}>{scope}</Badge>{/each}</div>
              </div>
            </div>
            <Button variant="ghost" size="sm" onclick={() => requestRevocation(authorization)}>撤销授权</Button>
          </div>
        {/each}
      </div>
    {/if}
  </div>
</section>

<ConfirmDialog
  bind:open={confirmOpen}
  title="撤销 OAuth 应用授权"
  description={`撤销后，“${target?.client_name || ''}”现有的访问令牌和刷新令牌将失效；再次使用时需要重新授权。`}
  confirmLabel="撤销授权"
  error={actionError}
  onconfirm={revokeAuthorization}
/>
