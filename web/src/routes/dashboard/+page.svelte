<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { api, type User } from '$lib/api';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import { AppWindow, KeyRound, UserRound } from 'lucide-svelte';

  const testClientEnabled = import.meta.env.DEV || import.meta.env.VITE_ENABLE_TEST_CLIENT === 'true';
  let me = $state<User | null>(null);
  let appCount = $state(0);
  let appLimit = $state(0);
  let identityCount = $state(0);
  let loading = $state(true);
  let error = $state('');

  async function loadOverview() {
    loading = true;
    error = '';
    try {
      const [user, apps, identities] = await Promise.all([api.getMe(), api.my.getClients(), api.getMyIdentities()]);
      me = user;
      appCount = apps.quota_used;
      appLimit = apps.quota_limit;
      identityCount = identities.length;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '概览加载失败';
    } finally {
      loading = false;
    }
  }

  onMount(loadOverview);
</script>

<svelte:head><title>用户中心 - Nya</title></svelte:head>

<div class="mb-6"><h1 class="text-2xl font-bold text-nya-text-primary">欢迎回来{me?.display_name ? `，${me.display_name}` : ''}</h1><p class="mt-1 text-body text-nya-text-secondary">管理账户资料和 OAuth 应用</p></div>

<ResourceState {loading} {error} empty={!me} emptyTitle="无法显示账户概览" onretry={loadOverview}>
  {#snippet children()}
    <div class="grid gap-4 [grid-template-columns:repeat(auto-fit,minmax(220px,1fr))]">
      <button type="button" onclick={() => goto('/dashboard/apps')} class="min-h-28 rounded-nya-card border border-nya-border bg-nya-surface p-5 text-left shadow-nya-card transition-shadow hover:shadow-nya-hover"><div class="mb-3 flex items-center gap-3"><span class="flex h-10 w-10 items-center justify-center rounded-full bg-nya-blue-soft"><AppWindow size={20} class="text-nya-blue" /></span><span class="text-body text-nya-text-tertiary">我的应用</span></div><p class="text-[28px] font-bold text-nya-text-primary">{appCount}/{appLimit}</p></button>
      <button type="button" onclick={() => goto('/profile')} class="min-h-28 rounded-nya-card border border-nya-border bg-nya-surface p-5 text-left shadow-nya-card transition-shadow hover:shadow-nya-hover"><div class="mb-3 flex items-center gap-3"><span class="flex h-10 w-10 items-center justify-center rounded-full bg-nya-primary-soft"><UserRound size={20} class="text-nya-primary" /></span><span class="text-body text-nya-text-tertiary">个人资料</span></div><p class="text-body text-nya-text-secondary">{identityCount} 个外部身份已绑定</p></button>
      {#if testClientEnabled}<button type="button" onclick={() => goto('/test-client')} class="min-h-28 rounded-nya-card border border-nya-border bg-nya-surface p-5 text-left shadow-nya-card transition-shadow hover:shadow-nya-hover"><div class="mb-3 flex items-center gap-3"><span class="flex h-10 w-10 items-center justify-center rounded-full bg-nya-mint-soft"><KeyRound size={20} class="text-nya-mint" /></span><span class="text-body text-nya-text-tertiary">OAuth 测试</span></div><p class="text-body text-nya-text-secondary">仅开发环境可用</p></button>{/if}
    </div>
  {/snippet}
</ResourceState>
