<script lang="ts">
  import { api } from '$lib/api';
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { AppWindow, User, KeyRound } from 'lucide-svelte';

  let me = $state<any>(null);
  let appCount = $state(0);
  let identityCount = $state(0);
  let loading = $state(true);

  onMount(async () => {
    try {
      me = await api.getMe();
      const apps = await req<any>('/api/my/clients');
      appCount = apps?.total || 0;
    } catch {} finally { loading = false; }
  });

  async function req<T>(path: string): Promise<T> {
    const token = localStorage.getItem('nya_token');
    const res = await fetch(path, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) throw new Error(`${res.status}`);
    return res.json();
  }
</script>

<svelte:head><title>用户中心 - Nya</title></svelte:head>

<div style="margin-bottom: 24px;">
  <h1 style="font-size: 24px; font-weight: 700; color: var(--nya-text-primary); margin: 0;">
    欢迎回来{me?.display_name ? `，${me.display_name}` : ''}！
  </h1>
  <p style="font-size: 14px; color: var(--nya-text-secondary); margin-top: 4px;">管理你的账户和应用</p>
</div>

<div class="grid" style="gap: 16px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
  <button onclick={() => goto('/dashboard/apps')} class="bg-[var(--nya-surface)] border border-[var(--nya-border)] text-left transition-all hover:shadow-nya-hover" style="min-height: 100px; padding: 20px; border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card);">
    <div class="flex items-center gap-3 mb-3">
      <div class="flex items-center justify-center rounded-full" style="width: 40px; height: 40px; background: var(--nya-blue-soft);">
        <AppWindow size={20} style="color: var(--nya-blue);" />
      </div>
      <span style="font-size: 13px; color: var(--nya-text-tertiary);">我的应用</span>
    </div>
    <p style="font-size: 28px; font-weight: 720; color: var(--nya-text-primary);">{appCount}</p>
  </button>

  <button onclick={() => goto('/profile')} class="bg-[var(--nya-surface)] border border-[var(--nya-border)] text-left transition-all hover:shadow-nya-hover" style="min-height: 100px; padding: 20px; border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card);">
    <div class="flex items-center gap-3 mb-3">
      <div class="flex items-center justify-center rounded-full" style="width: 40px; height: 40px; background: var(--nya-primary-soft);">
        <User size={20} style="color: var(--nya-primary);" />
      </div>
      <span style="font-size: 13px; color: var(--nya-text-tertiary);">个人资料</span>
    </div>
    <p style="font-size: 14px; color: var(--nya-text-secondary);">编辑个人信息和头像</p>
  </button>

  <button onclick={() => goto('/test-client')} class="bg-[var(--nya-surface)] border border-[var(--nya-border)] text-left transition-all hover:shadow-nya-hover" style="min-height: 100px; padding: 20px; border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card);">
    <div class="flex items-center gap-3 mb-3">
      <div class="flex items-center justify-center rounded-full" style="width: 40px; height: 40px; background: var(--nya-mint-soft);">
        <KeyRound size={20} style="color: var(--nya-mint);" />
      </div>
      <span style="font-size: 13px; color: var(--nya-text-tertiary);">OAuth 测试</span>
    </div>
    <p style="font-size: 14px; color: var(--nya-text-secondary);">测试 OAuth 授权流程</p>
  </button>
</div>
