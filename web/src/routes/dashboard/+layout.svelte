<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { api } from '$lib/api';
  import { sessionStore } from '$lib/stores';
  import { LayoutDashboard, AppWindow, Settings, LogOut, User } from 'lucide-svelte';
  import Topbar from '$lib/components/layout/Topbar.svelte';
  import type { Snippet } from 'svelte';

  let { children }: { children: Snippet } = $props();
  let sidebarCollapsed = $state(false);
  let authorized = $state(false);
  let loading = $state(true);

  const navItems = [
    { href: '/dashboard', icon: LayoutDashboard, label: '概览' },
    { href: '/dashboard/apps', icon: AppWindow, label: '我的应用' },
    { href: '/dashboard/settings', icon: Settings, label: '设置' },
  ];

  function nav(href: string) { goto(href); }
  onMount(async () => {
    const session = await sessionStore.initialize();
    if (!session) goto(`/login?return_to=${encodeURIComponent($page.url.pathname + $page.url.search)}`);
    else if (session.must_change_password) goto('/change-password');
    else authorized = true;
    loading = false;
  });

  async function handleLogout() {
    try { await api.logout(); } finally { sessionStore.clear(); goto('/login'); }
  }
</script>

{#if loading}
  <div class="min-h-screen flex items-center justify-center bg-[var(--nya-bg)]">
    <div class="animate-spin rounded-full h-6 w-6 border-2 border-[var(--nya-primary)]/30 border-t-[var(--nya-primary)]"></div>
  </div>
{:else if authorized}
<div class="min-h-screen bg-[var(--nya-bg)]">
  <!-- Sidebar -->
  <aside class="fixed inset-y-0 left-0 flex flex-col bg-[var(--nya-bg-sidebar)] border-r border-[var(--nya-border)] z-30 transition-all duration-300" style="width: {sidebarCollapsed ? '72px' : '248px'};">
    <!-- Brand -->
    <div class="flex flex-col items-center justify-center shrink-0" style="height: 140px; background: linear-gradient(135deg, #f8f5ff 0%, #fff0f6 100%);">
      <span class="select-none" style="font-size: 32px; font-weight: 750; background: linear-gradient(135deg, #8A6CFF, #FF9BCB); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Nya</span>
      {#if !sidebarCollapsed}
        <span style="font-size: 12px; color: var(--nya-text-tertiary); margin-top: 4px;">用户中心</span>
      {/if}
    </div>

    <!-- Nav -->
    <nav class="flex-1 py-2 overflow-y-auto" style="padding: 8px 12px;">
      {#each navItems as item}
        {@const active = $page.url.pathname === item.href}
        <button onclick={() => nav(item.href)} class="w-full flex items-center mb-0.5 transition-all duration-150 text-left" style="height: 44px; padding: 0 14px; border-radius: 10px; gap: 12px; font-size: 14px; font-weight: {active ? 600 : 500}; color: {active ? 'var(--nya-primary)' : 'var(--nya-text-secondary)'}; background: {active ? 'var(--nya-primary-soft)' : 'transparent'};">
          <item.icon size={18} />
          {#if !sidebarCollapsed}<span>{item.label}</span>{/if}
        </button>
      {/each}
    </nav>

    <!-- User card -->
    <div class="shrink-0" style="padding: 12px;">
      {#if !sidebarCollapsed}
        <div class="flex items-center bg-[var(--nya-surface)] border border-[var(--nya-border)]" style="height: 56px; padding: 0 14px; border-radius: var(--nya-radius-md); gap: 10px;">
          <button onclick={() => nav('/profile')} class="shrink-0 flex items-center justify-center rounded-full bg-[var(--nya-primary-soft)]" style="width: 32px; height: 32px;">
            <User size={16} style="color: var(--nya-primary);" />
          </button>
          <button onclick={() => nav('/profile')} class="flex-1 min-w-0 text-left">
            <p style="font-size: 13px; font-weight: 600; color: var(--nya-text-primary);">个人资料</p>
          </button>
          <button onclick={handleLogout} class="shrink-0 p-1.5 rounded-lg text-[var(--nya-text-tertiary)] hover:bg-[var(--nya-danger-soft)] hover:text-[var(--nya-danger)]" title="退出">
            <LogOut size={15} />
          </button>
        </div>
      {:else}
        <button onclick={handleLogout} class="w-full flex items-center justify-center p-2 rounded-lg text-[var(--nya-text-tertiary)] hover:bg-[var(--nya-danger-soft)] hover:text-[var(--nya-danger)]" title="退出">
          <LogOut size={16} />
        </button>
      {/if}
    </div>
  </aside>

  <!-- Main -->
  <div class="min-h-screen transition-all duration-300" style="margin-left: {sidebarCollapsed ? '72px' : '248px'};">
    <Topbar bind:collapsed={sidebarCollapsed} />
    <main style="padding: 20px 28px 32px;">
      {@render children()}
    </main>
  </div>
</div>
{/if}
