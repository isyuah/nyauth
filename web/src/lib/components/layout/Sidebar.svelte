<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { api } from '$lib/api';
  import { sessionStore } from '$lib/stores';
  import { LayoutDashboard, Users, AppWindow, KeyRound, LogOut, FlaskConical } from 'lucide-svelte';

  let {
    collapsed = false,
    mobile = false,
    mobileOpen = false,
    onNavigate = () => {},
  }: {
    collapsed?: boolean;
    mobile?: boolean;
    mobileOpen?: boolean;
    onNavigate?: () => void;
  } = $props();

  const navItems = [
    { href: '/admin', icon: LayoutDashboard, label: '仪表盘' },
    { href: '/admin/users', icon: Users, label: '用户管理' },
    { href: '/admin/clients', icon: AppWindow, label: '应用管理' },
    { href: '/admin/providers', icon: KeyRound, label: '身份提供者' },
  ];

  async function handleLogout() {
    try { await api.logout(); } finally { sessionStore.clear(); goto('/login'); }
  }

  function nav(href: string) {
    goto(href);
    onNavigate();
  }

  // Compute sidebar visibility
  let visible = $derived(mobile ? mobileOpen : true);
  let width = $derived(mobile ? '248px' : (collapsed ? '72px' : '248px'));
  let showLabels = $derived(mobile ? true : !collapsed);
</script>

{#if visible}
  <aside
    class="fixed inset-y-0 left-0 flex flex-col bg-[var(--nya-bg-sidebar)] border-r border-[var(--nya-border)] z-50 transition-all duration-300"
    class:shadow-nya-popup={mobile}
    style="width: {width};"
  >
    <!-- 品牌区 §2.2: 168px -->
    <div class="flex flex-col items-center justify-center overflow-hidden shrink-0" style="height: 168px; padding: 22px 20px 14px; background: linear-gradient(135deg, #f8f5ff 0%, #fff0f6 100%);">
      <span class="select-none" style="font-size: 36px; line-height: 1; font-weight: 750; background: linear-gradient(135deg, #8A6CFF 0%, #C28BFF 52%, #FF9BCB 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
        Nya
      </span>
      {#if showLabels}
        <svg class="mt-2" width="112" height="70" viewBox="0 0 112 70" fill="none">
          <path d="M28 42 L38 12 L48 38" stroke="#8b6cff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" opacity="0.7" fill="#f1edff"/>
          <path d="M64 38 L74 12 L84 42" stroke="#8b6cff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" opacity="0.7" fill="#f1edff"/>
          <ellipse cx="56" cy="46" rx="28" ry="22" fill="#f8f5ff" stroke="#8b6cff" stroke-width="2" opacity="0.6"/>
          <circle cx="46" cy="44" r="3" fill="#8b6cff" opacity="0.7"/>
          <circle cx="66" cy="44" r="3" fill="#8b6cff" opacity="0.7"/>
          <path d="M53 50 Q56 54 59 50" stroke="#8b6cff" stroke-width="1.5" stroke-linecap="round" fill="none" opacity="0.5"/>
          <circle cx="18" cy="28" r="2" fill="#c28bff" opacity="0.5"/>
          <circle cx="94" cy="22" r="1.5" fill="#ff9bcb" opacity="0.5"/>
          <circle cx="56" cy="8" r="1.5" fill="#c28bff" opacity="0.4"/>
        </svg>
      {/if}
    </div>

    <!-- 导航 -->
    <nav class="flex-1 py-2 overflow-y-auto" style="padding: 8px 12px;">
      {#each navItems as item}
        {@const isExact = $page.url.pathname === item.href}
        {@const isPrefix = item.href !== '/admin' && $page.url.pathname.startsWith(item.href)}
        {@const active = isExact || isPrefix}
        <button
          onclick={() => nav(item.href)}
          class="w-full flex items-center mb-0.5 transition-all duration-150 text-left"
          style="height: 44px; padding: 0 14px; border-radius: 10px; gap: 12px; font-size: 14px; font-weight: {active ? 600 : 500}; color: {active ? 'var(--nya-primary)' : 'var(--nya-text-secondary)'}; background: {active ? 'var(--nya-primary-soft)' : 'transparent'};"
        >
          <item.icon size={18} class="shrink-0" />
          {#if showLabels}
            <span>{item.label}</span>
          {/if}
        </button>
      {/each}

      <!-- 测试客户端入口 -->
      <button
        onclick={() => nav('/test-client')}
        class="w-full flex items-center mb-0.5 transition-all duration-150 text-left"
        style="height: 44px; padding: 0 14px; border-radius: 10px; gap: 12px; font-size: 14px; font-weight: 500; color: var(--nya-text-tertiary);"
      >
        <FlaskConical size={18} class="shrink-0" />
        {#if showLabels}
          <span>OAuth 测试</span>
        {/if}
      </button>
    </nav>

    <!-- 管理员卡片 -->
    <div class="shrink-0" style="padding: 12px;">
      {#if showLabels}
        <div class="flex items-center bg-[var(--nya-surface)] border border-[var(--nya-border)]" style="height: 60px; padding: 0 14px; border-radius: var(--nya-radius-md); gap: 10px;">
          <button onclick={() => nav('/profile')} class="shrink-0 flex items-center justify-center rounded-full bg-[var(--nya-primary-soft)] hover:ring-2 hover:ring-[var(--nya-primary-border)] transition-all" style="width: 34px; height: 34px;">
            <span style="font-size: 13px; font-weight: 600; color: var(--nya-primary);">A</span>
          </button>
          <button onclick={() => nav('/profile')} class="flex-1 min-w-0 text-left hover:opacity-80 transition-opacity">
            <p style="font-size: 14px; font-weight: 600; color: var(--nya-text-primary);">Nya Admin</p>
            <p style="font-size: 12px; color: var(--nya-text-tertiary);">超级管理员</p>
          </button>
          <button onclick={handleLogout} class="shrink-0 p-1.5 rounded-lg text-[var(--nya-text-tertiary)] hover:bg-[var(--nya-danger-soft)] hover:text-[var(--nya-danger)]" title="退出">
            <LogOut size={16} />
          </button>
        </div>
      {:else}
        <button onclick={handleLogout} class="w-full flex items-center justify-center p-2 rounded-lg text-[var(--nya-text-tertiary)] hover:bg-[var(--nya-danger-soft)] hover:text-[var(--nya-danger)]" title="退出登录">
          <LogOut size={16} />
        </button>
      {/if}
    </div>
  </aside>
{/if}
