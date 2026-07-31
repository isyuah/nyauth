<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { api } from '$lib/api';
  import { brandingStore, sessionStore } from '$lib/stores';
  import {
    AppWindow,
    FlaskConical,
    Gauge,
    KeyRound,
    LayoutDashboard,
    LogOut,
    ScrollText,
    Server,
    Settings,
    ShieldCheck,
    Ticket,
    UserRound,
    Users,
  } from 'lucide-svelte';

  let {
    section = 'user',
    collapsed = false,
    mobile = false,
    mobileOpen = false,
    onNavigate = () => {},
  }: {
    section?: 'admin' | 'user';
    collapsed?: boolean;
    mobile?: boolean;
    mobileOpen?: boolean;
    onNavigate?: () => void;
  } = $props();

  const adminItems = [
    { href: '/admin', icon: LayoutDashboard, label: '仪表盘' },
    { href: '/admin/users', icon: Users, label: '用户管理' },
    { href: '/admin/clients', icon: AppWindow, label: '应用管理' },
    { href: '/admin/oauth/test', icon: FlaskConical, label: 'OAuth 测试' },
    { href: '/admin/providers', icon: KeyRound, label: '身份提供者' },
    { href: '/admin/invites', icon: Ticket, label: '邀请管理' },
    { href: '/admin/audit', icon: ScrollText, label: '审计日志' },
    { href: '/admin/settings/branding', activePrefix: '/admin/settings', icon: Settings, label: '系统设置' },
    { href: '/admin/system', icon: Server, label: '系统状态' },
  ];

  const userItems = [
    { href: '/dashboard', icon: Gauge, label: '概览' },
    { href: '/dashboard/apps', icon: AppWindow, label: '我的应用' },
    { href: '/profile', icon: UserRound, label: '个人资料' },
  ];

  let visible = $derived(mobile ? mobileOpen : true);
  let width = $derived(mobile ? '248px' : (collapsed ? '72px' : '248px'));
  let showLabels = $derived(mobile || !collapsed);
  let navItems = $derived(section === 'admin' ? adminItems : userItems);
  let user = $derived($sessionStore.session?.user ?? null);
  let initials = $derived((user?.display_name || user?.username || '?').slice(0, 1).toUpperCase());

  function isActive(item: { href: string; activePrefix?: string }): boolean {
    const href = item.activePrefix || item.href;
    return $page.url.pathname === item.href || $page.url.pathname === href || (href !== '/admin' && href !== '/dashboard' && $page.url.pathname.startsWith(`${href}/`));
  }

  async function handleLogout() {
    try {
      await api.logout();
    } finally {
      sessionStore.clear();
      await goto('/login');
    }
  }
</script>

{#if visible}
  <aside
    class="fixed bottom-0 left-0 z-50 flex flex-col border-r border-nya-border bg-[var(--nya-bg-sidebar)] transition-[width] duration-300"
    class:shadow-nya-popup={mobile}
    style="top: {mobile ? '0' : 'var(--nya-global-banner-height, 0px)'}; width: {width};"
    aria-label={section === 'admin' ? '管理后台导航' : '用户中心导航'}
  >
    <a href={section === 'admin' ? '/admin' : '/dashboard'} onclick={onNavigate} class="flex h-[132px] shrink-0 flex-col items-center justify-center overflow-hidden bg-gradient-to-br from-[#f8f5ff] to-[#fff0f6] px-5">
      {#if showLabels}
        <span class="flex items-center gap-2">
          <img src={$brandingStore.logo_url || '/logo.png'} alt="" class="h-11 w-11 select-none" draggable="false" />
          <span class="select-none bg-gradient-to-br from-[#8A6CFF] via-[#C28BFF] to-[#FF9BCB] bg-clip-text text-[30px] font-bold leading-none text-transparent">{$brandingStore.title}</span>
        </span>
        <span class="mt-2 text-small text-nya-text-tertiary">{section === 'admin' ? '管理后台' : '用户中心'}</span>
      {:else}
        <img src={$brandingStore.logo_url || '/logo.png'} alt={$brandingStore.title} class="h-9 w-9 select-none" draggable="false" />
      {/if}
    </a>

    <nav class="flex-1 overflow-y-auto px-3 py-3">
      {#each navItems as item}
        <a
          href={item.href}
          onclick={onNavigate}
          aria-current={isActive(item) ? 'page' : undefined}
          class="mb-0.5 flex h-11 items-center gap-3 rounded-nya-md px-3.5 text-left text-body-medium transition-colors {isActive(item) ? 'bg-nya-primary-soft text-nya-primary' : 'text-nya-text-secondary hover:bg-nya-surface-muted hover:text-nya-text-primary'}"
          title={!showLabels ? item.label : undefined}
        >
          <item.icon size={18} class="shrink-0" />
          {#if showLabels}<span>{item.label}</span>{/if}
        </a>
      {/each}

      {#if user?.role === 'admin'}
        <div class="my-2 border-t border-nya-divider"></div>
        <a
          href={section === 'admin' ? '/dashboard' : '/admin'}
          onclick={onNavigate}
          class="mb-0.5 flex h-11 items-center gap-3 rounded-nya-md px-3.5 text-body-medium text-nya-text-secondary transition-colors hover:bg-nya-surface-muted hover:text-nya-text-primary"
          title={!showLabels ? (section === 'admin' ? '用户中心' : '管理后台') : undefined}
        >
          <ShieldCheck size={18} class="shrink-0" />
          {#if showLabels}<span>{section === 'admin' ? '用户中心' : '管理后台'}</span>{/if}
        </a>
      {/if}

    </nav>

    <div class="shrink-0 p-3">
      {#if showLabels}
        <div class="flex min-h-[60px] items-center gap-2.5 rounded-nya-md border border-nya-border bg-nya-surface px-3.5">
          <a href="/profile" onclick={onNavigate} class="flex h-9 w-9 shrink-0 items-center justify-center overflow-hidden rounded-full bg-nya-primary-soft text-small font-semibold text-nya-primary" aria-label="打开个人资料">
            {#if user?.avatar_url}<img src={user.avatar_url} alt="" class="h-full w-full object-cover" />{:else}{initials}{/if}
          </a>
          <a href="/profile" onclick={onNavigate} class="min-w-0 flex-1 text-left">
            <p class="truncate text-body-medium font-semibold text-nya-text-primary">{user?.display_name || user?.username || '当前用户'}</p>
            <p class="text-small text-nya-text-tertiary">{user?.role === 'admin' ? '管理员' : '用户'}</p>
          </a>
          <button type="button" onclick={handleLogout} class="shrink-0 rounded-lg p-1.5 text-nya-text-tertiary hover:bg-nya-danger-soft hover:text-nya-danger" aria-label="退出登录" title="退出登录">
            <LogOut size={16} />
          </button>
        </div>
      {:else}
        <button type="button" onclick={handleLogout} class="flex w-full items-center justify-center rounded-lg p-2 text-nya-text-tertiary hover:bg-nya-danger-soft hover:text-nya-danger" aria-label="退出登录" title="退出登录">
          <LogOut size={16} />
        </button>
      {/if}
    </div>
  </aside>
{/if}
