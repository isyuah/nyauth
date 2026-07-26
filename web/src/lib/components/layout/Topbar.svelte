<script lang="ts">
  import { sessionStore } from '$lib/stores';
  import { Menu, PanelLeft, PanelLeftClose } from 'lucide-svelte';

  let {
    collapsed = $bindable(false),
    isMobile = false,
    mobileMenuOpen = false,
    section = 'user',
    onMenuClick = () => {},
  }: {
    collapsed?: boolean;
    isMobile?: boolean;
    mobileMenuOpen?: boolean;
    section?: 'admin' | 'user';
    onMenuClick?: () => void;
  } = $props();

  let user = $derived($sessionStore.session?.user ?? null);
  let initials = $derived((user?.display_name || user?.username || '?').slice(0, 1).toUpperCase());
</script>

<header class="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-nya-divider bg-white/95 px-4 backdrop-blur-[10px] md:px-5">
  <div class="flex items-center gap-3">
    {#if isMobile}
      <button
        type="button"
        onclick={onMenuClick}
        class="flex h-9 w-9 items-center justify-center rounded-nya-md text-nya-text-tertiary hover:bg-nya-surface-muted hover:text-nya-text-primary"
        aria-label={mobileMenuOpen ? '关闭导航菜单' : '打开导航菜单'}
        aria-expanded={mobileMenuOpen}
        aria-controls="mobile-navigation"
      >
        <Menu size={20} />
      </button>
    {:else}
      <button type="button" onclick={() => (collapsed = !collapsed)} class="flex h-9 w-9 items-center justify-center rounded-nya-md text-nya-text-tertiary hover:bg-nya-surface-muted hover:text-nya-text-primary" aria-label={collapsed ? '展开侧边栏' : '收起侧边栏'}>
        {#if collapsed}<PanelLeft size={18} />{:else}<PanelLeftClose size={18} />{/if}
      </button>
    {/if}
    <span class="text-body-medium text-nya-text-secondary">{section === 'admin' ? '管理后台' : '用户中心'}</span>
  </div>

  <a href="/profile" class="flex items-center gap-2 rounded-nya-md px-1.5 py-1 hover:bg-nya-surface-muted" aria-label="打开个人资料">
    <span class="hidden max-w-48 truncate text-body-medium text-nya-text-secondary sm:block">{user?.display_name || user?.username || '当前用户'}</span>
    <span class="flex h-8 w-8 items-center justify-center overflow-hidden rounded-full bg-nya-primary-soft text-small font-semibold text-nya-primary">
      {#if user?.avatar_url}<img src={user.avatar_url} alt="" class="h-full w-full object-cover" />{:else}{initials}{/if}
    </span>
  </a>
</header>
