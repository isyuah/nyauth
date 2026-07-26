<script lang="ts">
  import type { Snippet } from 'svelte';
  import { Dialog } from 'bits-ui';
  import Sidebar from './Sidebar.svelte';
  import Topbar from './Topbar.svelte';

  let {
    section = 'user',
    children,
  }: {
    section?: 'admin' | 'user';
    children: Snippet;
  } = $props();

  let sidebarCollapsed = $state(false);
  let mobileMenuOpen = $state(false);
  let isMobile = $state(false);

  function checkViewport() {
    isMobile = window.innerWidth < 768;
    // sidebarCollapsed is the user's desktop preference; the mobile layout
    // uses the drawer instead, so viewport changes must not overwrite it.
    if (!isMobile) mobileMenuOpen = false;
  }

  $effect(() => {
    if (typeof window === 'undefined') return;
    checkViewport();
    window.addEventListener('resize', checkViewport);
    return () => window.removeEventListener('resize', checkViewport);
  });
</script>

<div class="min-h-screen bg-nya-bg text-nya-text-primary">
  {#if isMobile}
    <Dialog.Root bind:open={mobileMenuOpen}>
      <Dialog.Portal>
        <Dialog.Overlay class="fixed inset-0 z-40 bg-black/30" />
        <Dialog.Content id="mobile-navigation" class="fixed inset-y-0 left-0 z-50 w-[248px] outline-none">
          <Dialog.Title class="sr-only">{section === 'admin' ? '管理后台导航' : '用户中心导航'}</Dialog.Title>
          <Sidebar
            {section}
            collapsed={false}
            mobile={true}
            mobileOpen={true}
            onNavigate={() => (mobileMenuOpen = false)}
          />
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  {:else}
    <Sidebar
      {section}
      collapsed={sidebarCollapsed}
      mobile={false}
      mobileOpen={false}
    />
  {/if}

  <div
    class="min-h-screen transition-[margin] duration-300"
    style="margin-left: {isMobile ? '0' : (sidebarCollapsed ? '72px' : '248px')};"
  >
    <Topbar
      bind:collapsed={sidebarCollapsed}
      {isMobile}
      {mobileMenuOpen}
      {section}
      onMenuClick={() => (mobileMenuOpen = !mobileMenuOpen)}
    />
    <main class="px-4 py-5 md:px-7 md:pb-8">
      {@render children()}
    </main>
  </div>
</div>
