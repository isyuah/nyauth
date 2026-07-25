<script lang="ts">
  import Sidebar from './Sidebar.svelte';
  import Topbar from './Topbar.svelte';
  import type { Snippet } from 'svelte';

  let { children }: { children: Snippet } = $props();
  let sidebarCollapsed = $state(false);
  let mobileMenuOpen = $state(false);
  let isMobile = $state(false);

  // Detect mobile on mount and resize
  function checkMobile() {
    isMobile = typeof window !== 'undefined' && window.innerWidth < 768;
    if (isMobile) sidebarCollapsed = true;
  }

  $effect(() => {
    checkMobile();
    if (typeof window !== 'undefined') {
      window.addEventListener('resize', checkMobile);
      return () => window.removeEventListener('resize', checkMobile);
    }
  });

  function closeMobileMenu() {
    mobileMenuOpen = false;
  }
</script>

<div class="min-h-screen bg-[var(--nya-bg)] text-[var(--nya-text-primary)]">
  <!-- Mobile overlay -->
  {#if isMobile && mobileMenuOpen}
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div class="fixed inset-0 bg-black/30 z-40 md:hidden" onclick={closeMobileMenu}></div>
  {/if}

  <Sidebar
    collapsed={isMobile ? false : sidebarCollapsed}
    mobile={isMobile}
    mobileOpen={mobileMenuOpen}
    onNavigate={closeMobileMenu}
  />

  <div
    class="min-h-screen transition-all duration-300"
    style="margin-left: {isMobile ? '0' : (sidebarCollapsed ? '72px' : '248px')};"
  >
    <Topbar
      bind:collapsed={sidebarCollapsed}
      {isMobile}
      onMenuClick={() => (mobileMenuOpen = !mobileMenuOpen)}
    />

    <main style="padding: {isMobile ? '16px' : '20px 28px 32px'};">
      {@render children()}
    </main>
  </div>
</div>
