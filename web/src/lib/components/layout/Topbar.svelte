<script lang="ts">
  import { Sun, Moon, PanelLeftClose, PanelLeft, Bell, Menu } from 'lucide-svelte';

  let {
    collapsed = $bindable(false),
    isMobile = false,
    onMenuClick = () => {},
  }: {
    collapsed?: boolean;
    isMobile?: boolean;
    onMenuClick?: () => void;
  } = $props();
  let theme = $state<'light' | 'dark'>('light');

  function toggleTheme() {
    theme = theme === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', theme === 'dark' ? 'dark' : '');
  }
</script>

<header
  class="sticky top-0 z-20 flex items-center justify-between bg-white/94 backdrop-blur-[10px] border-b border-[var(--nya-divider)]"
  style="height: 64px; padding: 0 {isMobile ? '16px' : '20px'};"
>
  {#if isMobile}
    <button
      onclick={onMenuClick}
      class="flex items-center justify-center text-[var(--nya-text-tertiary)] hover:text-[var(--nya-text-primary)]"
      style="width: 36px; height: 36px; border-radius: 10px;"
    >
      <Menu size={20} />
    </button>
  {:else}
    <button
      onclick={() => (collapsed = !collapsed)}
      class="flex items-center justify-center text-[var(--nya-text-tertiary)] hover:text-[var(--nya-text-primary)] hover:bg-[var(--nya-surface-muted)] transition-colors"
      style="width: 36px; height: 36px; border-radius: 10px;"
    >
      {#if collapsed}<PanelLeft size={18} />{:else}<PanelLeftClose size={18} />{/if}
    </button>
  {/if}

  <div class="flex items-center gap-1">
    <button onclick={toggleTheme} class="flex items-center justify-center text-[var(--nya-text-tertiary)] hover:text-[var(--nya-text-primary)]" style="width: 36px; height: 36px; border-radius: 10px;">
      {#if theme === 'light'}<Moon size={18} />{:else}<Sun size={18} />{/if}
    </button>
    <button class="relative flex items-center justify-center text-[var(--nya-text-tertiary)]" style="width: 36px; height: 36px; border-radius: 10px;">
      <Bell size={18} />
    </button>
    <button onclick={() => window.location.href = '/profile'} class="ml-2 flex items-center justify-center rounded-full bg-[var(--nya-primary-soft)] hover:ring-2 hover:ring-[var(--nya-primary-border)] transition-all" style="width: 32px; height: 32px; font-size: 13px; font-weight: 600; color: var(--nya-primary);">A</button>
  </div>
</header>
