<script lang="ts">
  import type { Snippet } from 'svelte';
  import { X } from 'lucide-svelte';
  import { scale, fade } from 'svelte/transition';

  let {
    open = $bindable(false),
    size = 'md',
    title = '',
    children,
  }: {
    open?: boolean;
    size?: 'sm' | 'md' | 'lg';
    title?: string;
    children: Snippet;
  } = $props();

  const widths = { sm: '420px', md: '560px', lg: '720px' };
</script>

{#if open}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div class="fixed inset-0 z-50 flex items-center justify-center p-4" onclick={() => (open = false)}>
    <div class="fixed inset-0 bg-black/30" transition:fade={{ duration: 150 }} style="backdrop-filter: blur(2px);"></div>
    <div
      class="relative w-full bg-[var(--nya-surface)] overflow-hidden"
      style="max-width: {widths[size]}; border-radius: var(--nya-radius-lg); box-shadow: var(--nya-shadow-popup);"
      transition:scale={{ start: 0.95, duration: 200, easing: (t) => t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2 }}
      onclick={(e) => e.stopPropagation()}
    >
      {#if title}
        <div class="flex items-center justify-between px-6 py-4 border-b border-[var(--nya-divider)]">
          <h3 style="font-size: 16px; font-weight: 650; color: var(--nya-text-primary);">{title}</h3>
          <button onclick={() => (open = false)} class="p-1.5 rounded-lg hover:bg-[var(--nya-surface-muted)] text-[var(--nya-text-tertiary)] transition-colors">
            <X size={18} />
          </button>
        </div>
      {/if}
      <div style="padding: 20px 24px;">
        {@render children()}
      </div>
    </div>
  </div>
{/if}
