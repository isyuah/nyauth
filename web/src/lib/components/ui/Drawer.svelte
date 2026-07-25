<script lang="ts">
  import type { Snippet } from 'svelte';
  import { X } from 'lucide-svelte';
  import { fly } from 'svelte/transition';

  let {
    open = $bindable(false),
    title = '',
    width = '480px',
    children,
  }: {
    open?: boolean;
    title?: string;
    width?: string;
    children: Snippet;
  } = $props();

  let canClose = $state(false);

  // Prevent immediate close from the same click that opened the drawer
  $effect(() => {
    if (open) {
      canClose = false;
      const timer = setTimeout(() => (canClose = true), 50);
      return () => clearTimeout(timer);
    }
  });

  function close() {
    if (canClose) open = false;
  }
</script>

{#if open}
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div class="fixed inset-0 z-50 flex justify-end" onclick={close}>
    <div class="fixed inset-0 bg-black/30" style="backdrop-filter: blur(2px);"></div>
    <div
      class="relative h-full bg-[var(--nya-surface)] overflow-y-auto"
      style="width: min({width}, 85vw); box-shadow: var(--nya-shadow-popup);"
      transition:fly={{ x: 400, duration: 250, easing: (t: number) => t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2 }}
      onclick={(e) => e.stopPropagation()}
    >
      {#if title}
        <div class="sticky top-0 z-10 flex items-center justify-between px-6 py-4 border-b border-[var(--nya-divider)] bg-[var(--nya-surface)]">
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
