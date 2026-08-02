<script lang="ts">
  import { brandingStore, resolvedThemeStore } from '$lib/stores';
  import type { ResolvedTheme } from '$lib/api';
  import { logoForTheme } from '$lib/theme';

  let {
    size = 44,
    showName = false,
    compact = false,
    imageClass = '',
    textClass = 'text-nya-primary',
    theme,
  }: {
    size?: number;
    showName?: boolean;
    compact?: boolean;
    imageClass?: string;
    textClass?: string;
    theme?: ResolvedTheme;
  } = $props();

  let logoURL = $derived(logoForTheme($brandingStore, theme ?? $resolvedThemeStore));
</script>

<span class="inline-flex min-w-0 items-center gap-2.5">
  <img
    src={logoURL}
    alt={showName ? '' : $brandingStore.title}
    class="shrink-0 select-none object-contain {imageClass}"
    style="width: {size}px; height: {size}px;"
    draggable="false"
  />
  {#if showName}
    <span class="truncate font-bold leading-none {textClass} {compact ? 'text-xl' : 'text-[30px]'}">{$brandingStore.title}</span>
  {/if}
</span>
