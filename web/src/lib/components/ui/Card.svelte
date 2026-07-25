<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    padding = true,
    hover = false,
    children,
  }: {
    padding?: boolean;
    hover?: boolean;
    children: Snippet;
  } = $props();
</script>

<div
  class="bg-nya-surface border border-nya-border rounded-nya-md shadow-nya-xs transition-all duration-fast
    {padding ? 'p-5' : ''}
    {hover ? 'hover:shadow-nya-sm hover:bg-nya-surface-hover cursor-pointer' : ''}"
>
  {@render children()}
</div>
