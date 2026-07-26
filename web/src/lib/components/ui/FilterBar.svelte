<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    label = '筛选条件',
    children,
    actions,
  }: {
    label?: string;
    children: Snippet;
    actions?: Snippet;
  } = $props();
</script>

<section class="mb-4 border-y border-nya-border bg-nya-surface-muted/40 py-4" aria-label={label}>
  <div class="flex flex-col gap-3 xl:flex-row xl:items-end">
    <div class="min-w-0 flex-1">{@render children()}</div>
    {#if actions}<div class="flex shrink-0 items-center gap-2">{@render actions()}</div>{/if}
  </div>
</section>
