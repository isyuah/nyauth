<script lang="ts">
  import type { Snippet } from 'svelte';
  import EmptyState from './EmptyState.svelte';
  import ErrorState from './ErrorState.svelte';
  import Skeleton from './Skeleton.svelte';

  let {
    loading = false,
    error = '',
    empty = false,
    emptyTitle = '暂无数据',
    emptyDescription = '',
    onretry,
    children,
    emptyAction,
  }: {
    loading?: boolean;
    error?: string;
    empty?: boolean;
    emptyTitle?: string;
    emptyDescription?: string;
    onretry?: () => void | Promise<void>;
    children: Snippet;
    emptyAction?: Snippet;
  } = $props();
</script>

{#if loading}
  <div class="rounded-nya-card border border-nya-border bg-nya-surface p-6" aria-busy="true" aria-label="正在加载">
    <Skeleton lines={5} />
  </div>
{:else if error}
  <ErrorState message={error} {onretry} />
{:else if empty}
  <EmptyState title={emptyTitle} description={emptyDescription} action={emptyAction} />
{:else}
  {@render children()}
{/if}
