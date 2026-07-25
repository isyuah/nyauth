<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    title = '暂无数据',
    description = '',
    icon,
    action,
  }: {
    title?: string;
    description?: string;
    icon?: Snippet;
    action?: Snippet;
  } = $props();
</script>

<div class="flex flex-col items-center justify-center py-16 px-4 text-center">
  {#if icon}
    <div class="mb-4 text-nya-text-disabled">
      {@render icon()}
    </div>
  {/if}
  <h3 class="text-card-title text-nya-text-primary mb-1">{title}</h3>
  {#if description}
    <p class="text-body text-nya-text-secondary max-w-sm mb-4">{description}</p>
  {/if}
  {#if action}
    {@render action()}
  {/if}
</div>
