<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    title = '',
    description = '',
    action,
  }: {
    title: string;
    description?: string;
    action?: Snippet;
  } = $props();
</script>

<div class="flex items-start justify-between" style="margin-bottom: 20px;">
  <div>
    <h1 style="font-size: 24px; line-height: 32px; font-weight: 700; color: var(--nya-text-primary); margin: 0;">{title}</h1>
    {#if description}
      <p style="font-size: 14px; line-height: 21px; color: var(--nya-text-secondary); margin-top: 4px;">{description}</p>
    {/if}
  </div>
  {#if action}
    <div class="flex items-center gap-2">
      {@render action()}
    </div>
  {/if}
</div>
