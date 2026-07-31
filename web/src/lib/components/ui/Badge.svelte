<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    variant = 'default',
    children,
  }: {
    variant?: 'default' | 'primary' | 'success' | 'warning' | 'danger' | 'info' | 'pink' | 'blue' | 'mint' | 'orange';
    children: Snippet;
  } = $props();

  const variants = {
    default: 'bg-nya-surface-soft text-nya-text-secondary',
    primary: 'bg-nya-primary-soft text-nya-primary',
    success: 'bg-nya-success-soft text-nya-success',
    warning: 'bg-nya-warning-soft text-nya-warning-strong',
    danger: 'bg-nya-danger-soft text-nya-danger',
    info: 'bg-nya-info-soft text-nya-info',
    pink: 'bg-nya-pink-soft text-nya-pink',
    blue: 'bg-nya-blue-soft text-nya-blue',
    mint: 'bg-nya-mint-soft text-nya-mint',
    orange: 'bg-nya-orange-soft text-nya-orange',
  };
</script>

<span class="inline-flex items-center h-5 px-2 rounded-nya-full text-micro font-medium {variants[variant]}">
  {@render children()}
</span>
