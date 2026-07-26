<script lang="ts">
  import type { Component } from 'svelte';

  let {
    title = '',
    value = '0',
    icon: Icon,
    color = 'primary',
    trend = '',
    trendUp = false,
  }: {
    title: string;
    value: string;
    icon?: Component<{ size?: number | string }>;
    color?: 'primary' | 'pink' | 'blue' | 'mint' | 'orange';
    trend?: string;
    trendUp?: boolean;
  } = $props();

  const bgColors = {
    primary: 'bg-nya-primary-soft text-nya-primary',
    pink: 'bg-nya-pink-soft text-nya-pink',
    blue: 'bg-nya-blue-soft text-nya-blue',
    mint: 'bg-nya-mint-soft text-nya-mint',
    orange: 'bg-nya-orange-soft text-nya-orange',
  };
</script>

<div class="bg-nya-surface border border-nya-border rounded-nya-md shadow-nya-xs p-5 flex items-center gap-4 h-[110px]">
  {#if Icon}
    <div class="flex items-center justify-center w-11 h-11 rounded-nya-md {bgColors[color]}">
      <Icon size={22} />
    </div>
  {/if}
  <div class="flex-1 min-w-0">
    <p class="text-small text-nya-text-tertiary mb-0.5">{title}</p>
    <p class="text-stat-value text-nya-text-primary tabular-nums">{value}</p>
    {#if trend}
      <p class="text-micro {trendUp ? 'text-nya-success' : 'text-nya-text-tertiary'}">{trend}</p>
    {/if}
  </div>
</div>
