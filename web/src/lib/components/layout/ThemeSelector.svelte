<script lang="ts">
  import type { Theme } from '$lib/api';
  import { localThemeStore } from '$lib/stores';
  import { Monitor, Moon, Sun } from 'lucide-svelte';

  const options: Array<{ value: Theme; label: string; icon: typeof Monitor }> = [
    { value: 'system', label: '自动主题', icon: Monitor },
    { value: 'light', label: '浅色主题', icon: Sun },
    { value: 'dark', label: '深色主题', icon: Moon },
  ];
</script>

<div class="inline-grid h-9 grid-cols-3 items-center rounded-nya-md border border-nya-border bg-nya-surface-muted p-0.5" role="group" aria-label="界面主题">
  {#each options as option}
    {@const Icon = option.icon}
    <button
      type="button"
      class="flex h-8 w-8 items-center justify-center rounded-nya-sm text-nya-text-tertiary transition-colors duration-fast hover:text-nya-text-primary aria-pressed:bg-nya-surface aria-pressed:text-nya-primary aria-pressed:shadow-sm"
      aria-label={option.label}
      aria-pressed={$localThemeStore === option.value}
      title={option.label}
      onclick={() => localThemeStore.set(option.value)}
    >
      <Icon size={16} />
    </button>
  {/each}
</div>
