<script lang="ts">
  import { Check, Copy, X } from 'lucide-svelte';

  let {
    value,
    label = '复制到剪贴板',
  }: {
    value: string;
    label?: string;
  } = $props();

  let state = $state<'idle' | 'copied' | 'failed'>('idle');
  let resetTimer: ReturnType<typeof setTimeout> | undefined;

  async function copy() {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      state = 'copied';
    } catch {
      state = 'failed';
    }
    if (resetTimer) clearTimeout(resetTimer);
    resetTimer = setTimeout(() => (state = 'idle'), 2000);
  }
</script>

<button
  type="button"
  onclick={copy}
  disabled={!value}
  class="flex h-8 w-8 shrink-0 items-center justify-center rounded-nya-xs text-nya-text-tertiary transition-colors duration-fast hover:bg-nya-primary-soft hover:text-nya-primary disabled:cursor-not-allowed disabled:opacity-40"
  aria-label={state === 'copied' ? '已复制' : state === 'failed' ? '复制失败' : label}
  title={state === 'copied' ? '已复制' : state === 'failed' ? '复制失败' : label}
>
  {#if state === 'copied'}
    <Check size={14} class="text-nya-success" />
  {:else if state === 'failed'}
    <X size={14} class="text-nya-danger" />
  {:else}
    <Copy size={14} />
  {/if}
</button>
<span class="sr-only" aria-live="polite">{state === 'copied' ? '已复制到剪贴板' : state === 'failed' ? '复制失败' : ''}</span>
