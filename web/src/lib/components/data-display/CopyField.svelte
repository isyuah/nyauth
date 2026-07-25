<script lang="ts">
  import { Copy, Check } from 'lucide-svelte';

  let {
    value = '',
    label = '',
    mono = true,
  }: {
    value: string;
    label?: string;
    mono?: boolean;
  } = $props();

  let copied = $state(false);

  async function copy() {
    await navigator.clipboard.writeText(value);
    copied = true;
    setTimeout(() => (copied = false), 2000);
  }
</script>

<div class="flex flex-col gap-1">
  {#if label}
    <span class="text-small text-nya-text-tertiary">{label}</span>
  {/if}
  <div class="flex items-center gap-2 group">
    <code class="flex-1 px-2.5 py-1.5 bg-nya-surface-soft border border-nya-border rounded-nya-xs {mono ? 'font-mono text-small' : 'text-body'} text-nya-text-primary truncate">
      {value}
    </code>
    <button
      onclick={copy}
      class="p-1.5 rounded-nya-xs text-nya-text-tertiary hover:text-nya-primary hover:bg-nya-primary-soft transition-colors duration-fast"
      title="复制"
    >
      {#if copied}
        <Check size={14} class="text-nya-success" />
      {:else}
        <Copy size={14} />
      {/if}
    </button>
  </div>
</div>
