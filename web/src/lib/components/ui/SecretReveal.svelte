<script lang="ts">
  import { Check, Copy, Eye, EyeOff } from 'lucide-svelte';

  let {
    value,
    label = 'Secret',
  }: {
    value: string;
    label?: string;
  } = $props();

  let revealed = $state(false);
  let copied = $state(false);
  let copyError = $state('');

  async function copy() {
    copyError = '';
    try {
      await navigator.clipboard.writeText(value);
      copied = true;
      setTimeout(() => (copied = false), 2000);
    } catch {
      copyError = '复制失败，请显示后手动复制。';
    }
  }
</script>

<div class="space-y-1.5">
  <span class="text-small text-nya-text-tertiary">{label}</span>
  <div class="flex items-center gap-2">
    <code class="min-w-0 flex-1 truncate rounded-nya-xs border border-nya-border bg-nya-surface px-2.5 py-2 font-mono text-small text-nya-text-primary" aria-label={revealed ? label : `${label} 已隐藏`}>
      {revealed ? value : '••••••••••••••••••••••••'}
    </code>
    <button type="button" onclick={() => (revealed = !revealed)} class="rounded-nya-xs p-2 text-nya-text-tertiary hover:bg-nya-surface-muted hover:text-nya-primary" aria-label={revealed ? `隐藏${label}` : `显示${label}`} title={revealed ? '隐藏' : '显示'}>{#if revealed}<EyeOff size={15} />{:else}<Eye size={15} />{/if}</button>
    <button type="button" onclick={copy} class="rounded-nya-xs p-2 text-nya-text-tertiary hover:bg-nya-surface-muted hover:text-nya-primary" aria-label={`复制${label}`} title="复制">{#if copied}<Check size={15} class="text-nya-success" />{:else}<Copy size={15} />{/if}</button>
  </div>
  {#if copyError}<p class="text-small text-nya-danger" role="alert">{copyError}</p>{/if}
</div>
