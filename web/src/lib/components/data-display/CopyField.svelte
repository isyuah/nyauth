<script lang="ts">
  import CopyButton from '$lib/components/ui/CopyButton.svelte';

  let {
    value = '',
    label = '',
    mono = true,
  }: {
    value: string;
    label?: string;
    mono?: boolean;
  } = $props();

</script>

<div class="flex flex-col gap-1">
  {#if label}
    <span class="text-small text-nya-text-tertiary">{label}</span>
  {/if}
  <div class="flex items-center gap-2 group">
    <code class="flex-1 px-2.5 py-1.5 bg-nya-surface-soft border border-nya-border rounded-nya-xs {mono ? 'font-mono text-small' : 'text-body'} text-nya-text-primary truncate">
      {value}
    </code>
    <CopyButton {value} />
  </div>
</div>
