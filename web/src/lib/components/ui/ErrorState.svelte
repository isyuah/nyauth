<script lang="ts">
  import { AlertCircle, RefreshCw } from 'lucide-svelte';
  import Button from './Button.svelte';

  let {
    title = '加载失败',
    message,
    onretry,
  }: {
    title?: string;
    message: string;
    onretry?: () => void | Promise<void>;
  } = $props();
</script>

<div class="flex min-h-48 flex-col items-center justify-center border-y border-nya-danger/20 bg-nya-surface px-6 py-10 text-center" role="alert">
  <AlertCircle size={28} class="mb-3 text-nya-danger" />
  <h2 class="text-card-title text-nya-text-primary">{title}</h2>
  <p class="mt-1 max-w-lg text-body text-nya-text-secondary">{message}</p>
  {#if onretry}
    <div class="mt-4">
      <Button variant="secondary" onclick={() => onretry?.()}><RefreshCw size={15} /> 重试</Button>
    </div>
  {/if}
</div>
