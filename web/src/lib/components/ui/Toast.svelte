<script lang="ts">
  import { CheckCircle, AlertCircle, AlertTriangle, Info, X } from 'lucide-svelte';
  import { flip } from 'svelte/animate';
  import { cubicOut } from 'svelte/easing';
  import { fly } from 'svelte/transition';
  import { dismissToast, toastStore, type ToastType } from '$lib/toast';

  const icons: Record<string, typeof CheckCircle> = {
    success: CheckCircle,
    error: AlertCircle,
    warning: AlertTriangle,
    info: Info,
  };

  const colors: Record<ToastType, string> = {
    success: 'border-nya-success text-nya-success',
    error: 'border-nya-danger text-nya-danger',
    warning: 'border-nya-warning text-nya-warning',
    info: 'border-nya-info text-nya-info',
  };
</script>

{#if $toastStore.length > 0}
  <aside class="pointer-events-none fixed left-4 right-4 top-4 z-[100] flex flex-col items-end gap-2 sm:left-auto sm:w-[min(28rem,calc(100vw-2rem))]" aria-label="通知">
    {#each $toastStore as item (item.id)}
      <div
        class="toast-item pointer-events-auto flex w-full items-start gap-3 rounded-nya-sm border border-nya-border border-l-4 bg-nya-surface py-3 pl-4 pr-3 shadow-nya-md {colors[item.type]}"
        role={item.type === 'error' ? 'alert' : 'status'}
        aria-atomic="true"
        in:fly={{ x: 48, duration: 200, easing: cubicOut }}
        out:fly={{ x: 48, duration: 160, easing: cubicOut }}
        animate:flip={{ duration: 180, easing: cubicOut }}
      >
        {#if icons[item.type]}
          {@const Icon = icons[item.type]}
          <Icon size={18} />
        {/if}
        <span class="min-w-0 flex-1 text-body text-nya-text-primary">{item.message}</span>
        <button onclick={() => dismissToast(item.id)} class="shrink-0 rounded-nya-xs p-1 hover:bg-nya-surface-muted" aria-label="关闭通知">
          <X size={14} class="text-nya-text-tertiary" />
        </button>
      </div>
    {/each}
  </aside>
{/if}

<style>
  @media (prefers-reduced-motion: reduce) {
    .toast-item {
      transition-duration: 1ms !important;
      animation-duration: 1ms !important;
    }
  }
</style>
