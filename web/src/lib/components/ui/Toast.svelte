<script lang="ts">
  import { CheckCircle, AlertCircle, AlertTriangle, Info, X } from 'lucide-svelte';

  let toasts = $state<Array<{ id: number; type: string; message: string }>>([]);
  let counter = 0;

  export function addToast(type: string, message: string, duration = 4000) {
    const id = ++counter;
    toasts = [...toasts, { id, type, message }];
    if (duration > 0) {
      setTimeout(() => removeToast(id), duration);
    }
  }

  function removeToast(id: number) {
    toasts = toasts.filter((t) => t.id !== id);
  }

  const icons: Record<string, typeof CheckCircle> = {
    success: CheckCircle,
    error: AlertCircle,
    warning: AlertTriangle,
    info: Info,
  };

  const colors: Record<string, string> = {
    success: 'border-nya-success text-nya-success',
    error: 'border-nya-danger text-nya-danger',
    warning: 'border-nya-warning text-nya-warning',
    info: 'border-nya-info text-nya-info',
  };
</script>

<div class="fixed right-4 top-4 z-[100] flex flex-col gap-2" aria-live="polite" aria-atomic="false">
  {#each toasts as toast (toast.id)}
    <div class="flex items-center gap-3 pl-4 pr-3 py-3 bg-nya-surface border-l-4 rounded-nya-sm shadow-nya-md animate-toast {colors[toast.type]}">
      {#if icons[toast.type]}
        {@const Icon = icons[toast.type]}
        <Icon size={18} />
      {/if}
      <span class="text-body text-nya-text-primary flex-1">{toast.message}</span>
      <button onclick={() => removeToast(toast.id)} class="rounded-nya-xs p-1 hover:bg-nya-surface-muted" aria-label="关闭通知">
        <X size={14} class="text-nya-text-tertiary" />
      </button>
    </div>
  {/each}
</div>

<style>
  .animate-toast {
    animation: toastIn var(--nya-duration-normal) var(--nya-ease-emphasized);
  }
  @keyframes toastIn {
    from { opacity: 0; transform: translateX(100%); }
    to { opacity: 1; transform: translateX(0); }
  }
</style>
