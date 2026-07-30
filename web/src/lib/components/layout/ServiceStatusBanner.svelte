<script lang="ts">
  import { serviceStatusStore } from '$lib/service-control';
  import { AlertTriangle, Clock3 } from 'lucide-svelte';

  let status = $derived($serviceStatusStore.value);
  let visible = $derived($serviceStatusStore.initialized && status.status !== 'normal');

  function formatExpiry(value: string | null): string {
    if (!value) return '恢复时间未设定';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : `预计 ${date.toLocaleString('zh-CN')} 自动恢复`;
  }
</script>

{#if visible}
  <aside class="flex min-h-11 items-center justify-center gap-3 border-b border-nya-warning/25 bg-nya-warning-soft px-4 py-2 text-small text-nya-warning" role="status" aria-live="polite">
    <AlertTriangle size={16} class="shrink-0" />
    <span class="min-w-0 font-semibold">{status.public_message || '部分服务正在维护，受影响的操作已暂时停用。'}</span>
    <span class="hidden shrink-0 items-center gap-1 font-normal md:flex"><Clock3 size={13} /> {formatExpiry(status.expires_at)}</span>
  </aside>
{/if}
