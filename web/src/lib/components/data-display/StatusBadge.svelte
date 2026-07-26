<script lang="ts">
  import Badge from '$lib/components/ui/Badge.svelte';

  let {
    status = 'active',
  }: {
    status: string;
  } = $props();

  const map: Record<string, { variant: 'success' | 'warning' | 'danger' | 'default'; label: string }> = {
    active: { variant: 'success', label: '正常' },
    suspended: { variant: 'danger', label: '已禁用' },
    pending: { variant: 'warning', label: '待验证' },
    enabled: { variant: 'success', label: '已启用' },
    disabled: { variant: 'default', label: '已禁用' },
    ok: { variant: 'success', label: '正常' },
    degraded: { variant: 'warning', label: '降级' },
    unavailable: { variant: 'danger', label: '不可用' },
    not_configured: { variant: 'default', label: '未配置' },
    not_ready: { variant: 'warning', label: '未就绪' },
  };

  let config = $derived(map[status] || { variant: 'default' as const, label: status });
</script>

<Badge variant={config.variant}>{config.label}</Badge>
