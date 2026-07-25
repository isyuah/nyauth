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
  };

  const config = map[status] || { variant: 'default' as const, label: status };
</script>

<Badge variant={config.variant}>{config.label}</Badge>
