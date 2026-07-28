<script lang="ts">
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import RouteTabs, { type RouteTab } from '$lib/components/layout/RouteTabs.svelte';

  let { title, description = '' }: { title: string; description?: string } = $props();
  const tabs: RouteTab[] = [
    { href: '/admin/settings/branding', label: '品牌' },
    { href: '/admin/settings/registration', label: '注册' },
    { href: '/admin/settings/mail', label: '邮件' },
    { href: '/admin/settings/security', label: '登录安全' },
    { href: '/admin/settings/operations', label: '运行控制' },
  ];
</script>

<PageHeader {title} {description} />
<RouteTabs {tabs} label="系统设置" />
