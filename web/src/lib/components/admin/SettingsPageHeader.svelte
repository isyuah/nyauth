<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '$lib/api';
  import { protectionSettingsStore, publishProtectionSettings } from '$lib/policy-settings';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import RouteTabs, { type RouteTab } from '$lib/components/layout/RouteTabs.svelte';
  import { AlertTriangle } from 'lucide-svelte';

  let { title, description = '' }: { title: string; description?: string } = $props();
  const tabs: RouteTab[] = [
    { href: '/admin/settings/branding', label: '品牌' },
    { href: '/admin/settings/registration', label: '注册' },
    { href: '/admin/settings/mail', label: '邮件' },
    { href: '/admin/settings/communications', label: '沟通' },
    { href: '/admin/settings/media', label: '媒体' },
    { href: '/admin/settings/security', label: '登录安全' },
    { href: '/admin/settings/protection', label: '访问保护' },
    { href: '/admin/settings/lifecycle', label: '生命周期' },
    { href: '/admin/settings/oauth', label: 'OAuth 客户端' },
    { href: '/admin/settings/operations', label: '运行控制' },
  ];
  let disabledRateLimits = $derived($protectionSettingsStore
    ? (['login', 'account', 'avatar', 'mail'] as const).filter((group) => !$protectionSettingsStore?.[group].enabled)
    : []);
  const rateLimitLabels: Record<string, string> = { login: '登录', account: '账户操作', avatar: '头像', mail: 'SMTP 管理' };

  onMount(async () => {
    try {
      publishProtectionSettings(await api.admin.getProtectionSettings());
    } catch (cause) {
      console.warn('failed to load rate-limit warning state', cause);
    }
  });
</script>

<PageHeader {title} {description} />
<RouteTabs {tabs} label="系统设置" />
{#if disabledRateLimits.length > 0}
  <a href="/admin/settings/protection" class="mt-3 flex items-start gap-2 rounded-nya-sm border border-nya-warning/30 bg-nya-warning-soft px-3 py-2 text-small text-nya-warning">
    <AlertTriangle size={16} class="mt-0.5 shrink-0" />
    <span>{disabledRateLimits.map((group) => rateLimitLabels[group] || group).join('、')}限流已关闭</span>
  </a>
{/if}
