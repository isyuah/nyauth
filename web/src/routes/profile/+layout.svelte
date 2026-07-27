<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { sessionStore } from '$lib/stores';
  import AppShell from '$lib/components/layout/AppShell.svelte';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import RouteTabs, { type RouteTab } from '$lib/components/layout/RouteTabs.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';

  let { children } = $props();

  const tabs: Array<RouteTab & { title: string; description: string }> = [
    { href: '/profile', label: '基本资料', exact: true, title: '个人资料', description: '管理账户资料、头像和邮箱' },
    { href: '/profile/security', label: '安全', title: '账户安全', description: '管理密码、多因素验证、Passkey 和近期认证' },
    { href: '/profile/sessions', label: '设备会话', title: '设备会话', description: '查看已登录设备并撤销不认识的会话' },
    { href: '/profile/authorizations', label: '应用授权', title: 'OAuth 应用授权', description: '查看并撤销已获准访问账户信息的应用' },
    { href: '/profile/identities', label: '外部身份', title: '外部身份', description: '管理可用于登录和重新认证的身份提供商' },
  ];

  let authorized = $state(false);
  let loading = $state(true);
  let error = $state('');
  let currentRoute = $derived(routeMetadata($page.url.pathname));

  function routeMetadata(pathname: string) {
    return tabs.find((tab) => pathname === tab.href || (!tab.exact && pathname.startsWith(`${tab.href}/`))) ?? tabs[0];
  }

  function returnPath(): string {
    return `${$page.url.pathname}${$page.url.search}${$page.url.hash}`;
  }

  async function authorize() {
    loading = true;
    error = '';
    try {
      const session = await sessionStore.initialize(true);
      if (!session) {
        await goto(`/login?return_to=${encodeURIComponent(returnPath())}`);
      } else if (session.must_change_password) {
        await goto(`/change-password?return_to=${encodeURIComponent(returnPath())}`);
      } else {
        authorized = true;
      }
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '无法验证当前会话';
    } finally {
      loading = false;
    }
  }

  onMount(authorize);
</script>

{#if loading || error}
  <div class="min-h-screen bg-nya-bg p-6">
    <div class="mx-auto max-w-2xl pt-24">
      <ResourceState {loading} {error} onretry={authorize}>{#snippet children()}{/snippet}</ResourceState>
    </div>
  </div>
{:else if authorized}
  <AppShell section="user">
    <div class="mx-auto max-w-4xl">
      <PageHeader title={currentRoute.title} description={currentRoute.description} />
      <RouteTabs {tabs} label="个人中心分区" />
      <div class="mt-5">
        {@render children()}
      </div>
    </div>
  </AppShell>
{/if}
