<script lang="ts">
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { api, type AdminUserOverview, type User } from '$lib/api';
  import { provideAdminUserDetailContext } from '$lib/admin-user-detail';
  import { safeReturnPath } from '$lib/navigation';
  import RouteTabs from '$lib/components/layout/RouteTabs.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import { ArrowLeft } from 'lucide-svelte';

  let { children } = $props();
  const userID = $derived($page.params.id || '');
  const returnTo = $derived(safeReturnPath($page.url.searchParams.get('return_to'), '/admin/users'));
  let overview = $state<AdminUserOverview | null>(null);
  let loading = $state(true);
  let error = $state('');

  async function loadOverview() {
    loading = true;
    error = '';
    try {
      overview = await api.admin.getUserOverview(userID);
    } catch (cause) {
      overview = null;
      error = cause instanceof Error ? cause.message : '用户详情加载失败';
    } finally {
      loading = false;
    }
  }

  function updateUser(user: User) {
    if (overview) overview = { ...overview, user };
  }

  function detailHref(path = ''): string {
    const params = new URLSearchParams({ return_to: returnTo });
    return `/admin/users/${encodeURIComponent(userID)}${path}?${params}`;
  }

  const tabs = $derived([
    { href: detailHref(), label: '资料', exact: true },
    { href: detailHref('/security'), label: '安全' },
    { href: detailHref('/sessions'), label: '会话' },
    { href: detailHref('/access'), label: '访问' },
    { href: detailHref('/activity'), label: '活动' },
  ]);

  const context = {
    get userID() { return userID; },
    get returnTo() { return returnTo; },
    get overview() { return overview; },
    get loading() { return loading; },
    get error() { return error; },
    reload: loadOverview,
    updateUser,
  };
  provideAdminUserDetailContext(context);

  onMount(loadOverview);
</script>

<ResourceState {loading} {error} empty={!overview} emptyTitle="用户不存在" emptyDescription="该用户可能已被删除。" onretry={loadOverview}>
  {#snippet children()}
    {#if overview}
      <div class="mb-5">
        <a href={returnTo} class="mb-4 inline-flex items-center gap-2 text-small text-nya-text-secondary hover:text-nya-primary"><ArrowLeft size={15} /> 返回用户列表</a>
        <div class="mb-4 flex flex-wrap items-center gap-4">
          <span class="flex h-14 w-14 items-center justify-center overflow-hidden rounded-full bg-nya-primary-soft text-xl font-semibold text-nya-primary">
            {#if overview.user.avatar_url}<img src={overview.user.avatar_url} alt="" class="h-full w-full object-cover" />{:else}{overview.user.username.slice(0, 1).toUpperCase()}{/if}
          </span>
          <div class="min-w-0 flex-1"><h1 class="truncate text-2xl font-bold text-nya-text-primary">{overview.user.display_name || overview.user.username}</h1><p class="text-body text-nya-text-secondary">@{overview.user.username}</p></div>
          <div class="flex gap-2"><Badge variant={overview.user.role === 'admin' ? 'pink' : 'default'}>{overview.user.role === 'admin' ? '管理员' : '用户'}</Badge><Badge variant={overview.user.status === 'active' ? 'success' : overview.user.status === 'suspended' ? 'danger' : 'warning'}>{overview.user.status === 'active' ? '正常' : overview.user.status === 'suspended' ? '已封禁' : '待验证'}</Badge></div>
        </div>
        <RouteTabs {tabs} label="用户详情" />
      </div>
      {@render children()}
    {/if}
  {/snippet}
</ResourceState>
