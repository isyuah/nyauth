<script lang="ts">
  import { goto } from '$app/navigation';
  import { page as pageStore } from '$app/stores';
  import { onMount } from 'svelte';
  import { api, type OAuthAuthorization } from '$lib/api';
  import OAuthClientLogo from '$lib/components/oauth/OAuthClientLogo.svelte';
  import Pagination from '$lib/components/data-display/Pagination.svelte';
  import FilterBar from '$lib/components/ui/FilterBar.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Select from '$lib/components/ui/Select.svelte';
  import Drawer from '$lib/components/ui/Drawer.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import { ExternalLink, Info, Search, TriangleAlert } from 'lucide-svelte';
  import { CLAIM_HELP } from '$lib/oauth-catalog';

  const pageSize = 15;
  let authorizations = $state<OAuthAuthorization[]>([]);
  let currentPage = $state(1);
  let total = $state(0);
  let query = $state('');
  let status = $state('');
  let loading = $state(true);
  let error = $state('');
  let selected = $state<OAuthAuthorization | null>(null);
  let drawerOpen = $state(false);
  let target = $state<OAuthAuthorization | null>(null);
  let confirmOpen = $state(false);
  let actionError = $state('');

  const statusOptions = [
    { value: '', label: '全部状态' }, { value: 'valid', label: '授权有效' },
    { value: 'changed', label: '应用信息已变更' }, { value: 'reauthorization_required', label: '需要重新授权' },
    { value: 'unused', label: '尚未使用' },
  ];

  async function loadAuthorizations() {
    loading = true;
    error = '';
    try {
      const result = await api.getMyAuthorizations({ q: query.trim(), status, page: currentPage, pageSize });
      authorizations = result.items;
      total = result.total;
      if (currentPage > Math.max(1, result.total_pages)) {
        currentPage = Math.max(1, result.total_pages);
        await syncURL();
      }
    } catch (cause) { error = cause instanceof Error ? cause.message : 'OAuth 授权加载失败'; }
    finally { loading = false; }
  }

  async function syncURL() {
    const url = new URL($pageStore.url);
    if (currentPage > 1) url.searchParams.set('page', String(currentPage)); else url.searchParams.delete('page');
    if (query.trim()) url.searchParams.set('q', query.trim()); else url.searchParams.delete('q');
    if (status) url.searchParams.set('status', status); else url.searchParams.delete('status');
    await goto(`${url.pathname}${url.search}`, { replaceState: true, noScroll: true, keepFocus: true });
  }

  async function applyFilters() { currentPage = 1; await syncURL(); await loadAuthorizations(); }
  async function clearFilters() { query = ''; status = ''; await applyFilters(); }
  async function changePage(value: number) { currentPage = value; await syncURL(); await loadAuthorizations(); }
  function openDetails(item: OAuthAuthorization) { selected = item; drawerOpen = true; }
  function requestRevocation(item: OAuthAuthorization) { target = item; actionError = ''; confirmOpen = true; }

  async function revokeAuthorization() {
    if (!target) return;
    const authorization = target;
    actionError = '';
    try {
      await api.revokeMyAuthorization(authorization.client_id);
      if (selected?.client_id === authorization.client_id) drawerOpen = false;
      target = null;
      await loadAuthorizations();
    } catch (cause) {
      actionError = cause instanceof Error ? cause.message : '无法撤销 OAuth 授权';
      throw cause;
    }
  }

  onMount(() => {
    currentPage = Math.max(1, Number($pageStore.url.searchParams.get('page')) || 1);
    query = $pageStore.url.searchParams.get('q') || '';
    status = $pageStore.url.searchParams.get('status') || '';
    void loadAuthorizations();
  });
</script>

<svelte:head><title>OAuth 应用授权 - Nya</title></svelte:head>

<section>
  <div class="mb-5"><h2 class="text-card-title text-nya-text-primary">OAuth 应用授权</h2><p class="mt-1 text-body text-nya-text-secondary">查看哪些应用可以访问您的账户，并按需撤销。</p></div>
  <FilterBar label="筛选 OAuth 授权">
    <form class="grid gap-3 sm:grid-cols-[minmax(0,1fr)_220px_auto]" onsubmit={(event) => { event.preventDefault(); void applyFilters(); }}>
      <Input id="authorization-search" label="搜索应用" bind:value={query} placeholder="应用名称或 Client ID" autocomplete="off" />
      <Select label="授权状态" bind:value={status} options={statusOptions} />
      <div class="flex items-end gap-2"><Button type="button" variant="ghost" onclick={clearFilters}>清除</Button><Button type="submit" variant="secondary" loading={loading}><Search size={14} /> 筛选</Button></div>
    </form>
  </FilterBar>

  {#if loading && authorizations.length === 0}<p class="py-10 text-center text-body text-nya-text-tertiary" role="status">正在加载应用授权…</p>
  {:else if error}<div class="flex items-center justify-between gap-3 bg-nya-danger-soft px-3 py-2"><p class="text-small text-nya-danger">{error}</p><Button variant="ghost" size="sm" onclick={loadAuthorizations}>重试</Button></div>
  {:else if authorizations.length === 0}<p class="py-10 text-center text-body text-nya-text-tertiary">没有符合条件的 OAuth 应用授权。</p>
  {:else}
    <div class="divide-y divide-nya-divider border-y border-nya-border">
      {#each authorizations as authorization (authorization.id)}
        <article class="grid gap-3 py-4 sm:grid-cols-[minmax(0,1fr)_minmax(180px,auto)_auto] sm:items-center">
          <div class="flex min-w-0 items-center gap-3"><OAuthClientLogo name={authorization.client_name} url={authorization.logo_url} /><div class="min-w-0"><h3 class="truncate text-body-medium font-semibold text-nya-text-primary">{authorization.client_name}</h3><code class="block truncate text-micro text-nya-text-tertiary">{authorization.client_id}</code></div></div>
          <div><div class="flex flex-wrap items-center gap-2">{#if authorization.reauthorization_required}<Badge variant="danger">需重新授权</Badge>{:else if authorization.application_changed}<Badge variant="warning">信息已变更</Badge>{:else}<Badge variant="success">授权有效</Badge>{/if}<span class="text-small text-nya-text-secondary">{authorization.scopes.length} 个 Scope</span></div><p class="mt-1 text-micro text-nya-text-tertiary">最近使用：{authorization.last_used_at ? new Date(authorization.last_used_at).toLocaleString() : '尚无记录'}</p></div>
          <div class="flex gap-2 sm:justify-end"><Button variant="secondary" size="sm" onclick={() => openDetails(authorization)}>查看详情</Button><Button variant="ghost" size="sm" onclick={() => requestRevocation(authorization)}>撤销</Button></div>
        </article>
      {/each}
    </div>
    <Pagination bind:page={currentPage} {pageSize} {total} onchange={changePage} />
  {/if}
</section>

<Drawer bind:open={drawerOpen} title={selected?.client_name || '授权详情'} description="当前授权的身份、权限和应用信息" width="560px">
  {#if selected}
    <div class="flex items-center gap-3"><OAuthClientLogo name={selected.client_name} url={selected.logo_url} size="lg" /><div class="min-w-0"><p class="text-card-title text-nya-text-primary">{selected.client_name}</p><code class="block truncate text-micro text-nya-text-tertiary">{selected.client_id}</code></div></div>
    {#if selected.reauthorization_required}<div class="mt-4 flex items-start gap-2 bg-nya-danger-soft px-3 py-2 text-small text-nya-danger"><TriangleAlert size={15} class="mt-0.5 shrink-0" /><span>应用的回调地址或授权能力发生高风险变更，下次使用时需要重新授权。</span></div>{:else if selected.application_changed}<div class="mt-4 flex items-start gap-2 bg-nya-warning-soft px-3 py-2 text-small text-nya-warning"><Info size={15} class="mt-0.5 shrink-0" /><span>应用名称、Logo、公开链接或发布者状态在授权后发生了变化。</span></div>{/if}
    <dl class="mt-5 grid gap-4 text-small sm:grid-cols-2"><div><dt class="text-nya-text-tertiary">授权时间</dt><dd class="mt-1 text-nya-text-primary">{new Date(selected.granted_at).toLocaleString()}</dd></div><div><dt class="text-nya-text-tertiary">最近使用</dt><dd class="mt-1 text-nya-text-primary">{selected.last_used_at ? new Date(selected.last_used_at).toLocaleString() : '尚无记录'}</dd></div></dl>
    {#if selected.homepage_uri || selected.privacy_policy_uri || selected.terms_of_service_uri}<nav aria-label="应用公开信息" class="mt-5 flex flex-wrap gap-3 text-small">{#if selected.homepage_uri}<a href={selected.homepage_uri} target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1 text-nya-primary hover:underline"><ExternalLink size={13} /> 应用主页</a>{/if}{#if selected.privacy_policy_uri}<a href={selected.privacy_policy_uri} target="_blank" rel="noopener noreferrer" class="text-nya-primary hover:underline">隐私政策</a>{/if}{#if selected.terms_of_service_uri}<a href={selected.terms_of_service_uri} target="_blank" rel="noopener noreferrer" class="text-nya-primary hover:underline">服务条款</a>{/if}</nav>{/if}
    <div class="mt-5"><p class="mb-2 text-small font-semibold text-nya-text-primary">已授予 Scope</p><div class="flex flex-wrap gap-1.5">{#each selected.scopes as scope}<Badge variant={scope === 'offline_access' ? 'warning' : 'default'}>{scope}</Badge>{/each}</div></div>
    {#if selected.allowed_claims.length > 0}<div class="mt-5"><p class="mb-2 text-small font-semibold text-nya-text-primary">允许返回的 Claim</p><div class="flex flex-wrap gap-1.5">{#each selected.allowed_claims as claim}<Badge variant="info">{CLAIM_HELP[claim]?.title || claim} <code class="ml-1">{claim}</code></Badge>{/each}</div></div>{/if}
    {#if selected.application_changed}<details class="mt-5 bg-nya-surface-muted px-3 py-2"><summary class="cursor-pointer text-small font-semibold text-nya-text-primary">授权时的应用信息</summary><dl class="mt-2 space-y-1 text-small text-nya-text-secondary"><div><dt class="inline text-nya-text-tertiary">名称：</dt><dd class="inline">{selected.client_name_at_grant || selected.client_name}</dd></div>{#if selected.homepage_uri_at_grant}<div><dt class="inline text-nya-text-tertiary">主页：</dt><dd class="inline break-all">{selected.homepage_uri_at_grant}</dd></div>{/if}</dl></details>{/if}
    <div class="mt-6 border-t border-nya-divider pt-4"><Button variant="danger" onclick={() => selected && requestRevocation(selected)}>撤销此应用授权</Button></div>
  {/if}
</Drawer>

<ConfirmDialog bind:open={confirmOpen} title="撤销 OAuth 应用授权" description={`撤销后，“${target?.client_name || ''}”现有的访问令牌和刷新令牌将失效；再次使用时需要重新授权。`} confirmLabel="撤销授权" error={actionError} onconfirm={revokeAuthorization} />
