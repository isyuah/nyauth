<script lang="ts">
  import { goto } from '$app/navigation';
  import { page as pageStore } from '$app/stores';
  import { onDestroy, onMount } from 'svelte';
  import { api, type ClientAccessPolicy, type ClientAccessUser, type CreateClientInput, type OAuthClient, type UpdateClientInput, type User } from '$lib/api';
  import { formatStringMetadata, parseLineList, parseStringMetadata, parseTokenList } from '$lib/admin-form-utils';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import CopyField from '$lib/components/data-display/CopyField.svelte';
  import Pagination from '$lib/components/data-display/Pagination.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Card from '$lib/components/ui/Card.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import SecretReveal from '$lib/components/ui/SecretReveal.svelte';
  import { AppWindow, ChevronLeft, ChevronRight, Pencil, Plus, RefreshCw, Users } from 'lucide-svelte';

  type ClientForm = {
    name: string;
    redirect_uris: string;
    post_logout_redirect_uris: string;
    is_public: boolean;
    owner_id: string | null;
  };

  type ClientEditForm = {
    name: string;
    redirect_uris: string;
    post_logout_redirect_uris: string;
    scopes: string;
    metadata: string;
    access_policy: ClientAccessPolicy;
  };

  const accessPolicyOptions: Array<{ value: ClientAccessPolicy; label: string; description: string }> = [
    { value: 'open', label: '开放', description: '所有活跃用户都可以授权此应用' },
    { value: 'admins_only', label: '仅管理员', description: '只有管理员角色可以授权' },
    { value: 'allowlist', label: '白名单', description: '只有被加入访问名单的用户可以授权' },
  ];

  function accessPolicyLabel(policy: string | undefined): string {
    return accessPolicyOptions.find((option) => option.value === policy)?.label ?? '开放';
  }

  const grantOptions = [
    { value: 'authorization_code', label: 'Authorization Code' },
    { value: 'refresh_token', label: 'Refresh Token' },
    { value: 'client_credentials', label: 'Client Credentials' },
  ];
  const pageSize = 20;
  const ownerPageSize = 8;
  const requestedPage = Number($pageStore.url.searchParams.get('page'));

  let clients = $state<OAuthClient[]>([]);
  let currentPage = $state(Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1);
  let total = $state(0);
  let loading = $state(true);
  let showCreate = $state(false);
  let creating = $state(false);
  let newClient = $state<ClientForm>({ name: '', redirect_uris: '', post_logout_redirect_uris: '', is_public: false, owner_id: null });
  let createdSecret = $state('');
  let rotatedSecret = $state('');
  let rotatedClientName = $state('');
  let createError = $state('');
  let pageError = $state('');
  let deleteTarget = $state<OAuthClient | null>(null);
  let deleteOpen = $state(false);
  let deleteError = $state('');
  let rotateTarget = $state<OAuthClient | null>(null);
  let rotateOpen = $state(false);
  let rotateError = $state('');
  let editTarget = $state<OAuthClient | null>(null);
  let showEdit = $state(false);
  let editing = $state(false);
  let editError = $state('');
  let editGrants = $state<string[]>([]);
  let editForm = $state<ClientEditForm>({ name: '', redirect_uris: '', post_logout_redirect_uris: '', scopes: '', metadata: '{}', access_policy: 'open' });
  let accessTarget = $state<OAuthClient | null>(null);
  let accessModalOpen = $state(false);
  let accessUsers = $state<ClientAccessUser[]>([]);
  let accessLoading = $state(false);
  let accessSaving = $state(false);
  let accessError = $state('');
  let accessNotice = $state('');
  let accessSearch = $state('');
  let accessSearchResults = $state<User[]>([]);
  let accessSearchLoading = $state(false);
  let accessSearchError = $state('');
  let accessSearchVersion = 0;
  let ownerCandidates = $state<User[]>([]);
  let ownerLabels = $state<Record<string, string>>({});
  let ownerSearch = $state('');
  let ownerPage = $state(1);
  let ownerTotalPages = $state(1);
  let ownerLoading = $state(false);
  let ownerError = $state('');
  let ownerSearchTimer: ReturnType<typeof setTimeout> | undefined;
  let ownerRequestVersion = 0;
  let ownerTarget = $state<OAuthClient | null>(null);
  let pendingOwnerID = $state<string | null>(null);
  let ownerModalOpen = $state(false);
  let ownerConfirmOpen = $state(false);
  let ownerChangeError = $state('');
  let ownerNotice = $state('');
  let currentURLKey = '';
  let listRequestVersion = 0;

  function ownerDisplayName(user: User): string {
    return `${user.display_name || user.username} (@${user.username})`;
  }

  function selectedOwnerLabel(ownerID: string | null): string {
    if (!ownerID) return '未分配';
    return ownerLabels[ownerID] || ownerID;
  }

  function selectCreateOwner(ownerID: string | null) {
    newClient.owner_id = ownerID;
  }

  function selectPendingOwner(ownerID: string | null) {
    pendingOwnerID = ownerID;
  }

  function resetOwnerPicker() {
    if (ownerSearchTimer) clearTimeout(ownerSearchTimer);
    ownerSearch = '';
    ownerPage = 1;
    ownerTotalPages = 1;
    ownerCandidates = [];
    ownerError = '';
  }

  async function loadOwnerCandidates() {
    const requestVersion = ++ownerRequestVersion;
    ownerLoading = true;
    ownerError = '';
    try {
      const response = await api.admin.getUsers(ownerPage, ownerPageSize, ownerSearch.trim(), 'active');
      if (requestVersion !== ownerRequestVersion) return;
      ownerCandidates = response.items;
      ownerLabels = {
        ...ownerLabels,
        ...Object.fromEntries(response.items.map((user) => [user.id, ownerDisplayName(user)])),
      };
      ownerTotalPages = Math.max(1, response.total_pages);
    } catch (cause) {
      if (requestVersion === ownerRequestVersion) {
        ownerError = cause instanceof Error ? cause.message : 'Owner 候选用户加载失败';
        ownerCandidates = [];
      }
    } finally {
      if (requestVersion === ownerRequestVersion) ownerLoading = false;
    }
  }

  function scheduleOwnerSearch() {
    if (ownerSearchTimer) clearTimeout(ownerSearchTimer);
    ownerSearchTimer = setTimeout(() => {
      ownerPage = 1;
      void loadOwnerCandidates();
    }, 300);
  }

  async function changeOwnerPage(nextPage: number) {
    if (nextPage < 1 || nextPage > ownerTotalPages || nextPage === ownerPage) return;
    ownerPage = nextPage;
    await loadOwnerCandidates();
  }

  async function openCreate() {
    createdSecret = '';
    resetOwnerPicker();
    showCreate = true;
    await loadOwnerCandidates();
  }

  async function openOwnerManager(client: OAuthClient) {
    ownerTarget = client;
    pendingOwnerID = client.owner_id || null;
    ownerChangeError = '';
    resetOwnerPicker();
    ownerModalOpen = true;
    await loadOwnerCandidates();
  }

  function requestOwnerChange() {
    if (!ownerTarget || pendingOwnerID === (ownerTarget.owner_id || null)) return;
    ownerChangeError = '';
    ownerModalOpen = false;
    ownerConfirmOpen = true;
  }

  async function updateOwner() {
    const target = ownerTarget;
    if (!target) return;
    ownerChangeError = '';
    try {
      const updated = await api.admin.updateClientOwner(target.id, { owner_id: pendingOwnerID });
      clients = clients.map((client) => client.id === updated.id ? updated : client);
      ownerTarget = updated;
      ownerNotice = pendingOwnerID
        ? `已将“${updated.name}”转移给 ${selectedOwnerLabel(pendingOwnerID)}。`
        : `已解除“${updated.name}”的 Owner。`;
    } catch (cause) {
      ownerChangeError = cause instanceof Error ? cause.message : 'Owner 更新失败';
      throw cause;
    }
  }

  async function loadClients() {
    const requestVersion = ++listRequestVersion;
    loading = true;
    pageError = '';
    try {
      const response = await api.admin.getClients(currentPage, pageSize);
      if (requestVersion !== listRequestVersion) return;
      clients = response.items;
      total = response.total;
      if (currentPage > Math.max(1, response.total_pages)) {
        currentPage = Math.max(1, response.total_pages);
        await syncListURL();
        return;
      }
    } catch (cause) {
      if (requestVersion === listRequestVersion) pageError = cause instanceof Error ? cause.message : '应用列表加载失败';
    } finally {
      if (requestVersion === listRequestVersion) loading = false;
    }
  }

  async function syncListURL(): Promise<boolean> {
    const url = new URL($pageStore.url);
    if (currentPage > 1) url.searchParams.set('page', String(currentPage));
    else url.searchParams.delete('page');
    const target = `${url.pathname}${url.search}${url.hash}`;
    const current = `${$pageStore.url.pathname}${$pageStore.url.search}${$pageStore.url.hash}`;
    if (target === current) return false;
    await goto(target, { replaceState: true, noScroll: true, keepFocus: true });
    return true;
  }

  function applyListURLState(url: URL) {
    const key = `${url.pathname}${url.search}${url.hash}`;
    if (key === currentURLKey) return;
    currentURLKey = key;
    currentPage = Math.max(1, Number(url.searchParams.get('page')) || 1);
    void loadClients();
  }

  async function changePage(nextPage: number) {
    currentPage = nextPage;
    await syncListURL();
  }

  async function handleCreate(event: SubmitEvent) {
    event.preventDefault();
    creating = true;
    createError = '';
    createdSecret = '';
    rotatedSecret = '';
    rotatedClientName = '';
    try {
      const payload: CreateClientInput = {
        name: newClient.name,
        redirect_uris: newClient.redirect_uris.split('\n').map((uri) => uri.trim()).filter(Boolean),
        post_logout_redirect_uris: newClient.post_logout_redirect_uris.split('\n').map((uri) => uri.trim()).filter(Boolean),
        grants: ['authorization_code', 'refresh_token'],
        scopes: ['openid', 'profile', 'email', 'offline_access'],
        is_public: newClient.is_public,
        owner_id: newClient.owner_id,
      };
      const result = await api.admin.createClient(payload);
      createdSecret = result.secret || '';
      showCreate = false;
      newClient = { name: '', redirect_uris: '', post_logout_redirect_uris: '', is_public: false, owner_id: null };
      await loadClients();
    } catch (cause) {
      createError = cause instanceof Error ? cause.message : '创建失败';
    } finally {
      creating = false;
    }
  }

  function requestDelete(client: OAuthClient) {
    deleteTarget = client;
    deleteError = '';
    deleteOpen = true;
  }

  function requestRotation(client: OAuthClient) {
    createdSecret = '';
    rotatedSecret = '';
    rotatedClientName = '';
    rotateTarget = client;
    rotateError = '';
    rotateOpen = true;
  }

  async function rotateSecret() {
    const target = rotateTarget;
    if (!target) return;
    rotateError = '';
    try {
      const result = await api.admin.rotateClientSecret(target.id);
      rotatedSecret = result.secret;
      rotatedClientName = target.name;
      clients = clients.map((client) => client.id === target.id ? {
        ...client,
        secret_hint: result.secret_hint,
        secret_version: result.secret_version,
        secret_rotated_at: result.secret_rotated_at,
        secret_last_used_at: null,
      } : client);
    } catch (cause) {
      rotateError = cause instanceof Error ? cause.message : 'Secret 轮换失败';
      throw cause;
    }
  }

  async function deleteClient() {
    if (!deleteTarget) return;
    deleteError = '';
    try {
      await api.admin.deleteClient(deleteTarget.id);
      await loadClients();
    } catch (cause) {
      deleteError = cause instanceof Error ? cause.message : '删除失败';
      throw cause;
    }
  }

  function openEdit(client: OAuthClient) {
    editTarget = client;
    editGrants = [...client.grants];
    editForm = {
      name: client.name,
      redirect_uris: client.redirect_uris.join('\n'),
      post_logout_redirect_uris: client.post_logout_redirect_uris.join('\n'),
      scopes: client.scopes.join('\n'),
      metadata: formatStringMetadata(client.metadata),
      access_policy: (client.access_policy as ClientAccessPolicy) || 'open',
    };
    editError = '';
    showEdit = true;
  }

  async function handleEdit(event: SubmitEvent) {
    event.preventDefault();
    const target = editTarget;
    if (!target) return;

    editError = '';
    const name = editForm.name.trim();
    const redirectURIs = parseLineList(editForm.redirect_uris);
    const postLogoutRedirectURIs = parseLineList(editForm.post_logout_redirect_uris);
    const grants = [...new Set(editGrants)];
    if (!name) { editError = '应用名称不能为空。'; return; }
    if (redirectURIs.length === 0) { editError = '至少需要一个 Redirect URI。'; return; }
    if (grants.length === 0) { editError = '至少需要一个 Grant。'; return; }
    if (grants.includes('refresh_token') && !grants.includes('authorization_code')) {
      editError = 'Refresh Token 必须与 Authorization Code 同时启用。';
      return;
    }
    if (target.is_public && grants.includes('client_credentials')) {
      editError = 'Public Client 不能使用 Client Credentials。';
      return;
    }

    let metadata: Record<string, string>;
    try {
      metadata = parseStringMetadata(editForm.metadata);
    } catch (cause) {
      editError = cause instanceof Error ? cause.message : 'Metadata 格式无效。';
      return;
    }

    const payload: UpdateClientInput = {
      name,
      redirect_uris: redirectURIs,
      post_logout_redirect_uris: postLogoutRedirectURIs,
      grants,
      scopes: parseTokenList(editForm.scopes),
      metadata,
      access_policy: editForm.access_policy,
    };
    editing = true;
    try {
      const updated = await api.admin.updateClient(target.id, payload);
      clients = clients.map((client) => client.id === updated.id ? updated : client);
      showEdit = false;
    } catch (cause) {
      editError = cause instanceof Error ? cause.message : '应用更新失败';
    } finally {
      editing = false;
    }
  }

  async function openAccessUsers(client: OAuthClient) {
    accessTarget = client;
    accessModalOpen = true;
    accessUsers = [];
    accessError = '';
    accessNotice = '';
    accessSearch = '';
    accessSearchResults = [];
    accessSearchError = '';
    accessLoading = true;
    try {
      accessUsers = await api.admin.getClientAccessUsers(client.id);
    } catch (cause) {
      accessError = cause instanceof Error ? cause.message : '访问名单加载失败';
    } finally {
      accessLoading = false;
    }
  }

  async function searchAccessCandidates() {
    const term = accessSearch.trim();
    const version = ++accessSearchVersion;
    accessSearchLoading = true;
    accessSearchError = '';
    try {
      const response = await api.admin.getUsers(1, 8, term, 'active');
      if (version !== accessSearchVersion) return;
      accessSearchResults = response.items;
    } catch (cause) {
      if (version !== accessSearchVersion) return;
      accessSearchError = cause instanceof Error ? cause.message : '用户搜索失败';
    } finally {
      if (version === accessSearchVersion) accessSearchLoading = false;
    }
  }

  function addAccessUser(user: User) {
    if (accessUsers.some((entry) => entry.user_id === user.id)) return;
    accessUsers = [...accessUsers, {
      user_id: user.id,
      username: user.username,
      display_name: user.display_name || '',
      status: user.status,
      created_at: new Date().toISOString(),
    }];
    accessNotice = '';
  }

  function removeAccessUser(userID: string) {
    accessUsers = accessUsers.filter((entry) => entry.user_id !== userID);
    accessNotice = '';
  }

  async function saveAccessUsers() {
    const target = accessTarget;
    if (!target) return;
    accessSaving = true;
    accessError = '';
    accessNotice = '';
    try {
      accessUsers = await api.admin.updateClientAccessUsers(target.id, accessUsers.map((entry) => entry.user_id));
      accessNotice = '访问名单已保存，名单外用户的现有令牌将在下次使用时失效。';
    } catch (cause) {
      accessError = cause instanceof Error ? cause.message : '访问名单保存失败';
    } finally {
      accessSaving = false;
    }
  }

  onMount(() => pageStore.subscribe(({ url }) => applyListURLState(url)));
  onDestroy(() => {
    if (ownerSearchTimer) clearTimeout(ownerSearchTimer);
    ownerRequestVersion += 1;
  });
</script>

<svelte:head><title>应用管理 - Nya</title></svelte:head>

{#snippet ownerPicker(selectedOwnerID: string | null, selectOwner: (ownerID: string | null) => void, groupName: string)}
  <fieldset class="space-y-3">
    <legend class="text-body-medium font-semibold text-nya-text-primary">Owner</legend>
    <p class="text-small text-nya-text-secondary">只显示状态正常的用户；搜索和分页均由服务端处理。</p>
    <Input id={`${groupName}-search`} label="搜索 Owner" bind:value={ownerSearch} oninput={scheduleOwnerSearch} placeholder="用户名或邮箱" autocomplete="off" />
    <div class="overflow-hidden rounded-nya-sm border border-nya-border" role="radiogroup" aria-label="选择 Client Owner">
      <label class="flex min-h-12 cursor-pointer items-center gap-3 border-b border-nya-divider px-3 py-2 hover:bg-nya-surface-muted">
        <input type="radio" name={groupName} checked={selectedOwnerID === null} onchange={() => selectOwner(null)} />
        <span><span class="block text-body-medium text-nya-text-primary">未分配</span><span class="block text-small text-nya-text-tertiary">不归属于任何用户</span></span>
      </label>
      {#if ownerLoading}
        <p class="px-3 py-4 text-center text-small text-nya-text-tertiary" role="status">正在加载 Owner 候选…</p>
      {:else if ownerError}
        <div class="flex items-center justify-between gap-3 px-3 py-3"><p class="text-small text-nya-danger" role="alert">{ownerError}</p><Button variant="ghost" size="sm" onclick={loadOwnerCandidates}>重试</Button></div>
      {:else if ownerCandidates.length === 0}
        <p class="px-3 py-4 text-center text-small text-nya-text-tertiary">本页没有可选的 active 用户，请搜索或翻页。</p>
      {:else}
        {#each ownerCandidates as candidate}
          <label class="flex min-h-12 cursor-pointer items-center gap-3 border-b border-nya-divider px-3 py-2 last:border-b-0 hover:bg-nya-surface-muted">
            <input type="radio" name={groupName} checked={selectedOwnerID === candidate.id} onchange={() => selectOwner(candidate.id)} />
            <span class="min-w-0"><span class="block truncate text-body-medium text-nya-text-primary">{ownerDisplayName(candidate)}</span><span class="block truncate text-small text-nya-text-tertiary">{candidate.email || candidate.id}</span></span>
          </label>
        {/each}
      {/if}
    </div>
    <div class="flex items-center justify-between gap-3">
      <p class="min-w-0 truncate text-small text-nya-text-secondary">当前选择：{selectedOwnerLabel(selectedOwnerID)}</p>
      <div class="flex shrink-0 items-center gap-1">
        <Button variant="ghost" size="sm" ariaLabel="上一页 Owner 候选" disabled={ownerPage <= 1 || ownerLoading} onclick={() => changeOwnerPage(ownerPage - 1)}><ChevronLeft size={15} /></Button>
        <span class="min-w-16 text-center text-small text-nya-text-tertiary">{ownerPage} / {ownerTotalPages}</span>
        <Button variant="ghost" size="sm" ariaLabel="下一页 Owner 候选" disabled={ownerPage >= ownerTotalPages || ownerLoading} onclick={() => changeOwnerPage(ownerPage + 1)}><ChevronRight size={15} /></Button>
      </div>
    </div>
  </fieldset>
{/snippet}

<PageHeader title="应用管理" description="管理 OAuth 2.0 / OIDC 客户端、授权能力与回调地址">
  {#snippet action()}<Button variant="primary" requiredCapability="admin_mutations" onclick={openCreate}><Plus size={16} /> 创建应用</Button>{/snippet}
</PageHeader>

{#if ownerNotice}<p class="mb-4 rounded-nya-sm bg-nya-success-soft px-4 py-3 text-small text-nya-success" role="status">{ownerNotice}</p>{/if}

{#if createdSecret}
  <div class="mb-4 rounded-nya-md border border-nya-info/20 bg-nya-info-soft px-5 py-4">
    <p class="mb-2 text-body-medium text-nya-info">请立即复制并安全保存 Client Secret，离开本页后无法再次查看。</p>
    <SecretReveal value={createdSecret} label="Client Secret" />
  </div>
{/if}

{#if rotatedSecret}
  <div class="mb-4 rounded-nya-md border border-nya-warning/20 bg-nya-warning-soft px-5 py-4">
    <p class="mb-2 text-body-medium text-nya-warning">“{rotatedClientName}”的旧 Secret 已立即失效。新 Secret 仅在当前页面显示，请现在保存。</p>
    <SecretReveal value={rotatedSecret} label="新 Client Secret" />
  </div>
{/if}

<ResourceState
  {loading}
  error={pageError}
  empty={clients.length === 0}
  emptyTitle="还没有创建应用"
  emptyDescription="创建第一个 OAuth / OIDC 客户端后即可接入应用。"
  onretry={loadClients}
>
  {#snippet emptyAction()}<Button variant="primary" requiredCapability="admin_mutations" onclick={openCreate}>创建应用</Button>{/snippet}
  {#snippet children()}
    <div class="space-y-3">
      {#each clients as client}
        <Card>
          <div class="flex flex-col justify-between gap-4 md:flex-row md:items-start">
            <div class="flex min-w-0 items-center gap-3"><span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-nya-md bg-nya-blue-soft"><AppWindow size={20} class="text-nya-blue" /></span><div class="min-w-0"><h2 class="truncate text-card-title text-nya-text-primary">{client.name}</h2><CopyField value={client.id} /></div></div>
            <div class="flex flex-wrap items-center gap-2">{#if client.is_public}<Badge variant="warning">Public</Badge>{:else}<Badge variant="default">Confidential</Badge><Button variant="secondary" size="sm" requiredCapability="admin_mutations" onclick={() => requestRotation(client)}><RefreshCw size={14} /> 轮换 Secret</Button>{/if}{#if client.access_policy && client.access_policy !== 'open'}<Badge variant="warning">访问：{accessPolicyLabel(client.access_policy)}</Badge>{/if}<Badge variant="primary">{client.grants.join(', ')}</Badge>{#if client.access_policy === 'allowlist'}<Button variant="secondary" size="sm" requiredCapability="admin_mutations" ariaLabel={`管理 ${client.name} 访问名单`} onclick={() => openAccessUsers(client)}><Users size={14} /> 访问名单</Button>{/if}<Button variant="ghost" size="sm" requiredCapability="admin_mutations" onclick={() => openEdit(client)}><Pencil size={14} /> 编辑</Button><Button variant="ghost" size="sm" requiredCapability="admin_mutations" onclick={() => requestDelete(client)}>删除</Button></div>
          </div>
          <div class="mt-3 flex flex-wrap items-center justify-between gap-2"><p class="min-w-0 text-small text-nya-text-tertiary">Owner：<code class="break-all font-mono">{client.owner_id || '未分配'}</code> · Client 类型为只读，创建后不可更改。</p><Button variant="secondary" size="sm" requiredCapability="admin_mutations" ariaLabel={`管理 ${client.name} Owner`} onclick={() => openOwnerManager(client)}><Users size={14} /> 管理 Owner</Button></div>
          {#if !client.is_public}<p class="mt-3 text-small text-nya-text-tertiary">Secret 版本 {client.secret_version}{#if client.secret_hint} · 尾号 {client.secret_hint}{/if}{#if client.secret_rotated_at} · 最近轮换 {new Date(client.secret_rotated_at).toLocaleString()}{/if}{#if client.secret_last_used_at} · 最近使用 {new Date(client.secret_last_used_at).toLocaleString()}{/if}</p>{/if}
          <div class="mt-4"><p class="mb-1 text-small font-semibold text-nya-text-tertiary">Redirect URI</p><div class="flex flex-wrap gap-1.5">{#each client.redirect_uris as uri}<code class="break-all rounded-nya-xs bg-nya-surface-muted px-2 py-1 text-micro text-nya-text-secondary">{uri}</code>{/each}</div></div>
          {#if client.post_logout_redirect_uris.length > 0}<div class="mt-3"><p class="mb-1 text-small font-semibold text-nya-text-tertiary">Post-logout Redirect URI</p><div class="flex flex-wrap gap-1.5">{#each client.post_logout_redirect_uris as uri}<code class="break-all rounded-nya-xs bg-nya-surface-muted px-2 py-1 text-micro text-nya-text-secondary">{uri}</code>{/each}</div></div>{/if}
          <div class="mt-3"><p class="mb-1 text-small font-semibold text-nya-text-tertiary">Scopes</p><div class="flex flex-wrap gap-1.5">{#each client.scopes as scope}<Badge variant="default">{scope}</Badge>{/each}</div></div>
          {#if client.metadata && Object.keys(client.metadata).length > 0}<details class="mt-3"><summary class="cursor-pointer text-small text-nya-primary">Metadata</summary><pre class="mt-2 overflow-x-auto rounded-nya-sm bg-nya-surface-muted p-3 text-micro text-nya-text-secondary">{formatStringMetadata(client.metadata)}</pre></details>{/if}
        </Card>
      {/each}
    </div>
    <Pagination bind:page={currentPage} {pageSize} {total} onchange={changePage} />
  {/snippet}
</ResourceState>

<Modal bind:open={showCreate} title="创建应用" description="授权码客户端始终强制使用 S256 PKCE" size="md">
  <form onsubmit={handleCreate} class="space-y-4">
    {#if createError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{createError}</p>{/if}
    <Input id="client-name" label="应用名称" bind:value={newClient.name} required placeholder="我的应用" />
    <div class="flex flex-col gap-1.5"><label for="admin-redirect-uris" class="text-body-medium text-nya-text-primary">Redirect URI <span class="text-small text-nya-text-tertiary">（每行一个）</span></label><textarea id="admin-redirect-uris" bind:value={newClient.redirect_uris} required rows="3" placeholder="https://app.example.com/callback" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small text-nya-text-primary focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea></div>
    <div class="flex flex-col gap-1.5"><label for="admin-post-logout-uris" class="text-body-medium text-nya-text-primary">Post-logout Redirect URI <span class="text-small text-nya-text-tertiary">（每行一个）</span></label><textarea id="admin-post-logout-uris" bind:value={newClient.post_logout_redirect_uris} rows="2" placeholder="https://app.example.com/signed-out" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small text-nya-text-primary focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea></div>
    {@render ownerPicker(newClient.owner_id, selectCreateOwner, 'create-client-owner')}
    <label class="flex cursor-pointer items-start gap-2"><input type="checkbox" bind:checked={newClient.is_public} class="mt-0.5 rounded" /><span><span class="block text-body text-nya-text-primary">公共客户端</span><span class="block text-small text-nya-text-tertiary">仅用于无法安全保存 Secret 的原生应用；浏览器 SPA 暂不作为正式支持模式。</span></span></label>
    <div class="flex justify-end gap-2 pt-2"><Button variant="secondary" onclick={() => (showCreate = false)} disabled={creating}>取消</Button><Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={creating}>创建</Button></div>
  </form>
</Modal>

<Modal bind:open={showEdit} title={`编辑 OAuth Client · ${editTarget?.name || ''}`} description="Client 类型不可变；Owner 请通过应用卡片上的独立操作管理" size="lg">
  <form onsubmit={handleEdit} class="space-y-4">
    {#if editError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{editError}</p>{/if}
    <div class="grid gap-4 sm:grid-cols-2"><Input id="edit-client-name" label="应用名称" bind:value={editForm.name} required /><div><span class="mb-1.5 block text-body-medium text-nya-text-primary">Client 类型 / Owner</span><p class="rounded-nya-sm bg-nya-surface-muted px-3 py-2 text-small text-nya-text-secondary">{editTarget?.is_public ? 'Public' : 'Confidential'} · <code>{editTarget?.owner_id || '未分配'}</code></p></div></div>
    <div><label for="edit-client-redirects" class="mb-1.5 block text-body-medium text-nya-text-primary">Redirect URI（每行一个）</label><textarea id="edit-client-redirects" bind:value={editForm.redirect_uris} required rows="3" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea></div>
    <div><label for="edit-client-logouts" class="mb-1.5 block text-body-medium text-nya-text-primary">Post-logout Redirect URI（每行一个）</label><textarea id="edit-client-logouts" bind:value={editForm.post_logout_redirect_uris} rows="2" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea></div>
    <fieldset><legend class="mb-2 text-body-medium text-nya-text-primary">Grants</legend><div class="grid gap-2 sm:grid-cols-3">{#each grantOptions as option}<label class="flex items-center gap-2 rounded-nya-sm border border-nya-border px-3 py-2 text-small text-nya-text-secondary"><input type="checkbox" value={option.value} bind:group={editGrants} disabled={editTarget?.is_public && option.value === 'client_credentials'} /> {option.label}</label>{/each}</div></fieldset>
    <fieldset><legend class="mb-2 text-body-medium text-nya-text-primary">访问策略</legend><div class="grid gap-2 sm:grid-cols-3">{#each accessPolicyOptions as option}<label class="flex cursor-pointer items-start gap-2 rounded-nya-sm border border-nya-border px-3 py-2 {editForm.access_policy === option.value ? 'border-nya-primary bg-nya-primary-soft' : ''}"><input type="radio" name="edit-access-policy" value={option.value} bind:group={editForm.access_policy} class="mt-0.5" /><span><span class="block text-small font-semibold text-nya-text-primary">{option.label}</span><span class="block text-micro text-nya-text-tertiary">{option.description}</span></span></label>{/each}</div><p class="mt-1.5 text-micro text-nya-text-tertiary">策略只作用于用户授权流程；client_credentials 机器流程不受限制。切换为白名单后请在应用卡片上维护访问名单。</p></fieldset>
    <div><label for="edit-client-scopes" class="mb-1.5 block text-body-medium text-nya-text-primary">Scopes（空格、逗号或换行分隔）</label><textarea id="edit-client-scopes" bind:value={editForm.scopes} rows="2" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea></div>
    <div><label for="edit-client-metadata" class="mb-1.5 block text-body-medium text-nya-text-primary">Metadata（JSON 字符串键值）</label><textarea id="edit-client-metadata" bind:value={editForm.metadata} rows="5" spellcheck="false" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea></div>
    <div class="flex justify-end gap-2"><Button variant="secondary" onclick={() => (showEdit = false)} disabled={editing}>取消</Button><Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={editing}>保存更改</Button></div>
  </form>
</Modal>

<Modal bind:open={accessModalOpen} title={`访问名单 · ${accessTarget?.name || ''}`} description="只有名单内的用户可以完成此应用的授权；保存后立刻生效" size="md">
  <div class="space-y-4">
    {#if accessError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{accessError}</p>{/if}
    {#if accessNotice}<p class="rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">{accessNotice}</p>{/if}
    <div>
      <p class="mb-2 text-body-medium font-semibold text-nya-text-primary">当前名单（{accessUsers.length}）</p>
      {#if accessLoading}
        <p class="text-small text-nya-text-tertiary">加载中…</p>
      {:else if accessUsers.length === 0}
        <p class="rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning">名单为空：当前没有任何用户可以授权此应用。</p>
      {:else}
        <ul class="space-y-1.5">
          {#each accessUsers as entry (entry.user_id)}
            <li class="flex items-center justify-between gap-2 rounded-nya-sm border border-nya-border px-3 py-2">
              <span class="min-w-0 truncate text-small text-nya-text-primary">{entry.display_name || entry.username} <span class="text-nya-text-tertiary">@{entry.username}</span></span>
              <Button variant="ghost" size="sm" ariaLabel={`移除 ${entry.username}`} onclick={() => removeAccessUser(entry.user_id)}>移除</Button>
            </li>
          {/each}
        </ul>
      {/if}
    </div>
    <div>
      <p class="mb-2 text-body-medium font-semibold text-nya-text-primary">添加用户</p>
      <div class="flex items-end gap-2">
        <div class="min-w-0 flex-1"><Input id="access-user-search" label="搜索用户" bind:value={accessSearch} placeholder="用户名或邮箱" autocomplete="off" /></div>
        <Button variant="secondary" onclick={searchAccessCandidates} loading={accessSearchLoading}>搜索</Button>
      </div>
      {#if accessSearchError}<p class="mt-2 text-small text-nya-danger" role="alert">{accessSearchError}</p>{/if}
      {#if accessSearchResults.length > 0}
        <ul class="mt-2 space-y-1.5">
          {#each accessSearchResults as candidate (candidate.id)}
            <li class="flex items-center justify-between gap-2 rounded-nya-sm border border-nya-border px-3 py-2">
              <span class="min-w-0 truncate text-small text-nya-text-primary">{candidate.display_name || candidate.username} <span class="text-nya-text-tertiary">@{candidate.username}</span></span>
              <Button variant="secondary" size="sm" disabled={accessUsers.some((entry) => entry.user_id === candidate.id)} onclick={() => addAccessUser(candidate)}>添加</Button>
            </li>
          {/each}
        </ul>
      {/if}
    </div>
    <div class="flex justify-end gap-2"><Button variant="secondary" onclick={() => (accessModalOpen = false)} disabled={accessSaving}>关闭</Button><Button variant="primary" requiredCapability="admin_mutations" onclick={saveAccessUsers} loading={accessSaving}>保存名单</Button></div>
  </div>
</Modal>

<Modal bind:open={ownerModalOpen} title={`管理 Client Owner · ${ownerTarget?.name || ''}`} description="转移或解除 Owner 会改变用户对该客户端的管理权限" size="md">
  <div class="space-y-4">
    {@render ownerPicker(pendingOwnerID, selectPendingOwner, 'transfer-client-owner')}
    <div class="flex justify-end gap-2"><Button variant="secondary" onclick={() => (ownerModalOpen = false)}>取消</Button><Button variant="primary" requiredCapability="admin_mutations" onclick={requestOwnerChange} disabled={pendingOwnerID === (ownerTarget?.owner_id || null)}>继续</Button></div>
  </div>
</Modal>

<ConfirmDialog
  bind:open={deleteOpen}
  title="删除应用"
  description={`删除后，所有使用“${deleteTarget?.name || ''}”的 OAuth 集成会立即失效。`}
  confirmLabel="永久删除"
  confirmationText={deleteTarget?.name || ''}
  error={deleteError}
  onconfirm={deleteClient}
/>

<ConfirmDialog
  bind:open={rotateOpen}
  title="轮换 Client Secret"
  description={`“${rotateTarget?.name || ''}”的旧 Secret 会立即失效，所有使用旧凭据的服务必须同步更新。`}
  confirmLabel="立即轮换"
  confirmationText={rotateTarget?.name || ''}
  error={rotateError}
  onconfirm={rotateSecret}
/>

<ConfirmDialog
  bind:open={ownerConfirmOpen}
  title="确认变更 Client Owner"
  description={pendingOwnerID ? `“${ownerTarget?.name || ''}”将转移给 ${selectedOwnerLabel(pendingOwnerID)}。` : `“${ownerTarget?.name || ''}”将解除 Owner，之后不归属于任何用户。`}
  confirmLabel={pendingOwnerID ? '确认转移' : '确认解除'}
  confirmationText={ownerTarget?.name || ''}
  error={ownerChangeError}
  onconfirm={updateOwner}
/>
