<script lang="ts">
  import { goto } from '$app/navigation';
  import { page as pageStore } from '$app/stores';
  import { onDestroy, onMount } from 'svelte';
  import { api, type BrowserSession, type ExternalIdentity, type User, type UserRole } from '$lib/api';
  import { formatStringMetadata, parseStringMetadata } from '$lib/admin-form-utils';
  import { PASSWORD_REQUIREMENT, passwordPolicyError } from '$lib/password-policy';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import Pagination from '$lib/components/data-display/Pagination.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import DangerZone from '$lib/components/ui/DangerZone.svelte';
  import Drawer from '$lib/components/ui/Drawer.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import Select from '$lib/components/ui/Select.svelte';
  import { Ban, CheckCircle, KeyRound, LogOut, MonitorSmartphone, Plus, Search, Shield, Trash2 } from 'lucide-svelte';

  type ConfirmAction = { kind: 'delete' | 'suspend' | 'revoke-sessions'; user: User } | null;

  const pageSize = 20;
  const statusMap: Record<string, { label: string; variant: 'success' | 'danger' | 'warning' | 'default' }> = {
    active: { label: '正常', variant: 'success' },
    suspended: { label: '已封禁', variant: 'danger' },
    pending: { label: '待验证', variant: 'warning' },
  };

  let users = $state<User[]>([]);
  let total = $state(0);
  let currentPage = $state(Math.max(1, Number($pageStore.url.searchParams.get('page')) || 1));
  let search = $state($pageStore.url.searchParams.get('q') || '');
  let loading = $state(true);
  let pageError = $state('');
  let showCreate = $state(false);
  let creating = $state(false);
  let newUser = $state({ username: '', email: '', password: '', display_name: '' });
  let createError = $state('');
  let drawerOpen = $state(false);
  let selectedUser = $state<User | null>(null);
  let selectedRole = $state<UserRole>('user');
  let profileForm = $state({ email: '', display_name: '', avatar_url: '', metadata: '{}' });
  let profileSaving = $state(false);
  let profileError = $state('');
  let profileNotice = $state('');
  let userIdentities = $state<ExternalIdentity[]>([]);
  let identitiesLoading = $state(false);
  let identitiesError = $state('');
  let identitiesNotice = $state('');
  let identityTarget = $state<ExternalIdentity | null>(null);
  let identityConfirmOpen = $state(false);
  let identityConfirmError = $state('');
  let userSessions = $state<BrowserSession[]>([]);
  let sessionsLoading = $state(false);
  let sessionsError = $state('');
  let sessionsNotice = $state('');
  let resetPasswordValue = $state('');
  let resetPasswordConfirmation = $state('');
  let passwordResetting = $state(false);
  let passwordResetError = $state('');
  let passwordResetComplete = $state(false);
  let roleSaving = $state(false);
  let roleError = $state('');
  let confirmAction = $state<ConfirmAction>(null);
  let confirmOpen = $state(false);
  let confirmError = $state('');
  let searchTimer: ReturnType<typeof setTimeout> | undefined;
  let currentURLKey = '';
  let listRequestVersion = 0;

  async function syncURL(): Promise<boolean> {
    const url = new URL($pageStore.url);
    if (search) url.searchParams.set('q', search);
    else url.searchParams.delete('q');
    if (currentPage > 1) url.searchParams.set('page', String(currentPage));
    else url.searchParams.delete('page');
    const target = `${url.pathname}${url.search}${url.hash}`;
    const current = `${$pageStore.url.pathname}${$pageStore.url.search}${$pageStore.url.hash}`;
    if (target === current) return false;
    await goto(target, { replaceState: true, noScroll: true, keepFocus: true });
    return true;
  }

  async function loadUsers() {
    const requestVersion = ++listRequestVersion;
    loading = true;
    pageError = '';
    try {
      const response = await api.admin.getUsers(currentPage, pageSize, search);
      if (requestVersion !== listRequestVersion) return;
      users = response.items;
      total = response.total;
      if (currentPage > Math.max(1, response.total_pages)) {
        currentPage = Math.max(1, response.total_pages);
        await syncURL();
        return;
      }
    } catch (cause) {
      if (requestVersion === listRequestVersion) pageError = cause instanceof Error ? cause.message : '用户列表加载失败';
    } finally {
      if (requestVersion === listRequestVersion) loading = false;
    }
  }

  function applyURLState(url: URL) {
    const key = `${url.pathname}${url.search}${url.hash}`;
    if (key === currentURLKey) return;
    currentURLKey = key;
    currentPage = Math.max(1, Number(url.searchParams.get('page')) || 1);
    search = url.searchParams.get('q') || '';
    void loadUsers();
  }

  function scheduleSearch() {
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(async () => {
      currentPage = 1;
      await syncURL();
    }, 300);
  }

  async function changePage(nextPage: number) {
    currentPage = nextPage;
    await syncURL();
  }

  async function handleCreate(event: SubmitEvent) {
    event.preventDefault();
    createError = '';
    const policyError = passwordPolicyError(newUser.password);
    if (policyError) {
      createError = policyError;
      return;
    }
    creating = true;
    try {
      await api.admin.createUser(newUser);
      showCreate = false;
      newUser = { username: '', email: '', password: '', display_name: '' };
      currentPage = 1;
      if (!(await syncURL())) await loadUsers();
    } catch (cause) {
      createError = cause instanceof Error ? cause.message : '创建失败';
    } finally {
      creating = false;
    }
  }

  function sessionDeviceLabel(userAgent = ''): string {
    const browser = /Edg\//.test(userAgent) ? 'Edge' : /Firefox\//.test(userAgent) ? 'Firefox' : /Chrome\//.test(userAgent) ? 'Chrome' : /Safari\//.test(userAgent) ? 'Safari' : '未知浏览器';
    const system = /Windows/.test(userAgent) ? 'Windows' : /Android/.test(userAgent) ? 'Android' : /iPhone|iPad/.test(userAgent) ? 'iOS' : /Mac OS/.test(userAgent) ? 'macOS' : /Linux/.test(userAgent) ? 'Linux' : '未知系统';
    return `${browser} · ${system}`;
  }

  async function loadUserIdentities(userID: string) {
    userIdentities = [];
    identitiesError = '';
    identitiesLoading = true;
    try {
      const result = await api.admin.getUserIdentities(userID);
      if (selectedUser?.id === userID) userIdentities = result;
    } catch (cause) {
      if (selectedUser?.id === userID) identitiesError = cause instanceof Error ? cause.message : '外部身份加载失败';
    } finally {
      if (selectedUser?.id === userID) identitiesLoading = false;
    }
  }

  async function loadUserSessions(userID: string) {
    userSessions = [];
    sessionsError = '';
    sessionsLoading = true;
    try {
      const result = await api.admin.getUserSessions(userID);
      if (selectedUser?.id === userID) userSessions = result;
    } catch (cause) {
      if (selectedUser?.id === userID) sessionsError = cause instanceof Error ? cause.message : '设备会话加载失败';
    } finally {
      if (selectedUser?.id === userID) sessionsLoading = false;
    }
  }

  async function openDrawer(user: User) {
    selectedUser = user;
    selectedRole = user.role;
    roleError = '';
    profileForm = {
      email: user.email || '',
      display_name: user.display_name || '',
      avatar_url: user.avatar_url || '',
      metadata: formatStringMetadata(user.metadata),
    };
    profileError = '';
    profileNotice = '';
    identitiesNotice = '';
    identityTarget = null;
    identityConfirmOpen = false;
    identityConfirmError = '';
    sessionsNotice = '';
    resetPasswordValue = '';
    resetPasswordConfirmation = '';
    passwordResetError = '';
    passwordResetComplete = false;
    drawerOpen = true;
    await Promise.all([loadUserIdentities(user.id), loadUserSessions(user.id)]);
  }

  async function saveProfile(event: SubmitEvent) {
    event.preventDefault();
    if (!selectedUser) return;
    profileError = '';
    profileNotice = '';

    let metadata: Record<string, string>;
    try {
      metadata = parseStringMetadata(profileForm.metadata);
    } catch (cause) {
      profileError = cause instanceof Error ? cause.message : 'Metadata 格式无效。';
      return;
    }

    profileSaving = true;
    try {
      const updated = await api.admin.updateUser(selectedUser.id, {
        email: profileForm.email.trim(),
        display_name: profileForm.display_name.trim(),
        avatar_url: profileForm.avatar_url.trim(),
        metadata,
      });
      selectedUser = updated;
      users = users.map((user) => user.id === updated.id ? updated : user);
      profileForm = {
        email: updated.email || '',
        display_name: updated.display_name || '',
        avatar_url: updated.avatar_url || '',
        metadata: formatStringMetadata(updated.metadata),
      };
      profileNotice = '用户资料已更新。';
    } catch (cause) {
      profileError = cause instanceof Error ? cause.message : '用户资料更新失败';
    } finally {
      profileSaving = false;
    }
  }

  function requestIdentityRemoval(identity: ExternalIdentity) {
    identityTarget = identity;
    identityConfirmError = '';
    identityConfirmOpen = true;
  }

  async function removeIdentity() {
    const user = selectedUser;
    const identity = identityTarget;
    if (!user || !identity) return;
    identityConfirmError = '';
    identitiesNotice = '';
    try {
      await api.admin.deleteUserIdentity(user.id, identity.id);
      if (selectedUser?.id === user.id) {
        userIdentities = userIdentities.filter((item) => item.id !== identity.id);
        identitiesNotice = `已解绑 ${identity.provider} 身份。`;
      }
      identityTarget = null;
    } catch (cause) {
      identityConfirmError = cause instanceof Error ? cause.message : '外部身份解绑失败';
      throw cause;
    }
  }

  async function handlePasswordReset(event: SubmitEvent) {
    event.preventDefault();
    if (!selectedUser) return;
    passwordResetError = '';
    passwordResetComplete = false;
    const policyError = passwordPolicyError(resetPasswordValue);
    if (policyError) {
      passwordResetError = policyError;
      return;
    }
    if (resetPasswordValue !== resetPasswordConfirmation) {
      passwordResetError = '两次输入的新密码不一致。';
      return;
    }
    passwordResetting = true;
    try {
      await api.admin.resetPassword(selectedUser.id, resetPasswordValue);
      resetPasswordValue = '';
      resetPasswordConfirmation = '';
      passwordResetComplete = true;
    } catch (cause) {
      passwordResetError = cause instanceof Error ? cause.message : '密码重置失败';
    } finally {
      passwordResetting = false;
    }
  }

  async function saveRole() {
    if (!selectedUser || selectedRole === selectedUser.role) return;
    roleSaving = true;
    roleError = '';
    try {
      const updated = await api.admin.updateUserRole(selectedUser.id, selectedRole);
      selectedUser = updated;
      users = users.map((user) => user.id === updated.id ? updated : user);
    } catch (cause) {
      roleError = cause instanceof Error ? cause.message : '角色更新失败';
      selectedRole = selectedUser.role;
    } finally {
      roleSaving = false;
    }
  }

  async function activateUser(user: User) {
    pageError = '';
    try {
      const updated = await api.admin.activateUser(user.id);
      users = users.map((item) => item.id === updated.id ? updated : item);
      if (selectedUser?.id === updated.id) selectedUser = updated;
    } catch (cause) {
      pageError = cause instanceof Error ? cause.message : '解封失败';
    }
  }

  function requestConfirmation(kind: 'delete' | 'suspend' | 'revoke-sessions', user: User) {
    confirmError = '';
    confirmAction = { kind, user };
    confirmOpen = true;
  }

  async function runConfirmedAction() {
    const action = confirmAction;
    if (!action) return;
    confirmError = '';
    try {
      if (action.kind === 'delete') {
        await api.admin.deleteUser(action.user.id);
        drawerOpen = false;
      } else if (action.kind === 'suspend') {
        const updated = await api.admin.suspendUser(action.user.id);
        if (selectedUser?.id === updated.id) selectedUser = updated;
      } else {
        const result = await api.admin.revokeUserSessions(action.user.id);
        if (selectedUser?.id === action.user.id) {
          userSessions = [];
          sessionsNotice = `已撤销 ${result.revoked} 个设备会话。`;
        }
      }
      if (action.kind !== 'revoke-sessions') await loadUsers();
    } catch (cause) {
      confirmError = cause instanceof Error ? cause.message : '操作失败';
      throw cause;
    }
  }

  onMount(() => pageStore.subscribe(({ url }) => applyURLState(url)));
  onDestroy(() => {
    if (searchTimer) clearTimeout(searchTimer);
  });
</script>

<svelte:head><title>用户管理 - Nya</title></svelte:head>

<PageHeader title="用户管理" description="管理用户、登录方式、角色和账户状态">
  {#snippet action()}<Button variant="primary" onclick={() => (showCreate = true)}><Plus size={16} /> 创建用户</Button>{/snippet}
</PageHeader>

<div class="mb-4 flex max-w-md items-end gap-2">
  <div class="flex-1"><Input id="user-search" label="搜索" placeholder="用户名或邮箱" bind:value={search} oninput={scheduleSearch} /></div>
  <Button variant="secondary" onclick={loadUsers} ariaLabel="立即搜索"><Search size={16} /></Button>
</div>

<ResourceState
  {loading}
  error={pageError}
  empty={users.length === 0}
  emptyTitle={search ? '没有匹配的用户' : '暂无用户'}
  emptyDescription={search ? '请尝试调整搜索关键词。' : '创建第一个用户后即可开始使用。'}
  onretry={loadUsers}
>
  {#snippet emptyAction()}
    {#if !search}<Button variant="primary" onclick={() => (showCreate = true)}>创建用户</Button>{/if}
  {/snippet}
  {#snippet children()}
    <div class="overflow-hidden rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
      <div class="overflow-x-auto">
        <table class="w-full">
          <thead><tr class="h-11 border-b border-nya-divider bg-nya-surface-subtle text-small font-semibold text-nya-text-secondary"><th scope="col" class="px-4 text-left">用户名</th><th scope="col" class="px-4 text-left">邮箱</th><th scope="col" class="px-4 text-left">角色</th><th scope="col" class="px-4 text-left">状态</th><th scope="col" class="px-4 text-left">最后登录</th><th scope="col" class="px-4 text-right">操作</th></tr></thead>
          <tbody class="divide-y divide-nya-divider">
            {#each users as user}
              <tr class="h-[52px] hover:bg-nya-surface-muted">
                <td class="px-4"><button type="button" onclick={() => openDrawer(user)} class="font-medium text-nya-text-primary hover:text-nya-primary hover:underline">{user.username}</button></td>
                <td class="px-4 text-body text-nya-text-secondary">{user.email || '-'}</td>
                <td class="px-4"><Badge variant={user.role === 'admin' ? 'pink' : 'default'}>{user.role === 'admin' ? '管理员' : '用户'}</Badge></td>
                <td class="px-4"><Badge variant={(statusMap[user.status] || statusMap.pending).variant}>{(statusMap[user.status] || { label: user.status }).label}</Badge></td>
                <td class="px-4 text-small text-nya-text-tertiary">{user.last_login_at ? new Date(user.last_login_at).toLocaleString() : '从未登录'}</td>
                <td class="px-4"><div class="flex justify-end gap-1">
                  {#if user.status === 'active'}
                    <button type="button" onclick={() => requestConfirmation('suspend', user)} class="rounded-lg p-1.5 text-nya-warning hover:bg-nya-warning-soft" aria-label={`封禁用户 ${user.username}`} title="封禁"><Ban size={15} /></button>
                  {:else}
                    <button type="button" onclick={() => activateUser(user)} class="rounded-lg p-1.5 text-nya-success hover:bg-nya-success-soft" aria-label={`解封用户 ${user.username}`} title="解封"><CheckCircle size={15} /></button>
                  {/if}
                  <button type="button" onclick={() => requestConfirmation('delete', user)} class="rounded-lg p-1.5 text-nya-danger hover:bg-nya-danger-soft" aria-label={`删除用户 ${user.username}`} title="删除"><Trash2 size={15} /></button>
                </div></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <Pagination bind:page={currentPage} {pageSize} {total} onchange={changePage} />
    </div>
  {/snippet}
</ResourceState>

<Drawer bind:open={drawerOpen} title={selectedUser ? `用户详情 · ${selectedUser.username}` : '用户详情'} width="520px">
  {#if selectedUser}
    <div class="space-y-6">
      <div class="flex items-center gap-4">
        <span class="flex h-14 w-14 items-center justify-center overflow-hidden rounded-full bg-nya-primary-soft text-xl font-semibold text-nya-primary">{#if selectedUser.avatar_url}<img src={selectedUser.avatar_url} alt="" class="h-full w-full object-cover" />{:else}{selectedUser.username.slice(0, 1).toUpperCase()}{/if}</span>
        <div><h3 class="text-lg font-semibold text-nya-text-primary">{selectedUser.display_name || selectedUser.username}</h3><p class="text-body text-nya-text-secondary">@{selectedUser.username}</p></div>
      </div>

      <section class="rounded-nya-sm bg-nya-surface-muted p-4">
        {#if roleError}<p class="mb-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{roleError}</p>{/if}
        <div class="flex items-end gap-3"><div class="min-w-0 flex-1"><Select id="user-role" label="角色" bind:value={selectedRole} options={[{ value: 'user', label: '用户' }, { value: 'admin', label: '管理员' }]} /></div><Button variant="secondary" size="sm" onclick={saveRole} loading={roleSaving} disabled={selectedRole === selectedUser.role}><Shield size={15} /> 保存角色</Button></div>
      </section>

      <section class="rounded-nya-sm border border-nya-border p-4">
        <h3 class="font-semibold text-nya-text-primary">基本资料</h3>
        <p class="mb-3 mt-1 text-small text-nya-text-secondary">更新用户的联系方式、展示信息和管理 metadata。</p>
        {#if profileError}<p class="mb-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{profileError}</p>{/if}
        {#if profileNotice}<p class="mb-3 rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">{profileNotice}</p>{/if}
        <form onsubmit={saveProfile} class="space-y-3">
          <Input id="admin-user-email" label="邮箱" type="email" bind:value={profileForm.email} autocomplete="email" placeholder="可选" />
          <Input id="admin-user-display-name" label="显示名称" bind:value={profileForm.display_name} placeholder="可选" />
          <Input id="admin-user-avatar-url" label="头像 URL" type="url" bind:value={profileForm.avatar_url} placeholder="https://example.com/avatar.png" />
          <div><label for="admin-user-metadata" class="mb-1.5 block text-body-medium text-nya-text-primary">Metadata（JSON 字符串键值）</label><textarea id="admin-user-metadata" bind:value={profileForm.metadata} rows="5" spellcheck="false" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea></div>
          <div class="flex justify-end"><Button type="submit" variant="primary" size="sm" loading={profileSaving}>保存资料</Button></div>
        </form>
      </section>

      <dl class="divide-y divide-nya-divider text-body">
        <div class="flex justify-between gap-4 py-2.5"><dt class="text-nya-text-tertiary">邮箱</dt><dd class="text-right">{selectedUser.email || '未设置'}</dd></div>
        <div class="flex justify-between gap-4 py-2.5"><dt class="text-nya-text-tertiary">状态</dt><dd>{(statusMap[selectedUser.status] || { label: selectedUser.status }).label}</dd></div>
        <div class="flex justify-between gap-4 py-2.5"><dt class="text-nya-text-tertiary">最后登录</dt><dd class="text-right">{selectedUser.last_login_at ? new Date(selectedUser.last_login_at).toLocaleString() : '从未登录'}</dd></div>
        <div class="flex justify-between gap-4 py-2.5"><dt class="text-nya-text-tertiary">登录 IP</dt><dd class="font-mono">{selectedUser.last_login_ip || '-'}</dd></div>
        <div class="flex justify-between gap-4 py-2.5"><dt class="text-nya-text-tertiary">创建时间</dt><dd class="text-right">{new Date(selectedUser.created_at).toLocaleString()}</dd></div>
      </dl>

      <section><h3 class="mb-2 flex items-center gap-2 text-body-medium font-semibold text-nya-text-primary"><KeyRound size={16} class="text-nya-primary" /> 外部身份</h3>
        {#if identitiesNotice}<p class="mb-2 rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">{identitiesNotice}</p>{/if}
        {#if identitiesLoading}<p class="rounded-nya-sm bg-nya-surface-muted p-3 text-body text-nya-text-tertiary">加载中…</p>
        {:else if identitiesError}<div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft p-3"><p class="text-small text-nya-danger">{identitiesError}</p><Button variant="ghost" size="sm" onclick={() => selectedUser && loadUserIdentities(selectedUser.id)}>重试</Button></div>
        {:else if userIdentities.length === 0}<p class="rounded-nya-sm bg-nya-surface-muted p-3 text-body text-nya-text-tertiary">未绑定外部身份</p>
        {:else}<div class="space-y-2">{#each userIdentities as identity}<div class="flex items-center gap-3 rounded-nya-sm bg-nya-surface-muted p-3"><Badge variant="info">{identity.provider}</Badge><span class="min-w-0 flex-1 truncate text-body">{identity.external_username || identity.external_id}</span><Button variant="ghost" size="sm" ariaLabel={`解绑 ${identity.provider} 身份`} onclick={() => requestIdentityRemoval(identity)}><Trash2 size={14} /> 解绑</Button></div>{/each}</div>{/if}
      </section>

      <section>
        <div class="mb-2 flex items-center justify-between gap-3"><h3 class="flex items-center gap-2 text-body-medium font-semibold text-nya-text-primary"><MonitorSmartphone size={16} class="text-nya-primary" /> 设备会话</h3>{#if !sessionsLoading && userSessions.length > 0}<Button variant="secondary" size="sm" onclick={() => selectedUser && requestConfirmation('revoke-sessions', selectedUser)}><LogOut size={14} /> 全部撤销</Button>{/if}</div>
        {#if sessionsNotice}<p class="mb-2 rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">{sessionsNotice}</p>{/if}
        {#if sessionsLoading}<p class="rounded-nya-sm bg-nya-surface-muted p-3 text-body text-nya-text-tertiary">正在加载设备会话…</p>
        {:else if sessionsError}<div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft p-3"><p class="text-small text-nya-danger">{sessionsError}</p><Button variant="ghost" size="sm" onclick={() => selectedUser && loadUserSessions(selectedUser.id)}>重试</Button></div>
        {:else if userSessions.length === 0}<p class="rounded-nya-sm bg-nya-surface-muted p-3 text-body text-nya-text-tertiary">没有活动设备会话。</p>
        {:else}<div class="divide-y divide-nya-divider rounded-nya-sm bg-nya-surface-muted px-3">{#each userSessions as item}<div class="py-3"><div class="flex items-center justify-between gap-3"><p class="font-medium text-nya-text-primary">{sessionDeviceLabel(item.user_agent)}</p><span class="font-mono text-micro text-nya-text-tertiary">{item.ip_address || 'IP 未知'}</span></div><p class="mt-1 text-small text-nya-text-tertiary">最后活动 {new Date(item.last_seen_at).toLocaleString()}</p><p class="mt-0.5 truncate text-micro text-nya-text-tertiary" title={item.user_agent}>{item.user_agent || '未提供 User-Agent'}</p></div>{/each}</div>{/if}
      </section>

      <section class="rounded-nya-sm border border-nya-border p-4">
        <h3 class="flex items-center gap-2 font-semibold text-nya-text-primary"><KeyRound size={16} class="text-nya-primary" /> 重置密码</h3>
        <p class="mb-3 mt-1 text-small text-nya-text-secondary">设置临时密码后，该用户的旧会话和令牌会立即失效。</p>
        {#if passwordResetError}<p class="mb-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{passwordResetError}</p>{/if}
        {#if passwordResetComplete}<p class="mb-3 rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">密码已重置。请通过安全渠道将临时密码交给用户。</p>{/if}
        <form onsubmit={handlePasswordReset} class="space-y-3">
          <div><Input id="admin-reset-password" label="新密码" type="password" bind:value={resetPasswordValue} autocomplete="new-password" required /><p class="mt-1.5 text-small text-nya-text-tertiary">{PASSWORD_REQUIREMENT}</p></div>
          <Input id="admin-reset-password-confirmation" label="确认新密码" type="password" bind:value={resetPasswordConfirmation} autocomplete="new-password" required />
          <Button type="submit" variant="secondary" size="sm" loading={passwordResetting}>重置密码</Button>
        </form>
      </section>

      <DangerZone description="删除用户会立即使其会话和令牌失效，且无法恢复。">
        {#snippet children()}<Button variant="danger" size="sm" onclick={() => selectedUser && requestConfirmation('delete', selectedUser)}><Trash2 size={15} /> 删除此用户</Button>{/snippet}
      </DangerZone>
    </div>
  {/if}
</Drawer>

<Modal bind:open={showCreate} title="创建用户" description="新用户可以使用用户名和本地密码登录" size="sm">
  <form onsubmit={handleCreate} class="space-y-4">
    {#if createError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{createError}</p>{/if}
    <Input id="create-username" label="用户名" bind:value={newUser.username} required autocomplete="username" placeholder="3–64 位字母、数字或 ._-" />
    <Input id="create-email" label="邮箱" type="email" bind:value={newUser.email} autocomplete="email" placeholder="可选" />
    <div><Input id="create-password" label="密码" type="password" bind:value={newUser.password} required autocomplete="new-password" placeholder="12–1024 字节" /><p class="mt-1.5 text-small text-nya-text-tertiary">{PASSWORD_REQUIREMENT}</p></div>
    <Input id="create-display-name" label="显示名称" bind:value={newUser.display_name} placeholder="可选" />
    <div class="flex justify-end gap-2 pt-2"><Button variant="secondary" onclick={() => (showCreate = false)} disabled={creating}>取消</Button><Button type="submit" variant="primary" loading={creating}>创建</Button></div>
  </form>
</Modal>

<ConfirmDialog
  bind:open={confirmOpen}
  title={confirmAction?.kind === 'delete' ? '删除用户' : confirmAction?.kind === 'revoke-sessions' ? '撤销全部设备会话' : '封禁用户'}
  description={confirmAction?.kind === 'delete' ? `删除后，用户“${confirmAction?.user.username || ''}”的所有会话和令牌会立即失效，且无法恢复。` : confirmAction?.kind === 'revoke-sessions' ? `用户“${confirmAction?.user.username || ''}”需要在所有设备上重新登录。` : `封禁后，用户“${confirmAction?.user.username || ''}”将无法继续登录。`}
  confirmLabel={confirmAction?.kind === 'delete' ? '永久删除' : confirmAction?.kind === 'revoke-sessions' ? '全部撤销' : '确认封禁'}
  confirmationText={confirmAction?.kind === 'delete' ? confirmAction?.user.username || '' : ''}
  error={confirmError}
  onconfirm={runConfirmedAction}
/>

<ConfirmDialog
  bind:open={identityConfirmOpen}
  title="解绑外部身份"
  description={`解绑“${identityTarget?.provider || ''}”后，该用户将无法再使用此身份登录，现有会话和令牌也会失效。`}
  confirmLabel="确认解绑"
  confirmationText={identityTarget?.provider || ''}
  error={identityConfirmError}
  onconfirm={removeIdentity}
/>
