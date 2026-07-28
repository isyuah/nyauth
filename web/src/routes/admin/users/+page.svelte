<script lang="ts">
  import { goto } from '$app/navigation';
  import { page as pageStore } from '$app/stores';
  import { onDestroy, onMount } from 'svelte';
  import { api, type User } from '$lib/api';
  import { PASSWORD_REQUIREMENT, passwordPolicyError } from '$lib/password-policy';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import Pagination from '$lib/components/data-display/Pagination.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import { ChevronRight, Plus, Search } from 'lucide-svelte';

  const pageSize = 20;
  const statusMap: Record<string, { label: string; variant: 'success' | 'danger' | 'warning' | 'default' }> = {
    active: { label: '正常', variant: 'success' }, suspended: { label: '已封禁', variant: 'danger' }, pending: { label: '待验证', variant: 'warning' },
  };
  let users = $state<User[]>([]);
  let total = $state(0);
  let currentPage = $state(Math.max(1, Number($pageStore.url.searchParams.get('page')) || 1));
  let search = $state($pageStore.url.searchParams.get('q') || '');
  let loading = $state(true);
  let error = $state('');
  let showCreate = $state(false);
  let creating = $state(false);
  let newUser = $state({ username: '', email: '', password: '', display_name: '' });
  let createError = $state('');
  let searchTimer: ReturnType<typeof setTimeout> | undefined;
  let currentURLKey = '';
  let requestVersion = 0;

  function currentListPath(): string {
    return `${$pageStore.url.pathname}${$pageStore.url.search}${$pageStore.url.hash}`;
  }

  function detailHref(user: User): string {
    return `/admin/users/${encodeURIComponent(user.id)}?return_to=${encodeURIComponent(currentListPath())}`;
  }

  async function syncURL(): Promise<boolean> {
    const url = new URL($pageStore.url);
    if (search) url.searchParams.set('q', search); else url.searchParams.delete('q');
    if (currentPage > 1) url.searchParams.set('page', String(currentPage)); else url.searchParams.delete('page');
    const target = `${url.pathname}${url.search}${url.hash}`;
    if (target === currentListPath()) return false;
    await goto(target, { replaceState: true, noScroll: true, keepFocus: true });
    return true;
  }

  async function loadUsers() {
    const version = ++requestVersion;
    loading = true;
    error = '';
    try {
      const response = await api.admin.getUsers(currentPage, pageSize, search);
      if (version !== requestVersion) return;
      users = response.items;
      total = response.total;
      if (currentPage > Math.max(1, response.total_pages)) {
        currentPage = Math.max(1, response.total_pages);
        await syncURL();
      }
    } catch (cause) {
      if (version === requestVersion) error = cause instanceof Error ? cause.message : '用户列表加载失败';
    } finally {
      if (version === requestVersion) loading = false;
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
    searchTimer = setTimeout(async () => { currentPage = 1; await syncURL(); }, 300);
  }

  async function changePage(nextPage: number) {
    currentPage = nextPage;
    await syncURL();
  }

  async function handleCreate(event: SubmitEvent) {
    event.preventDefault();
    createError = '';
    const policyError = passwordPolicyError(newUser.password);
    if (policyError) { createError = policyError; return; }
    creating = true;
    try {
      const created = await api.admin.createUser(newUser);
      showCreate = false;
      newUser = { username: '', email: '', password: '', display_name: '' };
      await goto(detailHref(created));
    } catch (cause) {
      createError = cause instanceof Error ? cause.message : '创建失败';
    } finally {
      creating = false;
    }
  }

  onMount(() => pageStore.subscribe(({ url }) => applyURLState(url)));
  onDestroy(() => { if (searchTimer) clearTimeout(searchTimer); });
</script>

<svelte:head><title>用户管理 - Nya</title></svelte:head>
<PageHeader title="用户管理" description="搜索用户并进入独立详情页查看资料、安全状态、会话与活动">
  {#snippet action()}<Button variant="primary" requiredCapability="admin_mutations" onclick={() => (showCreate = true)}><Plus size={16} /> 创建用户</Button>{/snippet}
</PageHeader>

<div class="mb-4 flex max-w-md items-end gap-2"><div class="flex-1"><Input id="user-search" label="搜索" placeholder="用户名或邮箱" bind:value={search} oninput={scheduleSearch} /></div><Button variant="secondary" onclick={loadUsers} ariaLabel="立即搜索"><Search size={16} /></Button></div>

<ResourceState {loading} {error} empty={users.length === 0} emptyTitle={search ? '没有匹配的用户' : '暂无用户'} emptyDescription={search ? '请尝试调整搜索关键词。' : '创建第一个用户后即可开始使用。'} onretry={loadUsers}>
  {#snippet emptyAction()}{#if !search}<Button variant="primary" requiredCapability="admin_mutations" onclick={() => (showCreate = true)}>创建用户</Button>{/if}{/snippet}
  {#snippet children()}
    <div class="overflow-hidden rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
      <div class="overflow-x-auto"><table class="w-full"><thead><tr class="h-11 border-b border-nya-divider bg-nya-surface-subtle text-small font-semibold text-nya-text-secondary"><th class="px-4 text-left">用户</th><th class="px-4 text-left">邮箱</th><th class="px-4 text-left">角色</th><th class="px-4 text-left">状态</th><th class="px-4 text-left">最后登录</th><th class="px-4 text-right">详情</th></tr></thead><tbody class="divide-y divide-nya-divider">{#each users as user}<tr class="h-[58px] hover:bg-nya-surface-muted"><td class="px-4"><a href={detailHref(user)} class="flex items-center gap-3 font-medium text-nya-text-primary hover:text-nya-primary"><span class="flex h-8 w-8 items-center justify-center overflow-hidden rounded-full bg-nya-primary-soft text-small font-semibold text-nya-primary">{#if user.avatar_url}<img src={user.avatar_url} alt="" class="h-full w-full object-cover" />{:else}{user.username.slice(0, 1).toUpperCase()}{/if}</span><span><span class="block">{user.display_name || user.username}</span><span class="block text-micro font-normal text-nya-text-tertiary">@{user.username}</span></span></a></td><td class="px-4 text-body text-nya-text-secondary">{user.email || '-'}</td><td class="px-4"><Badge variant={user.role === 'admin' ? 'pink' : 'default'}>{user.role === 'admin' ? '管理员' : '用户'}</Badge></td><td class="px-4"><Badge variant={(statusMap[user.status] || statusMap.pending).variant}>{(statusMap[user.status] || { label: user.status }).label}</Badge></td><td class="px-4 text-small text-nya-text-tertiary">{user.last_login_at ? new Date(user.last_login_at).toLocaleString() : '从未登录'}</td><td class="px-4 text-right"><a href={detailHref(user)} class="inline-flex rounded-lg p-2 text-nya-text-tertiary hover:bg-nya-primary-soft hover:text-nya-primary" aria-label={`查看用户 ${user.username}`}><ChevronRight size={17} /></a></td></tr>{/each}</tbody></table></div>
      <Pagination bind:page={currentPage} {pageSize} {total} onchange={changePage} />
    </div>
  {/snippet}
</ResourceState>

<Modal bind:open={showCreate} title="创建用户" description="新用户可以使用用户名和本地密码登录" size="sm">
  <form onsubmit={handleCreate} class="space-y-4">
    {#if createError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{createError}</p>{/if}
    <Input id="create-username" label="用户名" bind:value={newUser.username} required autocomplete="username" placeholder="3–64 位字母、数字或 ._-" />
    <Input id="create-email" label="邮箱" type="email" bind:value={newUser.email} autocomplete="email" placeholder="可选" />
    <div><Input id="create-password" label="密码" type="password" bind:value={newUser.password} required autocomplete="new-password" placeholder="12–1024 字节" /><p class="mt-1.5 text-small text-nya-text-tertiary">{PASSWORD_REQUIREMENT}</p></div>
    <Input id="create-display-name" label="显示名称" bind:value={newUser.display_name} placeholder="可选" />
    <div class="flex justify-end gap-2 pt-2"><Button variant="secondary" onclick={() => (showCreate = false)} disabled={creating}>取消</Button><Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={creating}>创建</Button></div>
  </form>
</Modal>
