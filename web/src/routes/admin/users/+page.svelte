<script lang="ts">
  import { api } from '$lib/api';
  import { onMount } from 'svelte';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import Drawer from '$lib/components/ui/Drawer.svelte';
  import Select from '$lib/components/ui/Select.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import EmptyState from '$lib/components/ui/EmptyState.svelte';
  import { Plus, Search, Users, Shield, Ban, CheckCircle, KeyRound } from 'lucide-svelte';

  let users = $state<any[]>([]);
  let total = $state(0);
  let page = $state(1);
  let search = $state('');
  let loading = $state(false);
  let showCreate = $state(false);
  let newUser = $state({ username: '', email: '', password: '', display_name: '' });
  let createError = $state('');

  // Drawer state
  let drawerOpen = $state(false);
  let selectedUser = $state<any>(null);
  let userIdentities = $state<any[]>([]);

  onMount(() => loadUsers());

  async function loadUsers() {
    loading = true;
    try {
      const res = await api.admin.getUsers(page, 20, search);
      users = res.items || [];
      total = res.total || 0;
    } catch {} finally { loading = false; }
  }

  async function handleCreate(e: Event) {
    e.preventDefault();
    createError = '';
    try {
      await api.admin.createUser(newUser);
      showCreate = false;
      newUser = { username: '', email: '', password: '', display_name: '' };
      loadUsers();
    } catch (err) { createError = err instanceof Error ? err.message : '创建失败'; }
  }

  async function handleDelete(id: string) {
    if (!confirm('确定要删除此用户吗？此操作不可恢复。')) return;
    try { await api.admin.deleteUser(id); loadUsers(); } catch {}
  }

  async function handleSuspend(id: string) {
    if (!confirm('确定要封禁此用户吗？')) return;
    try { await api.admin.suspendUser(id); loadUsers(); if (selectedUser?.id === id) openDrawer(selectedUser); } catch {}
  }

  async function handleActivate(id: string) {
    try { await api.admin.activateUser(id); loadUsers(); if (selectedUser?.id === id) openDrawer(selectedUser); } catch {}
  }

  async function handleRoleChange(id: string, role: string) {
    try { await api.admin.updateUserRole(id, role); loadUsers(); if (selectedUser?.id === id) openDrawer(selectedUser); } catch {}
  }

  async function openDrawer(user: any) {
    selectedUser = user;
    drawerOpen = true;
    try { userIdentities = await api.admin.getUserIdentities(user.id); } catch { userIdentities = []; }
  }

  const statusMap: Record<string, { label: string; variant: 'success' | 'danger' | 'warning' }> = {
    active: { label: '正常', variant: 'success' },
    suspended: { label: '已封禁', variant: 'danger' },
    pending: { label: '待验证', variant: 'warning' },
  };
</script>

<svelte:head><title>用户管理 - Nya</title></svelte:head>

<PageHeader title="用户管理" description="管理系统用户、登录方式与状态">
  {#snippet action()}
    <Button variant="primary" onclick={() => (showCreate = true)}><Plus size={16} /> 创建用户</Button>
  {/snippet}
</PageHeader>

<div class="mb-4 flex gap-3 flex-wrap">
  <div class="flex-1" style="min-width: 200px; max-width: 320px;">
    <Input placeholder="搜索用户名或邮箱..." bind:value={search} />
  </div>
  <Button variant="secondary" onclick={loadUsers}><Search size={16} /></Button>
</div>

<div class="bg-[var(--nya-surface)] border border-[var(--nya-border)] overflow-hidden" style="border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card);">
  {#if loading && users.length === 0}
    <div class="py-12 text-center" style="color: var(--nya-text-tertiary);">加载中...</div>
  {:else if users.length === 0}
    <EmptyState title="暂无用户" description="创建第一个用户后即可开始使用">
      {#snippet icon()}<Users size={48} />{/snippet}
      {#snippet action()}<Button variant="primary" onclick={() => (showCreate = true)}>创建用户</Button>{/snippet}
    </EmptyState>
  {:else}
    <div class="overflow-x-auto">
      <table class="w-full">
        <thead>
          <tr style="height: 44px; background: var(--nya-surface-subtle); border-bottom: 1px solid var(--nya-divider);">
            <th class="text-left px-4" style="font-size: 12px; font-weight: 600; color: var(--nya-text-secondary);">用户名</th>
            <th class="text-left px-4" style="font-size: 12px; font-weight: 600; color: var(--nya-text-secondary);">邮箱</th>
            <th class="text-left px-4" style="font-size: 12px; font-weight: 600; color: var(--nya-text-secondary);">角色</th>
            <th class="text-left px-4" style="font-size: 12px; font-weight: 600; color: var(--nya-text-secondary);">状态</th>
            <th class="text-left px-4" style="font-size: 12px; font-weight: 600; color: var(--nya-text-secondary);">最后登录</th>
            <th class="text-right px-4" style="font-size: 12px; font-weight: 600; color: var(--nya-text-secondary);">操作</th>
          </tr>
        </thead>
        <tbody>
          {#each users as u}
            <tr class="cursor-pointer" style="height: 52px; border-bottom: 1px solid var(--nya-divider);" onclick={(e) => { e.stopPropagation(); openDrawer(u); }}>
              <td class="px-4" style="font-size: 13px; font-weight: 500;">{u.username}</td>
              <td class="px-4" style="font-size: 13px; color: var(--nya-text-secondary);">{u.email || '-'}</td>
              <td class="px-4">
                <Badge variant={u.role === 'admin' ? 'pink' : 'default'}>{u.role === 'admin' ? '管理员' : '用户'}</Badge>
              </td>
              <td class="px-4">
                <Badge variant={(statusMap[u.status] || { variant: 'default' }).variant}>{(statusMap[u.status] || { label: u.status }).label}</Badge>
              </td>
              <td class="px-4" style="font-size: 12px; color: var(--nya-text-tertiary);">
                {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : '从未登录'}
              </td>
              <td class="px-4 text-right">
                <div class="flex gap-1 justify-end" onclick={(e) => e.stopPropagation()}>
                  {#if u.status === 'active'}
                    <button onclick={() => handleSuspend(u.id)} class="p-1.5 rounded-lg hover:bg-[var(--nya-warning-soft)]" title="封禁">
                      <Ban size={14} style="color: var(--nya-warning);" />
                    </button>
                  {:else}
                    <button onclick={() => handleActivate(u.id)} class="p-1.5 rounded-lg hover:bg-[var(--nya-success-soft)]" title="解封">
                      <CheckCircle size={14} style="color: var(--nya-success);" />
                    </button>
                  {/if}
                  <button onclick={() => handleDelete(u.id)} class="p-1.5 rounded-lg hover:bg-[var(--nya-danger-soft)]" title="删除">
                    <span style="font-size: 12px; color: var(--nya-danger);">删除</span>
                  </button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if total > 20}
      <div class="flex items-center justify-between px-4 py-3" style="border-top: 1px solid var(--nya-divider); font-size: 12px; color: var(--nya-text-secondary);">
        <span>共 {total} 个用户</span>
        <div class="flex gap-2">
          <button disabled={page <= 1} onclick={() => { page--; loadUsers(); }} class="px-2 py-1 rounded hover:bg-[var(--nya-surface-muted)] disabled:opacity-40">上一页</button>
          <span>{page}</span>
          <button disabled={page * 20 >= total} onclick={() => { page++; loadUsers(); }} class="px-2 py-1 rounded hover:bg-[var(--nya-surface-muted)] disabled:opacity-40">下一页</button>
        </div>
      </div>
    {/if}
  {/if}
</div>

<!-- 用户详情 Drawer -->
<Drawer bind:open={drawerOpen} title={selectedUser ? `用户详情 - ${selectedUser.username}` : '用户详情'} width="520px">
  {#if selectedUser}
    <div class="space-y-5">
      <!-- 基本信息 -->
      <div class="flex items-center gap-4">
        <div class="flex items-center justify-center rounded-full bg-[var(--nya-primary-soft)]" style="width: 56px; height: 56px; font-size: 20px; font-weight: 600; color: var(--nya-primary);">
          {selectedUser.avatar_url ? '' : selectedUser.username[0].toUpperCase()}
        </div>
        <div>
          <p style="font-size: 18px; font-weight: 650;">{selectedUser.display_name || selectedUser.username}</p>
          <p style="font-size: 13px; color: var(--nya-text-secondary);">@{selectedUser.username}</p>
        </div>
      </div>

      <!-- 角色 & 状态 -->
      <div class="flex gap-3 flex-wrap">
        <div class="flex items-center gap-3 px-3 py-2 rounded-lg" style="background: var(--nya-surface-muted); font-size: 13px;">
          <Shield size={14} />
          <span>角色:</span>
          <div style="min-width: 100px;">
            <Select
              bind:value={selectedUser.role}
              options={[{ value: 'user', label: '用户' }, { value: 'admin', label: '管理员' }]}
            />
          </div>
          <Button variant="ghost" size="sm" onclick={() => handleRoleChange(selectedUser.id, selectedUser.role)}>保存</Button>
        </div>
        <div class="flex items-center gap-2 px-3 py-2 rounded-lg" style="background: {selectedUser.status === 'active' ? 'var(--nya-success-soft)' : 'var(--nya-danger-soft)'}; font-size: 13px;">
          {#if selectedUser.status === 'active'}
            <CheckCircle size={14} style="color: var(--nya-success);" />
            <span style="color: var(--nya-success);">正常</span>
            <button onclick={() => handleSuspend(selectedUser.id)} style="font-size: 12px; color: var(--nya-warning); margin-left: 8px; text-decoration: underline;">封禁</button>
          {:else}
            <Ban size={14} style="color: var(--nya-danger);" />
            <span style="color: var(--nya-danger);">已封禁</span>
            <button onclick={() => handleActivate(selectedUser.id)} style="font-size: 12px; color: var(--nya-success); margin-left: 8px; text-decoration: underline;">解封</button>
          {/if}
        </div>
      </div>

      <!-- 详细信息 -->
      <div class="space-y-2">
        <div class="flex justify-between py-2" style="border-bottom: 1px solid var(--nya-divider); font-size: 13px;">
          <span style="color: var(--nya-text-tertiary);">邮箱</span>
          <span>{selectedUser.email || '未设置'}</span>
        </div>
        <div class="flex justify-between py-2" style="border-bottom: 1px solid var(--nya-divider); font-size: 13px;">
          <span style="color: var(--nya-text-tertiary);">最后登录</span>
          <span>{selectedUser.last_login_at ? new Date(selectedUser.last_login_at).toLocaleString() : '从未登录'}</span>
        </div>
        <div class="flex justify-between py-2" style="border-bottom: 1px solid var(--nya-divider); font-size: 13px;">
          <span style="color: var(--nya-text-tertiary);">登录 IP</span>
          <span style="font-family: monospace;">{selectedUser.last_login_ip || '-'}</span>
        </div>
        <div class="flex justify-between py-2" style="border-bottom: 1px solid var(--nya-divider); font-size: 13px;">
          <span style="color: var(--nya-text-tertiary);">创建时间</span>
          <span>{new Date(selectedUser.created_at).toLocaleString()}</span>
        </div>
      </div>

      <!-- 外部身份绑定 -->
      <div>
        <h4 class="flex items-center gap-2" style="font-size: 14px; font-weight: 600; margin-bottom: 8px;">
          <KeyRound size={16} style="color: var(--nya-primary);" />
          外部身份绑定
        </h4>
        {#if userIdentities.length === 0}
          <p style="font-size: 13px; color: var(--nya-text-tertiary); padding: 12px; background: var(--nya-surface-muted); border-radius: 8px;">
            此用户未绑定任何外部身份提供商
          </p>
        {:else}
          <div class="space-y-2">
            {#each userIdentities as ident}
              <div class="flex items-center gap-3 p-3 rounded-lg" style="background: var(--nya-surface-muted); font-size: 13px;">
                <Badge variant="info">{ident.provider}</Badge>
                <span>{ident.external_username || ident.external_id}</span>
                {#if ident.external_email}
                  <span style="color: var(--nya-text-tertiary); margin-left: auto;">{ident.external_email}</span>
                {/if}
              </div>
            {/each}
          </div>
        {/if}
      </div>

      <!-- 危险操作 -->
      <div style="border-top: 1px solid var(--nya-divider); padding-top: 16px;">
        <button onclick={() => handleDelete(selectedUser.id)} style="font-size: 13px; color: var(--nya-danger);">删除此用户</button>
      </div>
    </div>
  {/if}
</Drawer>

<!-- 创建用户 Modal -->
<Modal bind:open={showCreate} title="创建用户" size="sm">
  <form onsubmit={handleCreate} class="space-y-4">
    {#if createError}
      <div class="px-3 py-2 rounded-lg" style="background: var(--nya-danger-soft); font-size: 12px; color: var(--nya-danger);">{createError}</div>
    {/if}
    <Input label="用户名" bind:value={newUser.username} required placeholder="输入用户名" />
    <Input label="邮箱" type="email" bind:value={newUser.email} placeholder="输入邮箱" />
    <Input label="密码" type="password" bind:value={newUser.password} required placeholder="至少 8 位" />
    <Input label="显示名称" bind:value={newUser.display_name} placeholder="可选" />
    <div class="flex justify-end gap-2 pt-2">
      <Button variant="secondary" onclick={() => (showCreate = false)}>取消</Button>
      <Button type="submit" variant="primary">创建</Button>
    </div>
  </form>
</Modal>
