<script lang="ts">
  import { goto } from '$app/navigation';
  import { api, type User, type UserCreationSource, type UserRole } from '$lib/api';
  import { useAdminUserDetailContext } from '$lib/admin-user-detail';
  import { formatStringMetadata, parseStringMetadata } from '$lib/admin-form-utils';
  import AvatarCropper from '$lib/components/account/AvatarCropper.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import DangerZone from '$lib/components/ui/DangerZone.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Select from '$lib/components/ui/Select.svelte';
  import { Ban, CheckCircle, Shield, Trash2 } from 'lucide-svelte';

  const detail = useAdminUserDetailContext();
  const sourceLabels: Record<UserCreationSource, string> = {
    bootstrap: '系统初始化', admin: '管理员创建', self_registration: '自助注册', provider: '外部身份首次登录', legacy: '历史数据',
  };
  let user = $derived(detail.overview?.user ?? null);
  let selectedRole = $state<UserRole>('user');
  let profileForm = $state({ email: '', display_name: '', metadata: '{}' });
  let syncedUserID = '';
  let saving = $state(false);
  let error = $state('');
  let notice = $state('');
  let roleSaving = $state(false);
  let roleError = $state('');
  let confirmAction = $state<'suspend' | 'activate' | 'delete' | null>(null);
  let confirmOpen = $state(false);
  let confirmError = $state('');

  $effect(() => {
    if (user && user.id !== syncedUserID) {
      syncedUserID = user.id;
      selectedRole = user.role;
      profileForm = { email: user.email || '', display_name: user.display_name || '', metadata: formatStringMetadata(user.metadata) };
    }
  });

  function applyUser(updated: User) {
    detail.updateUser(updated);
    selectedRole = updated.role;
    profileForm = { email: updated.email || '', display_name: updated.display_name || '', metadata: formatStringMetadata(updated.metadata) };
  }

  async function saveProfile(event: SubmitEvent) {
    event.preventDefault();
    if (!user) return;
    error = '';
    notice = '';
    let metadata: Record<string, string>;
    try {
      metadata = parseStringMetadata(profileForm.metadata);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Metadata 格式无效。';
      return;
    }
    saving = true;
    try {
      applyUser(await api.admin.updateUser(user.id, { email: profileForm.email.trim(), display_name: profileForm.display_name.trim(), metadata }));
      notice = '用户资料已更新。';
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '用户资料更新失败';
    } finally {
      saving = false;
    }
  }

  async function saveRole() {
    if (!user || selectedRole === user.role) return;
    roleSaving = true;
    roleError = '';
    try {
      applyUser(await api.admin.updateUserRole(user.id, selectedRole));
    } catch (cause) {
      roleError = cause instanceof Error ? cause.message : '角色更新失败';
      selectedRole = user.role;
    } finally {
      roleSaving = false;
    }
  }

  async function uploadAvatar(blob: Blob) {
    if (!user) return;
    applyUser(await api.admin.uploadUserAvatar(user.id, blob));
    notice = '用户头像已更新。';
  }

  async function removeAvatar() {
    if (!user) return;
    applyUser(await api.admin.removeUserAvatar(user.id));
    notice = '用户头像已删除。';
  }

  function requestAction(action: 'suspend' | 'activate' | 'delete') {
    confirmAction = action;
    confirmError = '';
    confirmOpen = true;
  }

  async function runAction() {
    if (!user || !confirmAction) return;
    confirmError = '';
    try {
      if (confirmAction === 'delete') {
        await api.admin.deleteUser(user.id);
        await goto(detail.returnTo);
      } else if (confirmAction === 'suspend') {
        applyUser(await api.admin.suspendUser(user.id));
      } else {
        applyUser(await api.admin.activateUser(user.id));
      }
    } catch (cause) {
      confirmError = cause instanceof Error ? cause.message : '操作失败';
      throw cause;
    }
  }
</script>

<svelte:head><title>{user ? `${user.username} - 用户资料` : '用户资料'} - Nya</title></svelte:head>

{#if user && detail.overview}
  <div class="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
    <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
      <h2 class="text-card-title text-nya-text-primary">基本资料</h2>
      <p class="mb-4 mt-1 text-body text-nya-text-secondary">管理用户的联系方式、展示信息、头像和 metadata。</p>
      {#if error}<p class="mb-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{error}</p>{/if}
      {#if notice}<p class="mb-3 rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">{notice}</p>{/if}
      <form onsubmit={saveProfile} class="space-y-4">
        <div class="grid gap-4 md:grid-cols-2"><Input id="admin-user-email" label="邮箱" type="email" bind:value={profileForm.email} autocomplete="email" placeholder="可选" /><Input id="admin-user-display-name" label="显示名称" bind:value={profileForm.display_name} placeholder="可选" /></div>
        <div><p class="mb-2 text-body-medium text-nya-text-primary">头像</p><AvatarCropper currentUrl={user.avatar_url} onupload={uploadAvatar} onremove={removeAvatar} /></div>
        <div><label for="admin-user-metadata" class="mb-1.5 block text-body-medium text-nya-text-primary">Metadata（JSON 字符串键值）</label><textarea id="admin-user-metadata" bind:value={profileForm.metadata} rows="5" spellcheck="false" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea></div>
        <Button type="submit" variant="primary" loading={saving}>保存资料</Button>
      </form>
    </section>

    <div class="space-y-4">
      <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
        <h2 class="text-card-title text-nya-text-primary">账户信息</h2>
        <dl class="mt-3 divide-y divide-nya-divider text-body">
          <div class="flex justify-between gap-4 py-2.5"><dt class="text-nya-text-tertiary">创建来源</dt><dd>{sourceLabels[detail.overview.creation_source]}</dd></div>
          <div class="flex justify-between gap-4 py-2.5"><dt class="text-nya-text-tertiary">创建者</dt><dd class="text-right">{detail.overview.created_by?.display_name || detail.overview.created_by?.username || '-'}</dd></div>
          <div class="flex justify-between gap-4 py-2.5"><dt class="text-nya-text-tertiary">邮箱验证</dt><dd><Badge variant={user.email && detail.overview.user.email_verified_at ? 'success' : 'default'}>{user.email && detail.overview.user.email_verified_at ? '已验证' : '未验证'}</Badge></dd></div>
          <div class="flex justify-between gap-4 py-2.5"><dt class="text-nya-text-tertiary">最后登录</dt><dd class="text-right">{user.last_login_at ? new Date(user.last_login_at).toLocaleString() : '从未登录'}</dd></div>
          <div class="flex justify-between gap-4 py-2.5"><dt class="text-nya-text-tertiary">登录 IP</dt><dd class="font-mono">{user.last_login_ip || '-'}</dd></div>
          <div class="flex justify-between gap-4 py-2.5"><dt class="text-nya-text-tertiary">创建时间</dt><dd class="text-right">{new Date(user.created_at).toLocaleString()}</dd></div>
        </dl>
        {#if detail.overview.self_registration}
          <div class="mt-4 rounded-nya-sm bg-nya-surface-muted p-3 text-small text-nya-text-secondary"><p class="font-semibold text-nya-text-primary">自助注册记录</p><p class="mt-1">状态：{detail.overview.self_registration.status}</p><p>截止：{new Date(detail.overview.self_registration.expires_at).toLocaleString()}</p></div>
        {/if}
      </section>

      <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
        <h2 class="text-card-title text-nya-text-primary">角色与状态</h2>
        {#if roleError}<p class="mt-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{roleError}</p>{/if}
        <div class="mt-4 flex items-end gap-3"><div class="min-w-0 flex-1"><Select id="user-role" label="角色" bind:value={selectedRole} options={[{ value: 'user', label: '用户' }, { value: 'admin', label: '管理员' }]} /></div><Button variant="secondary" size="sm" onclick={saveRole} loading={roleSaving} disabled={selectedRole === user.role}><Shield size={15} /> 保存</Button></div>
        <div class="mt-4">{#if user.status === 'active'}<Button variant="secondary" onclick={() => requestAction('suspend')}><Ban size={15} /> 封禁账户</Button>{:else}<Button variant="secondary" onclick={() => requestAction('activate')}><CheckCircle size={15} /> 激活账户</Button>{/if}</div>
      </section>

      <DangerZone description="删除用户会立即使其会话和令牌失效，且无法恢复。">
        {#snippet children()}<Button variant="danger" size="sm" onclick={() => requestAction('delete')}><Trash2 size={15} /> 删除此用户</Button>{/snippet}
      </DangerZone>
    </div>
  </div>
{/if}

<ConfirmDialog
  bind:open={confirmOpen}
  title={confirmAction === 'delete' ? '删除用户' : confirmAction === 'suspend' ? '封禁用户' : '激活用户'}
  description={confirmAction === 'delete' ? `删除后，用户“${user?.username || ''}”的所有会话和令牌会立即失效，且无法恢复。` : confirmAction === 'suspend' ? `封禁后，用户“${user?.username || ''}”将无法继续登录。` : `用户“${user?.username || ''}”将恢复登录能力。`}
  confirmLabel={confirmAction === 'delete' ? '永久删除' : '确认'}
  confirmationText={confirmAction === 'delete' ? user?.username || '' : ''}
  error={confirmError}
  onconfirm={runAction}
/>
