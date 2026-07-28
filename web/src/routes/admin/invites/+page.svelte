<script lang="ts">
  import { onMount } from 'svelte';
  import { api, isRecentAuthenticationError, type CreateInviteResult, type Invite, type RegistrationSettings } from '$lib/api';
  import { consumeProviderAuthError } from '$lib/stores';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Card from '$lib/components/ui/Card.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import CopyField from '$lib/components/data-display/CopyField.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import { Plus, Ticket } from 'lucide-svelte';

  const statusMeta: Record<string, { label: string; variant: 'success' | 'default' | 'warning' | 'danger' }> = {
    active: { label: '可用', variant: 'success' },
    expired: { label: '已过期', variant: 'default' },
    exhausted: { label: '已用完', variant: 'warning' },
    revoked: { label: '已吊销', variant: 'danger' },
  };

  let invites = $state<Invite[]>([]);
  let loading = $state(true);
  let pageError = $state('');
  let registrationMode = $state('closed');

  let showCreate = $state(false);
  let creating = $state(false);
  let createError = $state('');
  let createForm = $state({ note: '', max_uses: '', ttl: '' });
  let createdInvite = $state<CreateInviteResult | null>(null);
  let reauthOpen = $state(false);
  let pendingCreate = $state<{ note?: string; max_uses?: number; ttl?: string } | null>(null);

  const pendingCreateStorageKey = 'nyauth:reauth:admin-invite-create';

  let revokeTarget = $state<Invite | null>(null);
  let revokeOpen = $state(false);
  let revokeError = $state('');

  async function loadInvites() {
    loading = true;
    pageError = '';
    try {
      invites = await api.admin.getInvites();
    } catch (cause) {
      pageError = cause instanceof Error ? cause.message : '邀请列表加载失败';
    } finally {
      loading = false;
    }
  }

  async function loadRegistrationMode() {
    try {
      const settings: RegistrationSettings = await api.admin.getRegistrationSettings();
      registrationMode = settings.mode;
    } catch {
      registrationMode = 'closed';
    }
  }

  async function handleCreate(event: SubmitEvent) {
    event.preventDefault();
    createError = '';
    const payload: { note?: string; max_uses?: number; ttl?: string } = {};
    const note = createForm.note.trim();
    if (note) payload.note = note;
    const maxUsesRaw = createForm.max_uses.trim();
    if (maxUsesRaw) {
      const maxUses = Number.parseInt(maxUsesRaw, 10);
      if (!Number.isSafeInteger(maxUses) || maxUses < 1) {
        createError = '可用次数必须是不小于 1 的整数。';
        return;
      }
      payload.max_uses = maxUses;
    }
    if (createForm.ttl.trim()) payload.ttl = createForm.ttl.trim();
    pendingCreate = payload;
    await executeCreate(payload, true);
  }

  async function executeCreate(payload: { note?: string; max_uses?: number; ttl?: string }, allowReauthentication: boolean) {
    creating = true;
    try {
      createdInvite = await api.admin.createInvite(payload);
      pendingCreate = null;
      showCreate = false;
      createForm = { note: '', max_uses: '', ttl: '' };
      await loadInvites();
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        reauthOpen = true;
      } else {
        createError = cause instanceof Error ? cause.message : '创建邀请失败';
        showCreate = true;
      }
    } finally {
      creating = false;
    }
  }

  async function retryPendingCreate() {
    if (pendingCreate) await executeCreate(pendingCreate, false);
  }

  function persistPendingCreate() {
    if (pendingCreate) sessionStorage.setItem(pendingCreateStorageKey, JSON.stringify(pendingCreate));
  }

  async function restorePendingCreate() {
    const raw = sessionStorage.getItem(pendingCreateStorageKey);
    if (!raw) return;
    sessionStorage.removeItem(pendingCreateStorageKey);
    try {
      const restored = JSON.parse(raw) as { note?: string; max_uses?: number; ttl?: string };
      pendingCreate = restored;
      createForm = {
        note: restored.note || '',
        max_uses: restored.max_uses === undefined ? '' : String(restored.max_uses),
        ttl: restored.ttl || '',
      };
      showCreate = true;
      const providerError = consumeProviderAuthError();
      if (providerError) {
        createError = providerError.message;
        return;
      }
      await executeCreate(restored, false);
    } catch {
      createError = '无法恢复待创建的邀请，请重新填写。';
      showCreate = true;
    }
  }

  function requestRevoke(invite: Invite) {
    revokeTarget = invite;
    revokeError = '';
    revokeOpen = true;
  }

  async function revokeInvite() {
    if (!revokeTarget) return;
    revokeError = '';
    try {
      await api.admin.revokeInvite(revokeTarget.id);
      await loadInvites();
    } catch (cause) {
      revokeError = cause instanceof Error ? cause.message : '吊销失败';
      throw cause;
    }
  }

  function formatDateTime(value: string): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN');
  }

  onMount(() => {
    void loadInvites();
    void loadRegistrationMode();
    void restorePendingCreate();
  });
</script>

<svelte:head><title>邀请管理 - Nya</title></svelte:head>

<PageHeader title="邀请管理" description="创建、分发与吊销注册邀请码；邀请码明文只在创建时显示一次">
  {#snippet action()}
    <Button variant="primary" requiredCapability="admin_mutations" onclick={() => { createdInvite = null; createError = ''; showCreate = true; }}><Plus size={16} /> 创建邀请</Button>
  {/snippet}
</PageHeader>

{#if registrationMode !== 'invite_only'}
  <p class="mb-4 rounded-nya-sm bg-nya-warning-soft px-4 py-3 text-body text-nya-warning" role="status">当前注册模式不是"邀请制"，邀请码不会被使用。可在系统状态页的注册设置中调整。</p>
{/if}

{#if createdInvite}
  <section class="mb-4 rounded-nya-card border border-nya-primary/30 bg-nya-primary-soft/40 p-5 shadow-nya-card">
    <h2 class="text-card-title text-nya-text-primary">邀请已创建 — 请立即保存，关闭后无法再次查看</h2>
    <div class="mt-3 space-y-3">
      <div><p class="mb-1 text-small font-semibold text-nya-text-tertiary">邀请码</p><CopyField value={createdInvite.code} /></div>
      <div><p class="mb-1 text-small font-semibold text-nya-text-tertiary">注册链接</p><CopyField value={createdInvite.register_url} /></div>
    </div>
    <div class="mt-4"><Button variant="secondary" size="sm" onclick={() => (createdInvite = null)}>我已保存，关闭</Button></div>
  </section>
{/if}

<ResourceState
  {loading}
  error={pageError}
  empty={invites.length === 0}
  emptyTitle="还没有邀请"
  emptyDescription="创建一个邀请码，分享注册链接给受邀用户。"
  onretry={loadInvites}
>
  {#snippet children()}
    <div class="space-y-3">
      {#each invites as invite (invite.id)}
        <Card>
          <div class="flex flex-col justify-between gap-3 md:flex-row md:items-center">
            <div class="flex min-w-0 items-center gap-3">
              <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-nya-md bg-nya-primary-soft"><Ticket size={20} class="text-nya-primary" /></span>
              <div class="min-w-0">
                <p class="truncate text-body-medium font-semibold text-nya-text-primary">{invite.note || '未命名邀请'}</p>
                <p class="text-small text-nya-text-tertiary">已使用 {invite.used_count} / 待验证 {invite.reserved_count} / 总次数 {invite.max_uses} · {formatDateTime(invite.expires_at)} 过期 · 创建于 {formatDateTime(invite.created_at)}</p>
              </div>
            </div>
            <div class="flex shrink-0 items-center gap-2">
              <Badge variant={statusMeta[invite.status]?.variant ?? 'default'}>{statusMeta[invite.status]?.label ?? invite.status}</Badge>
              {#if invite.status === 'active'}
                <Button variant="ghost" size="sm" requiredCapability="admin_mutations" ariaLabel={`吊销邀请 ${invite.note || invite.id}`} onclick={() => requestRevoke(invite)}>吊销</Button>
              {/if}
            </div>
          </div>
        </Card>
      {/each}
    </div>
  {/snippet}
</ResourceState>

<Modal bind:open={showCreate} title="创建邀请" description="留空的字段使用注册设置中的默认值" size="md">
  <form onsubmit={handleCreate} class="space-y-4">
    {#if createError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{createError}</p>{/if}
    <Input id="invite-note" label="备注（可选）" bind:value={createForm.note} placeholder="给谁、做什么用" />
    <div class="grid gap-4 sm:grid-cols-2">
      <Input id="invite-max-uses" label="可用次数（可选）" bind:value={createForm.max_uses} placeholder="默认按注册设置" />
      <Input id="invite-ttl" label="有效期（可选）" bind:value={createForm.ttl} placeholder="如 168h、24h" />
    </div>
    <div class="flex justify-end gap-2 pt-2"><Button variant="secondary" onclick={() => (showCreate = false)} disabled={creating}>取消</Button><Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={creating}>创建</Button></div>
  </form>
</Modal>

<ConfirmDialog
  bind:open={revokeOpen}
  title="吊销邀请"
  description={`吊销后此邀请码立即失效，无法恢复。${revokeTarget?.note ? `备注：${revokeTarget.note}` : ''}`}
  confirmLabel="吊销"
  error={revokeError}
  onconfirm={revokeInvite}
/>

<ReauthenticationDialog
  bind:open={reauthOpen}
  returnTo="/admin/invites"
  description="创建邀请码前需要验证最近 10 分钟内的身份"
  onauthenticated={retryPendingCreate}
  onbeforeprovider={persistPendingCreate}
/>
