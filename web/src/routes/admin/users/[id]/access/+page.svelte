<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type AdminUserAuthorization, type AdminUserClientSummary, type ExternalIdentity } from '$lib/api';
  import { useAdminUserDetailContext } from '$lib/admin-user-detail';
  import ProviderIcon from '$lib/components/identity/ProviderIcon.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import { AppWindow, KeyRound, Link2, Trash2 } from 'lucide-svelte';

  const detail = useAdminUserDetailContext();
  let identities = $state<ExternalIdentity[]>([]);
  let authorizations = $state<AdminUserAuthorization[]>([]);
  let clients = $state<AdminUserClientSummary[]>([]);
  let loading = $state(true);
  let error = $state('');
  let identityTarget = $state<ExternalIdentity | null>(null);
  let confirmOpen = $state(false);
  let confirmError = $state('');
  let notice = $state('');

  async function loadAccess() {
    loading = true;
    error = '';
    try {
      const [identityItems, authorizationItems, clientResult] = await Promise.all([
        api.admin.getUserIdentities(detail.userID),
        api.admin.getUserAuthorizations(detail.userID),
        api.admin.getUserClients(detail.userID, 1, 50),
      ]);
      identities = identityItems;
      authorizations = authorizationItems;
      clients = clientResult.items;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '访问关系加载失败';
    } finally {
      loading = false;
    }
  }

  function requestIdentityRemoval(identity: ExternalIdentity) {
    identityTarget = identity;
    confirmError = '';
    confirmOpen = true;
  }

  async function removeIdentity() {
    if (!identityTarget) return;
    const target = identityTarget;
    confirmError = '';
    try {
      await api.admin.deleteUserIdentity(detail.userID, target.id);
      identities = identities.filter((item) => item.id !== target.id);
      notice = `已解绑 ${target.provider} 身份。`;
      identityTarget = null;
    } catch (cause) {
      confirmError = cause instanceof Error ? cause.message : '外部身份解绑失败';
      throw cause;
    }
  }

  onMount(loadAccess);
</script>

<svelte:head><title>用户访问关系 - Nya</title></svelte:head>

{#if notice}<p class="mb-4 rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">{notice}</p>{/if}
<ResourceState {loading} {error} onretry={loadAccess}>
  {#snippet children()}
    <div class="grid gap-4 xl:grid-cols-2">
      <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
        <div class="mb-4 flex items-center gap-2"><KeyRound size={18} class="text-nya-primary" /><h2 class="text-card-title text-nya-text-primary">外部身份</h2></div>
        {#if identities.length === 0}<p class="rounded-nya-sm bg-nya-surface-muted p-3 text-body text-nya-text-tertiary">未绑定外部身份</p>{:else}<div class="space-y-2">{#each identities as identity}<div class="flex items-center gap-3 rounded-nya-sm bg-nya-surface-muted p-3"><span class="text-nya-text-primary"><ProviderIcon type={identity.provider_type} iconKey={identity.provider_icon_key} size={18} /></span><Badge variant="info">{identity.provider_display_name || identity.provider}</Badge><div class="min-w-0 flex-1"><p class="truncate text-body text-nya-text-primary">{identity.external_username || identity.external_id}</p><p class="truncate text-small text-nya-text-tertiary">{identity.external_email || '未提供邮箱'}</p></div><Button variant="ghost" size="sm" ariaLabel={`解绑 ${identity.provider} 身份`} onclick={() => requestIdentityRemoval(identity)}><Trash2 size={14} /> 解绑</Button></div>{/each}</div>{/if}
      </section>

      <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
        <div class="mb-4 flex items-center gap-2"><Link2 size={18} class="text-nya-primary" /><h2 class="text-card-title text-nya-text-primary">OAuth 授权</h2></div>
        {#if authorizations.length === 0}<p class="rounded-nya-sm bg-nya-surface-muted p-3 text-body text-nya-text-tertiary">没有有效 OAuth 授权</p>{:else}<div class="space-y-2">{#each authorizations as item}<article class="rounded-nya-sm border border-nya-border p-3"><div class="flex items-center justify-between gap-3"><p class="font-medium text-nya-text-primary">{item.client_name}</p><span class="font-mono text-micro text-nya-text-tertiary">{item.client_id}</span></div><p class="mt-2 text-small text-nya-text-secondary">Scope：{item.scopes.join(' ') || '-'}</p><p class="mt-1 text-small text-nya-text-tertiary">授权于 {new Date(item.granted_at).toLocaleString()}</p></article>{/each}</div>{/if}
      </section>

      <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card xl:col-span-2">
        <div class="mb-4 flex items-center gap-2"><AppWindow size={18} class="text-nya-primary" /><h2 class="text-card-title text-nya-text-primary">拥有的 OAuth / OIDC 客户端</h2></div>
        {#if clients.length === 0}<p class="rounded-nya-sm bg-nya-surface-muted p-3 text-body text-nya-text-tertiary">该用户没有创建客户端</p>{:else}<div class="overflow-x-auto rounded-nya-sm border border-nya-border"><table class="w-full"><thead><tr class="h-10 border-b border-nya-divider bg-nya-surface-subtle text-small text-nya-text-secondary"><th class="px-3 text-left">名称</th><th class="px-3 text-left">Client ID</th><th class="px-3 text-left">类型</th><th class="px-3 text-left">访问策略</th><th class="px-3 text-left">创建时间</th></tr></thead><tbody class="divide-y divide-nya-divider">{#each clients as client}<tr><td class="px-3 py-3 font-medium text-nya-text-primary">{client.name}</td><td class="px-3 py-3 font-mono text-small text-nya-text-secondary">{client.id}</td><td class="px-3 py-3 text-small">{client.is_public ? '公开客户端' : '机密客户端'}</td><td class="px-3 py-3 text-small">{client.access_policy}</td><td class="px-3 py-3 text-small text-nya-text-tertiary">{new Date(client.created_at).toLocaleString()}</td></tr>{/each}</tbody></table></div>{/if}
      </section>
    </div>
  {/snippet}
</ResourceState>

<ConfirmDialog bind:open={confirmOpen} title="解绑外部身份" description={`解绑“${identityTarget?.provider || ''}”后，该用户将无法再使用此身份登录，现有会话和令牌也会失效。`} confirmLabel="确认解绑" confirmationText={identityTarget?.provider || ''} error={confirmError} onconfirm={removeIdentity} />
