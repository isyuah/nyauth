<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import {
    api,
    type CreateClientInput,
    type OAuthClient,
    type OAuthClientPolicy,
    type OAuthGrantType,
    type OAuthScope,
    type UpdateClientInput,
  } from '$lib/api';
  import { DEFAULT_OAUTH_SETTINGS, OAUTH_SCOPES } from '$lib/policy-settings';
  import { claimsForScopes, cloneScopeDefinitions } from '$lib/oauth-catalog';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import CopyField from '$lib/components/data-display/CopyField.svelte';
  import AvatarCropper from '$lib/components/account/AvatarCropper.svelte';
  import OAuthClientAuthorizationEditor from '$lib/components/oauth/OAuthClientAuthorizationEditor.svelte';
  import OAuthClientIdentityFields from '$lib/components/oauth/OAuthClientIdentityFields.svelte';
  import OAuthClientLogo from '$lib/components/oauth/OAuthClientLogo.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import SecretReveal from '$lib/components/ui/SecretReveal.svelte';
  import { toast } from '$lib/toast';
  import { BarChart3, ExternalLink, Pencil, Plus, RefreshCw } from 'lucide-svelte';

  type ClientForm = {
    name: string;
    homepage_uri: string;
    privacy_policy_uri: string;
    terms_of_service_uri: string;
    redirect_uris: string;
    post_logout_redirect_uris: string;
    is_public: boolean;
    grants: OAuthGrantType[];
    scopes: OAuthScope[];
    optional_scopes: OAuthScope[];
    allowed_claims: string[];
  };

  let clients = $state<OAuthClient[]>([]);
  let clientTotal = $state<number | null>(null);
  let clientLimit = $state<number | null>(null);
  let clientPolicy = $state<OAuthClientPolicy>({
    self_service_client_creation_enabled: DEFAULT_OAUTH_SETTINGS.self_service_client_creation_enabled,
    public_clients_enabled: DEFAULT_OAUTH_SETTINGS.public_clients_enabled,
    allowed_grant_types: [...DEFAULT_OAUTH_SETTINGS.allowed_grant_types],
    allowed_scopes: [...DEFAULT_OAUTH_SETTINGS.allowed_scopes],
    scope_definitions: cloneScopeDefinitions(DEFAULT_OAUTH_SETTINGS.scope_definitions),
    claim_assignment_policies: { ...DEFAULT_OAUTH_SETTINGS.claim_assignment_policies },
    max_redirect_uris: DEFAULT_OAUTH_SETTINGS.max_redirect_uris,
    max_post_logout_redirect_uris: DEFAULT_OAUTH_SETTINGS.max_post_logout_redirect_uris,
  });
  let loading = $state(true);
  let pageError = $state('');
  let showCreate = $state(false);
  let openingCreate = $state(false);
  let creating = $state(false);
  let createError = $state('');
  let newApp = $state<ClientForm>(defaultForm(DEFAULT_OAUTH_SETTINGS));
  let editTarget = $state<OAuthClient | null>(null);
  let editForm = $state<ClientForm>(defaultForm(DEFAULT_OAUTH_SETTINGS));
  let showEdit = $state(false);
  let openingEditID = $state<string | null>(null);
  let editing = $state(false);
  let editError = $state('');
  let createdSecret = $state('');
  let rotatedSecret = $state('');
  let rotatedClientName = $state('');
  let deleteTarget = $state<OAuthClient | null>(null);
  let deleteOpen = $state(false);
  let deleteError = $state('');
  let rotateTarget = $state<OAuthClient | null>(null);
  let rotateOpen = $state(false);
  let rotateError = $state('');

  let quotaReached = $derived(clientTotal !== null && clientLimit !== null && clientTotal >= clientLimit);
  let creationDisabled = $derived(!clientPolicy.self_service_client_creation_enabled);
  let createAuthorizationCodeSelected = $derived(newApp.grants.includes('authorization_code'));
  let editAuthorizationCodeSelected = $derived(editForm.grants.includes('authorization_code'));
  let createInteractiveGrantSelected = $derived(createAuthorizationCodeSelected || newApp.grants.includes('urn:ietf:params:oauth:grant-type:device_code'));

  function defaultForm(policy: OAuthClientPolicy): ClientForm {
    const grants: OAuthGrantType[] = [];
    if (policy.allowed_grant_types.includes('authorization_code')) grants.push('authorization_code');
    if (policy.allowed_grant_types.includes('refresh_token') && (grants.includes('authorization_code') || grants.includes('urn:ietf:params:oauth:grant-type:device_code'))) grants.push('refresh_token');
    if (grants.length === 0 && policy.allowed_grant_types[0]) grants.push(policy.allowed_grant_types[0]);
    const scopes = policy.allowed_scopes.filter((scope) => OAUTH_SCOPES.some((standard) => standard === scope)
      && (scope !== 'offline_access' || grants.includes('refresh_token')));
    return {
      name: '', homepage_uri: '', privacy_policy_uri: '', terms_of_service_uri: '',
      redirect_uris: '', post_logout_redirect_uris: '', is_public: false,
      grants, scopes, optional_scopes: [], allowed_claims: claimsForScopes(policy, scopes, false),
    };
  }

  function formFromClient(client: OAuthClient): ClientForm {
    return {
      name: client.name,
      homepage_uri: client.homepage_uri || '',
      privacy_policy_uri: client.privacy_policy_uri || '',
      terms_of_service_uri: client.terms_of_service_uri || '',
      redirect_uris: (client.redirect_uris || []).join('\n'),
      post_logout_redirect_uris: (client.post_logout_redirect_uris || []).join('\n'),
      is_public: client.is_public,
      grants: (client.grants || []).filter(knownGrant),
      scopes: [...(client.scopes || [])],
      optional_scopes: [...(client.optional_scopes || [])],
      allowed_claims: [...(client.allowed_claims || [])],
    };
  }

  function knownGrant(grant: string): grant is OAuthGrantType {
    return grant === 'authorization_code' || grant === 'urn:ietf:params:oauth:grant-type:device_code' || grant === 'refresh_token' || grant === 'client_credentials';
  }

  function applyClientPage(result: Awaited<ReturnType<typeof api.my.getClients>>) {
    clients = result.items || [];
    clientTotal = result.quota_used;
    clientLimit = result.quota_limit;
    clientPolicy = result.client_policy;
  }

  function parseLines(value: string): string[] {
    return [...new Set(value.split('\n').map((item) => item.trim()).filter(Boolean))];
  }

  function validateForm(form: ClientForm, existing?: OAuthClient): UpdateClientInput {
    const name = form.name.trim();
    const redirectURIs = parseLines(form.redirect_uris);
    const logoutURIs = parseLines(form.post_logout_redirect_uris);
    const grants = [...new Set(form.grants)];
    const scopes = [...new Set(form.scopes)];
    if (!name) throw new Error('应用名称不能为空。');
    if (grants.length === 0) throw new Error('至少选择一种 Grant。');
    if (grants.includes('refresh_token') && !grants.includes('authorization_code') && !grants.includes('urn:ietf:params:oauth:grant-type:device_code')) throw new Error('Refresh Token 必须与 Authorization Code 或 Device Authorization 同时启用。');
    if (grants.includes('authorization_code') && redirectURIs.length === 0) throw new Error('Authorization Code 客户端至少需要一个 Redirect URI。');
    if (redirectURIs.length > clientPolicy.max_redirect_uris && (!existing || redirectURIs.length > existing.redirect_uris.length)) {
      throw new Error(`Redirect URI 不能超过 ${clientPolicy.max_redirect_uris} 个。`);
    }
    if (logoutURIs.length > clientPolicy.max_post_logout_redirect_uris && (!existing || logoutURIs.length > existing.post_logout_redirect_uris.length)) {
      throw new Error(`Post-logout Redirect URI 不能超过 ${clientPolicy.max_post_logout_redirect_uris} 个。`);
    }
    const optionalScopes = grants.includes('authorization_code')
      ? form.optional_scopes.filter((scope) => scopes.includes(scope) && scope !== 'openid')
      : [];
    if (scopes.length > 0 && optionalScopes.length === scopes.length) throw new Error('至少保留一个必需 Scope。');
    return {
      name,
      homepage_uri: form.homepage_uri.trim(),
      privacy_policy_uri: form.privacy_policy_uri.trim(),
      terms_of_service_uri: form.terms_of_service_uri.trim(),
      redirect_uris: redirectURIs,
      post_logout_redirect_uris: logoutURIs,
      grants,
      scopes,
      optional_scopes: optionalScopes,
      allowed_claims: form.allowed_claims.filter((claim) => claim !== 'sub' || scopes.includes('openid')),
    };
  }

  async function loadApps() {
    loading = true;
    pageError = '';
    try { applyClientPage(await api.my.getClients()); }
    catch (cause) { pageError = cause instanceof Error ? cause.message : '应用列表加载失败'; }
    finally { loading = false; }
  }

  async function openCreate() {
    openingCreate = true;
    createError = '';
    createdSecret = '';
    try {
      const result = await api.my.getClients();
      applyClientPage(result);
      newApp = defaultForm(result.client_policy);
      showCreate = true;
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : '最新 OAuth 权限策略加载失败，请稍后重试');
    } finally { openingCreate = false; }
  }

  async function handleCreate(event: SubmitEvent) {
    event.preventDefault();
    creating = true;
    createError = '';
    createdSecret = '';
    rotatedSecret = '';
    try {
      if (creationDisabled) throw new Error('管理员已关闭用户自助创建客户端。');
      const configuration = validateForm(newApp) as CreateClientInput;
      const result = await api.my.createClient({ ...configuration, is_public: newApp.is_public });
      createdSecret = result.secret || '';
      showCreate = false;
      await loadApps();
    } catch (cause) { createError = cause instanceof Error ? cause.message : '创建失败'; }
    finally { creating = false; }
  }

  async function openEdit(client: OAuthClient) {
    openingEditID = client.id;
    editError = '';
    try {
      const result = await api.my.getClients();
      applyClientPage(result);
      const latest = result.items.find((item) => item.id === client.id);
      if (!latest) throw new Error('应用不存在，或您已失去管理权限。');
      editTarget = latest;
      editForm = formFromClient(latest);
      showEdit = true;
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : '应用最新配置加载失败');
    } finally { openingEditID = null; }
  }

  async function handleEdit(event: SubmitEvent) {
    event.preventDefault();
    const target = editTarget;
    if (!target) return;
    editError = '';
    editing = true;
    try {
      const updated = await api.my.updateClient(target.id, validateForm(editForm, target));
      clients = clients.map((client) => client.id === updated.id ? updated : client);
      editTarget = updated;
      showEdit = false;
      toast.success('应用设置已保存');
    } catch (cause) { editError = cause instanceof Error ? cause.message : '应用更新失败'; }
    finally { editing = false; }
  }

  function replaceEditedClient(updated: OAuthClient) {
    clients = clients.map((client) => client.id === updated.id ? updated : client);
    editTarget = updated;
  }

  async function uploadLogo(blob: Blob) {
    if (!editTarget) return;
    replaceEditedClient(await api.my.uploadClientLogo(editTarget.id, blob));
    toast.success('应用 Logo 已更新');
  }

  async function removeLogo() {
    if (!editTarget) return;
    replaceEditedClient(await api.my.removeClientLogo(editTarget.id));
    toast.success('应用 Logo 已删除');
  }

  function requestDelete(client: OAuthClient) { deleteTarget = client; deleteError = ''; deleteOpen = true; }
  function requestRotation(client: OAuthClient) { createdSecret = ''; rotatedSecret = ''; rotateTarget = client; rotateError = ''; rotateOpen = true; }

  async function rotateSecret() {
    if (!rotateTarget) return;
    rotateError = '';
    try {
      const result = await api.my.rotateClientSecret(rotateTarget.id);
      rotatedSecret = result.secret;
      rotatedClientName = rotateTarget.name;
      clients = clients.map((client) => client.id === rotateTarget?.id ? { ...client, secret_hint: result.secret_hint, secret_version: result.secret_version, secret_rotated_at: result.secret_rotated_at, secret_last_used_at: null } : client);
    } catch (cause) { rotateError = cause instanceof Error ? cause.message : 'Secret 轮换失败'; throw cause; }
  }

  async function deleteClient() {
    if (!deleteTarget) return;
    deleteError = '';
    try { await api.my.deleteClient(deleteTarget.id); await loadApps(); }
    catch (cause) { deleteError = cause instanceof Error ? cause.message : '删除失败'; throw cause; }
  }

  onMount(loadApps);
</script>

<svelte:head><title>我的应用 - Nya</title></svelte:head>

<PageHeader title="我的应用" description="管理你创建的 OAuth / OIDC 客户端">
  {#snippet action()}<div class="flex items-center gap-3"><span title="已创建应用 / 配额上限"><Badge variant={quotaReached ? 'warning' : 'default'}>{clientTotal === null || clientLimit === null ? '—/—' : `${clientTotal}/${clientLimit}`}</Badge></span><Button variant="primary" requiredCapability="account_mutations" loading={openingCreate} disabled={quotaReached || creationDisabled} onclick={openCreate}><Plus size={16} /> 创建应用</Button></div>{/snippet}
</PageHeader>

{#if createdSecret}<div class="mb-4 rounded-nya-md border border-nya-info/20 bg-nya-info-soft px-5 py-4"><p class="mb-2 text-body-medium text-nya-info">请立即复制并安全保存 Client Secret，离开本页后无法再次查看。</p><SecretReveal value={createdSecret} label="Client Secret" /></div>{/if}
{#if rotatedSecret}<div class="mb-4 rounded-nya-md border border-nya-warning/20 bg-nya-warning-soft px-5 py-4"><p class="mb-2 text-body-medium text-nya-warning">“{rotatedClientName}”的旧 Secret 已立即失效。新 Secret 仅在当前页面显示。</p><SecretReveal value={rotatedSecret} label="新 Client Secret" /></div>{/if}
{#if creationDisabled}<div class="mb-4 rounded-nya-sm bg-nya-surface-muted px-4 py-3 text-small text-nya-text-secondary">管理员已关闭自助创建；已有应用仍可编辑和管理。</div>{/if}

<ResourceState {loading} error={pageError} empty={clients.length === 0} emptyTitle="还没有创建应用" emptyDescription="创建第一个 OAuth / OIDC 客户端后即可接入项目。" onretry={loadApps}>
  {#snippet emptyAction()}<Button variant="primary" requiredCapability="account_mutations" loading={openingCreate} disabled={quotaReached || creationDisabled} onclick={openCreate}>创建应用</Button>{/snippet}
  {#snippet children()}
    <div class="space-y-3">
      {#each clients as client (client.id)}
        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="flex flex-col justify-between gap-4 md:flex-row md:items-start">
            <div class="flex min-w-0 items-center gap-3"><OAuthClientLogo name={client.name} url={client.logo_url} /><div class="min-w-0"><h2 class="truncate text-card-title text-nya-text-primary">{client.name}</h2><CopyField value={client.id} /></div></div>
            <div class="flex flex-wrap items-center gap-2"><Button variant="soft" size="sm" onclick={() => goto(`/dashboard/apps/${encodeURIComponent(client.id)}`)}><BarChart3 size={14} /> 数据与诊断</Button><Button variant="secondary" size="sm" requiredCapability="account_mutations" loading={openingEditID === client.id} onclick={() => openEdit(client)}><Pencil size={14} /> 编辑</Button>{#if client.is_public}<Badge variant="warning">Public</Badge>{:else}<Button variant="secondary" size="sm" requiredCapability="account_mutations" onclick={() => requestRotation(client)}><RefreshCw size={14} /> 轮换 Secret</Button>{/if}<Button variant="ghost" size="sm" requiredCapability="account_mutations" onclick={() => requestDelete(client)}>删除</Button></div>
          </div>
          {#if client.homepage_uri}<a href={client.homepage_uri} target="_blank" rel="noopener noreferrer" class="mt-3 inline-flex items-center gap-1 text-small text-nya-primary hover:underline"><ExternalLink size={13} /> 应用主页</a>{/if}
          {#if !client.is_public}<p class="mt-3 text-small text-nya-text-tertiary">Secret 版本 {client.secret_version}{#if client.secret_hint} · 尾号 {client.secret_hint}{/if}{#if client.secret_rotated_at} · 最近轮换 {new Date(client.secret_rotated_at).toLocaleString()}{/if}</p>{/if}
          <div class="mt-4 flex flex-wrap gap-1.5">{#each client.redirect_uris || [] as uri}<code class="break-all rounded-nya-xs bg-nya-surface-muted px-2 py-1 text-micro text-nya-text-secondary">{uri}</code>{/each}</div>
          <div class="mt-3 flex flex-wrap gap-1.5">{#each client.scopes || [] as scope}<Badge variant={(client.optional_scopes || []).includes(scope) ? 'info' : 'default'}>{scope}{(client.optional_scopes || []).includes(scope) ? ' · 可选' : ''}</Badge>{/each}{#each client.allowed_claims || [] as claim}<Badge variant="default">{claim}</Badge>{/each}</div>
        </section>
      {/each}
    </div>
  {/snippet}
</ResourceState>

<Modal bind:open={showCreate} title="创建应用" description="授权码客户端始终强制使用 S256 PKCE" size="lg">
  <form onsubmit={handleCreate} class="space-y-4">
    {#if createError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{createError}</p>{/if}
    <OAuthClientIdentityFields idPrefix="my-client-create" bind:name={newApp.name} bind:homepageURI={newApp.homepage_uri} bind:privacyPolicyURI={newApp.privacy_policy_uri} bind:termsOfServiceURI={newApp.terms_of_service_uri} />
    <OAuthClientAuthorizationEditor policy={clientPolicy} idPrefix="my-client-create" administrator={false} isPublic={newApp.is_public} bind:grants={newApp.grants} bind:scopes={newApp.scopes} bind:optionalScopes={newApp.optional_scopes} bind:allowedClaims={newApp.allowed_claims} onInteractiveGrantDisabled={() => (newApp.is_public = false)} />
    <div><label for="my-client-create-redirects" class="mb-1.5 block text-body-medium text-nya-text-primary">Redirect URI <span class="text-small text-nya-text-tertiary">（每行一个，最多 {clientPolicy.max_redirect_uris} 个）</span></label><textarea id="my-client-create-redirects" bind:value={newApp.redirect_uris} required={createAuthorizationCodeSelected} rows="3" placeholder="https://app.example.com/callback" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea></div>
    <div><label for="my-client-create-logouts" class="mb-1.5 block text-body-medium text-nya-text-primary">Post-logout Redirect URI <span class="text-small text-nya-text-tertiary">（每行一个，最多 {clientPolicy.max_post_logout_redirect_uris} 个）</span></label><textarea id="my-client-create-logouts" bind:value={newApp.post_logout_redirect_uris} rows="2" placeholder="https://app.example.com/signed-out" disabled={clientPolicy.max_post_logout_redirect_uris === 0} class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24 disabled:opacity-50"></textarea></div>
    <label class="flex cursor-pointer items-start gap-2 {clientPolicy.public_clients_enabled && createInteractiveGrantSelected ? '' : 'opacity-50'}"><input type="checkbox" bind:checked={newApp.is_public} disabled={!clientPolicy.public_clients_enabled || !createInteractiveGrantSelected} class="mt-0.5 rounded" /><span><span class="block text-body text-nya-text-primary">公共客户端</span><span class="block text-small text-nya-text-tertiary">用于无法安全保存 Secret 的原生应用、CLI 或输入受限设备。</span></span></label>
    <div class="flex justify-end gap-2 pt-2"><Button variant="secondary" onclick={() => (showCreate = false)} disabled={creating}>取消</Button><Button type="submit" variant="primary" requiredCapability="account_mutations" loading={creating} disabled={quotaReached || creationDisabled}>创建</Button></div>
  </form>
</Modal>

<Modal bind:open={showEdit} title={`编辑应用 · ${editTarget?.name || ''}`} description="应用身份信息会显示在授权页；高风险配置变更可能要求用户重新授权" size="lg">
  <form onsubmit={handleEdit} class="space-y-4">
    {#if editError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{editError}</p>{/if}
    {#if editTarget}<div class="flex items-start gap-4 rounded-nya-sm bg-nya-surface-soft p-4"><OAuthClientLogo name={editTarget.name} url={editTarget.logo_url} size="lg" /><div class="min-w-0 flex-1"><p class="mb-2 text-body-medium font-semibold text-nya-text-primary">应用 Logo</p><AvatarCropper currentUrl={editTarget.logo_url} subject="应用 Logo" previewShape="rounded" onupload={uploadLogo} onremove={removeLogo} /></div></div>{/if}
    <OAuthClientIdentityFields idPrefix="my-client-edit" bind:name={editForm.name} bind:homepageURI={editForm.homepage_uri} bind:privacyPolicyURI={editForm.privacy_policy_uri} bind:termsOfServiceURI={editForm.terms_of_service_uri} />
    <OAuthClientAuthorizationEditor policy={clientPolicy} idPrefix="my-client-edit" administrator={false} isPublic={editForm.is_public} bind:grants={editForm.grants} bind:scopes={editForm.scopes} bind:optionalScopes={editForm.optional_scopes} bind:allowedClaims={editForm.allowed_claims} existingGrants={editTarget?.grants ?? []} existingScopes={editTarget?.scopes ?? []} existingClaims={editTarget?.allowed_claims ?? []} />
    <div><label for="my-client-edit-redirects" class="mb-1.5 block text-body-medium text-nya-text-primary">Redirect URI</label><textarea id="my-client-edit-redirects" bind:value={editForm.redirect_uris} required={editAuthorizationCodeSelected} rows="3" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea></div>
    <div><label for="my-client-edit-logouts" class="mb-1.5 block text-body-medium text-nya-text-primary">Post-logout Redirect URI</label><textarea id="my-client-edit-logouts" bind:value={editForm.post_logout_redirect_uris} rows="2" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea></div>
    <p class="rounded-nya-sm bg-nya-surface-muted px-3 py-2 text-small text-nya-text-secondary">Client 类型不可修改：{editTarget?.is_public ? 'Public' : 'Confidential'}</p>
    <div class="flex justify-end gap-2"><Button variant="secondary" onclick={() => (showEdit = false)} disabled={editing}>取消</Button><Button type="submit" variant="primary" requiredCapability="account_mutations" loading={editing}>保存更改</Button></div>
  </form>
</Modal>

<ConfirmDialog bind:open={deleteOpen} title="删除应用" description={`删除后，使用“${deleteTarget?.name || ''}”的集成会立即失效。`} confirmLabel="永久删除" confirmationText={deleteTarget?.name || ''} error={deleteError} onconfirm={deleteClient} />
<ConfirmDialog bind:open={rotateOpen} title="轮换 Client Secret" description={`“${rotateTarget?.name || ''}”的旧 Secret 会立即失效，所有使用旧凭据的服务必须同步更新。`} confirmLabel="立即轮换" confirmationText={rotateTarget?.name || ''} error={rotateError} onconfirm={rotateSecret} />
