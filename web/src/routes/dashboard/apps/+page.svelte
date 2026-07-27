<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type CreateClientInput, type OAuthClient } from '$lib/api';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import CopyField from '$lib/components/data-display/CopyField.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import SecretReveal from '$lib/components/ui/SecretReveal.svelte';
  import { AppWindow, Plus, RefreshCw } from 'lucide-svelte';

  const clientLimit = 10;
  let clients = $state<OAuthClient[]>([]);
  let clientTotal = $state<number | null>(null);
  let loading = $state(true);
  let showCreate = $state(false);
  let creating = $state(false);
  let createError = $state('');
  let pageError = $state('');
  let createdSecret = $state('');
  let rotatedSecret = $state('');
  let rotatedClientName = $state('');
  let newApp = $state({ name: '', redirect_uris: '', post_logout_redirect_uris: '', is_public: false });
  let deleteTarget = $state<OAuthClient | null>(null);
  let deleteOpen = $state(false);
  let deleteError = $state('');
  let rotateTarget = $state<OAuthClient | null>(null);
  let rotateOpen = $state(false);
  let rotateError = $state('');
  let quotaReached = $derived(clientTotal !== null && clientTotal >= clientLimit);

  async function loadApps() {
    loading = true;
    pageError = '';
    try {
      const result = await api.my.getClients();
      clients = result.items;
      clientTotal = result.total;
    } catch (cause) {
      pageError = cause instanceof Error ? cause.message : '应用列表加载失败';
    } finally {
      loading = false;
    }
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
        name: newApp.name,
        redirect_uris: newApp.redirect_uris.split('\n').map((uri) => uri.trim()).filter(Boolean),
        post_logout_redirect_uris: newApp.post_logout_redirect_uris.split('\n').map((uri) => uri.trim()).filter(Boolean),
        grants: ['authorization_code', 'refresh_token'],
        scopes: ['openid', 'profile', 'email', 'offline_access'],
        is_public: newApp.is_public,
      };
      const result = await api.my.createClient(payload);
      createdSecret = result.secret || '';
      showCreate = false;
      newApp = { name: '', redirect_uris: '', post_logout_redirect_uris: '', is_public: false };
      await loadApps();
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
      const result = await api.my.rotateClientSecret(target.id);
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
      await api.my.deleteClient(deleteTarget.id);
      await loadApps();
    } catch (cause) {
      deleteError = cause instanceof Error ? cause.message : '删除失败';
      throw cause;
    }
  }

  onMount(loadApps);
</script>

<svelte:head><title>我的应用 - Nya</title></svelte:head>

<PageHeader title="我的应用" description="管理你创建的 OAuth / OIDC 客户端">
  {#snippet action()}
    <div class="flex items-center gap-3">
      <span title="已创建应用 / 配额上限"><Badge variant={quotaReached ? 'warning' : 'default'}>{clientTotal === null ? `—/${clientLimit}` : `${clientTotal}/${clientLimit}`}</Badge></span>
      <Button variant="primary" disabled={quotaReached} onclick={() => { createdSecret = ''; showCreate = true; }}><Plus size={16} /> 创建应用</Button>
    </div>
  {/snippet}
</PageHeader>

{#if createdSecret}<div class="mb-4 rounded-nya-md border border-nya-info/20 bg-nya-info-soft px-5 py-4"><p class="mb-2 text-body-medium text-nya-info">请立即复制并安全保存 Client Secret，离开本页后无法再次查看。</p><SecretReveal value={createdSecret} label="Client Secret" /></div>{/if}
{#if rotatedSecret}<div class="mb-4 rounded-nya-md border border-nya-warning/20 bg-nya-warning-soft px-5 py-4"><p class="mb-2 text-body-medium text-nya-warning">“{rotatedClientName}”的旧 Secret 已立即失效。新 Secret 仅在当前页面显示，请现在保存。</p><SecretReveal value={rotatedSecret} label="新 Client Secret" /></div>{/if}

<ResourceState {loading} error={pageError} empty={clients.length === 0} emptyTitle="还没有创建应用" emptyDescription="创建第一个 OAuth / OIDC 客户端后即可接入项目。" onretry={loadApps}>
  {#snippet emptyAction()}<Button variant="primary" onclick={() => (showCreate = true)}>创建应用</Button>{/snippet}
  {#snippet children()}
    <div class="space-y-3">
      {#each clients as client}
        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="flex flex-col justify-between gap-4 md:flex-row md:items-start">
            <div class="flex min-w-0 items-center gap-3"><span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-nya-md bg-nya-blue-soft"><AppWindow size={20} class="text-nya-blue" /></span><div class="min-w-0"><h2 class="truncate text-card-title text-nya-text-primary">{client.name}</h2><CopyField value={client.id} /></div></div>
            <div class="flex flex-wrap items-center gap-2">{#if client.is_public}<Badge variant="warning">Public</Badge>{:else}<Button variant="secondary" size="sm" onclick={() => requestRotation(client)}><RefreshCw size={14} /> 轮换 Secret</Button>{/if}<Button variant="ghost" size="sm" onclick={() => requestDelete(client)}>删除</Button></div>
          </div>
          {#if !client.is_public}<p class="mt-3 text-small text-nya-text-tertiary">Secret 版本 {client.secret_version}{#if client.secret_hint} · 尾号 {client.secret_hint}{/if}{#if client.secret_rotated_at} · 最近轮换 {new Date(client.secret_rotated_at).toLocaleString()}{/if}</p>{/if}
          <div class="mt-4 flex flex-wrap gap-1.5">{#each client.redirect_uris as uri}<code class="break-all rounded-nya-xs bg-nya-surface-muted px-2 py-1 text-micro text-nya-text-secondary">{uri}</code>{/each}</div>
          {#if client.post_logout_redirect_uris.length > 0}<div class="mt-2 flex flex-wrap gap-1.5">{#each client.post_logout_redirect_uris as uri}<code class="break-all rounded-nya-xs bg-nya-surface-muted px-2 py-1 text-micro text-nya-text-tertiary">退出：{uri}</code>{/each}</div>{/if}
        </section>
      {/each}
    </div>
  {/snippet}
</ResourceState>

<Modal bind:open={showCreate} title="创建应用" description="授权码客户端始终强制使用 S256 PKCE" size="md">
  <form onsubmit={handleCreate} class="space-y-4">
    {#if createError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{createError}</p>{/if}
    <Input id="my-client-name" label="应用名称" bind:value={newApp.name} required placeholder="我的应用" />
    <div><label for="my-client-redirects" class="mb-1.5 block text-body-medium text-nya-text-primary">Redirect URI <span class="text-small text-nya-text-tertiary">（每行一个）</span></label><textarea id="my-client-redirects" bind:value={newApp.redirect_uris} required rows="3" placeholder="https://app.example.com/callback" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea></div>
    <div><label for="my-client-logouts" class="mb-1.5 block text-body-medium text-nya-text-primary">Post-logout Redirect URI <span class="text-small text-nya-text-tertiary">（每行一个）</span></label><textarea id="my-client-logouts" bind:value={newApp.post_logout_redirect_uris} rows="2" placeholder="https://app.example.com/signed-out" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea></div>
    <label class="flex cursor-pointer items-start gap-2"><input type="checkbox" bind:checked={newApp.is_public} class="mt-0.5 rounded" /><span><span class="block text-body text-nya-text-primary">公共客户端</span><span class="block text-small text-nya-text-tertiary">仅用于无法安全保存 Secret 的原生应用；浏览器 SPA 暂不作为正式支持模式。</span></span></label>
    <div class="flex justify-end gap-2 pt-2"><Button variant="secondary" onclick={() => (showCreate = false)} disabled={creating}>取消</Button><Button type="submit" variant="primary" loading={creating}>创建</Button></div>
  </form>
</Modal>

<ConfirmDialog bind:open={deleteOpen} title="删除应用" description={`删除后，使用“${deleteTarget?.name || ''}”的集成会立即失效。`} confirmLabel="永久删除" confirmationText={deleteTarget?.name || ''} error={deleteError} onconfirm={deleteClient} />

<ConfirmDialog bind:open={rotateOpen} title="轮换 Client Secret" description={`“${rotateTarget?.name || ''}”的旧 Secret 会立即失效，所有使用旧凭据的服务必须同步更新。`} confirmLabel="立即轮换" confirmationText={rotateTarget?.name || ''} error={rotateError} onconfirm={rotateSecret} />
