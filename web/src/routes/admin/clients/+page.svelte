<script lang="ts">
  import { api } from '$lib/api';
  import { onMount } from 'svelte';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import Card from '$lib/components/ui/Card.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import CopyField from '$lib/components/data-display/CopyField.svelte';
  import EmptyState from '$lib/components/ui/EmptyState.svelte';
  import { Plus, AppWindow, Eye, EyeOff } from 'lucide-svelte';

  let clients = $state<any[]>([]);
  let total = $state(0);
  let showCreate = $state(false);
  let newClient = $state({ name: '', redirect_uris: '', grants: ['authorization_code'], is_public: false });
  let createdSecret = $state('');
  let createError = $state('');

  onMount(() => loadClients());

  async function loadClients() {
    try { const r = await api.admin.getClients(); clients = r.items || []; total = r.total || 0; } catch {}
  }

  async function handleCreate(e: Event) {
    e.preventDefault();
    createError = '';
    createdSecret = '';
    try {
      const uris = newClient.redirect_uris.split('\n').filter(Boolean);
      const res = await api.admin.createClient({ ...newClient, redirect_uris: uris, scopes: ['openid', 'profile', 'email'] });
      if (res.secret) createdSecret = res.secret;
      showCreate = false;
      loadClients();
    } catch (err) { createError = err instanceof Error ? err.message : '创建失败'; }
  }

  async function handleDelete(id: string) {
    if (!confirm('删除应用后，所有使用此 Client ID 的集成将立即失效。确定继续吗？')) return;
    try { await api.admin.deleteClient(id); loadClients(); } catch {}
  }
</script>

<svelte:head><title>应用管理 - Nya</title></svelte:head>

<PageHeader title="应用管理" description="管理 OAuth 2.x / OIDC 客户端、密钥与回调地址">
  {#snippet action()}
    <Button variant="primary" onclick={() => { createdSecret = ''; showCreate = true; }}>
      <Plus size={16} /> 创建应用
    </Button>
  {/snippet}
</PageHeader>

<!-- Secret 一次性展示 -->
{#if createdSecret}
  <div class="mb-4 px-5 py-4 bg-nya-info-soft border border-nya-info/20 rounded-nya-md">
    <p class="text-body-medium text-nya-info mb-2">请现在复制并安全保存 Client Secret，关闭后将无法再次查看。</p>
    <CopyField value={createdSecret} label="Client Secret" />
  </div>
{/if}

<!-- 应用列表 -->
{#if clients.length === 0 && !showCreate}
  <EmptyState title="还没有创建应用" description="创建第一个 OAuth / OIDC 客户端后，就可以接入你的项目了。">
    {#snippet icon()}<AppWindow size={48} />{/snippet}
    {#snippet action()}<Button variant="primary" onclick={() => (showCreate = true)}>创建应用</Button>{/snippet}
  </EmptyState>
{:else}
  <div class="space-y-3">
    {#each clients as cl}
      <Card>
        <div class="flex items-start justify-between">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-nya-md bg-nya-blue-soft flex items-center justify-center">
              <AppWindow size={20} class="text-nya-blue" />
            </div>
            <div>
              <h3 class="text-card-title text-nya-text-primary">{cl.name}</h3>
              <CopyField value={cl.id} />
            </div>
          </div>
          <div class="flex items-center gap-2">
            {#if cl.is_public}
              <Badge variant="warning">Public</Badge>
            {/if}
            <Badge variant="primary">{cl.grants?.join(', ') || 'authorization_code'}</Badge>
            <button onclick={() => handleDelete(cl.id)} class="text-small text-nya-danger hover:underline ml-2">删除</button>
          </div>
        </div>
        <div class="mt-3 flex flex-wrap gap-1.5">
          {#each cl.redirect_uris || [] as uri}
            <code class="text-micro px-2 py-0.5 bg-nya-surface-soft rounded-nya-xs text-nya-text-secondary">{uri}</code>
          {/each}
        </div>
      </Card>
    {/each}
  </div>
{/if}

<!-- 创建应用 Modal -->
<Modal bind:open={showCreate} title="创建应用" size="md">
  <form onsubmit={handleCreate} class="space-y-4">
    {#if createError}
      <div class="px-3 py-2 bg-nya-danger-soft text-small text-nya-danger rounded-nya-sm">{createError}</div>
    {/if}
    <Input label="应用名称" bind:value={newClient.name} required placeholder="我的应用" />
    <div class="flex flex-col gap-1.5">
      <label class="text-body-medium text-nya-text-primary">Redirect URI <span class="text-nya-text-tertiary text-small">(每行一个)</span></label>
      <textarea
        bind:value={newClient.redirect_uris}
        required
        rows="3"
        placeholder="https://my-app.com/callback"
        class="w-full px-3 py-2 bg-nya-surface border border-nya-border rounded-nya-sm text-body text-nya-text-primary placeholder-nya-text-tertiary font-mono text-small focus:border-nya-primary focus:ring-2 focus:ring-nya-primary/24 focus:outline-none"
      ></textarea>
    </div>
    <label class="flex items-center gap-2 cursor-pointer">
      <input type="checkbox" bind:checked={newClient.is_public} class="rounded" />
      <span class="text-body text-nya-text-primary">公共客户端（SPA / 移动端）</span>
    </label>
    <div class="flex justify-end gap-2 pt-2">
      <Button variant="secondary" onclick={() => (showCreate = false)}>取消</Button>
      <Button type="submit" variant="primary">创建</Button>
    </div>
  </form>
</Modal>
