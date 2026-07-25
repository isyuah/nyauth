<script lang="ts">
  import { api } from '$lib/api';
  import { onMount } from 'svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import EmptyState from '$lib/components/ui/EmptyState.svelte';
  import CopyField from '$lib/components/data-display/CopyField.svelte';
  import { Plus, AppWindow, ExternalLink } from 'lucide-svelte';

  let clients = $state<any[]>([]);
  let total = $state(0);
  let loading = $state(true);
  let showCreate = $state(false);
  let createError = $state('');
  let createdSecret = $state('');
  let newApp = $state({ name: '', redirect_uris: '' });

  onMount(() => loadApps());

  async function loadApps() {
    loading = true;
    try {
      const token = localStorage.getItem('nya_token');
      const res = await fetch('/api/my/clients', { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) {
        const data = await res.json();
        clients = data.items || [];
        total = data.total || 0;
      }
    } catch {} finally { loading = false; }
  }

  async function handleCreate(e: Event) {
    e.preventDefault();
    createError = '';
    createdSecret = '';
    try {
      const token = localStorage.getItem('nya_token');
      const res = await fetch('/api/my/clients', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          name: newApp.name,
          redirect_uris: newApp.redirect_uris.split('\n').filter(Boolean),
        }),
      });
      if (!res.ok) {
        const body = await res.json();
        throw new Error(body.error || '创建失败');
      }
      const result = await res.json();
      if (result.secret) createdSecret = result.secret;
      showCreate = false;
      newApp = { name: '', redirect_uris: '' };
      loadApps();
    } catch (err) { createError = err instanceof Error ? err.message : '创建失败'; }
  }

  async function handleDelete(id: string) {
    if (!confirm('删除后，使用此 Client ID 的集成将立即失效。确定继续吗？')) return;
    try {
      const token = localStorage.getItem('nya_token');
      await fetch(`/api/my/clients/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } });
      loadApps();
    } catch {}
  }
</script>

<svelte:head><title>我的应用 - Nya</title></svelte:head>

<div class="flex items-start justify-between" style="margin-bottom: 24px;">
  <div>
    <h1 style="font-size: 24px; font-weight: 700; color: var(--nya-text-primary); margin: 0;">我的应用</h1>
    <p style="font-size: 14px; color: var(--nya-text-secondary); margin-top: 4px;">管理你创建的 OAuth / OIDC 客户端（上限 10 个）</p>
  </div>
  <Button variant="primary" onclick={() => { createdSecret = ''; showCreate = true; }}>
    <Plus size={16} /> 创建应用
  </Button>
</div>

{#if createdSecret}
  <div class="mb-4 px-5 py-4 rounded-lg" style="background: var(--nya-info-soft); border: 1px solid var(--nya-info)/20;">
    <p style="font-size: 14px; font-weight: 550; color: var(--nya-info); margin-bottom: 8px;">
      请现在复制并安全保存 Client Secret，关闭后将无法再次查看。
    </p>
    <CopyField value={createdSecret} label="Client Secret" />
  </div>
{/if}

{#if loading}
  <div style="color: var(--nya-text-tertiary); text-align: center; padding: 48px;">加载中...</div>
{:else if clients.length === 0}
  <EmptyState title="还没有创建应用" description="创建第一个 OAuth / OIDC 客户端后，就可以接入你的项目了。">
    {#snippet icon()}<AppWindow size={48} />{/snippet}
    {#snippet action()}<Button variant="primary" onclick={() => (showCreate = true)}>创建应用</Button>{/snippet}
  </EmptyState>
{:else}
  <div class="space-y-3">
    {#each clients as cl}
      <div class="bg-[var(--nya-surface)] border border-[var(--nya-border)]" style="padding: 20px; border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card);">
        <div class="flex items-start justify-between">
          <div class="flex items-center gap-3">
            <div class="flex items-center justify-center rounded-lg" style="width: 40px; height: 40px; background: var(--nya-blue-soft);">
              <AppWindow size={20} style="color: var(--nya-blue);" />
            </div>
            <div>
              <h3 style="font-size: 15px; font-weight: 650; color: var(--nya-text-primary); margin: 0;">{cl.name}</h3>
              <CopyField value={cl.id} />
            </div>
          </div>
          <div class="flex items-center gap-2">
            {#if cl.is_public}<Badge variant="warning">Public</Badge>{/if}
            <button onclick={() => handleDelete(cl.id)} style="font-size: 12px; color: var(--nya-danger);">删除</button>
          </div>
        </div>
        <div class="flex flex-wrap gap-1.5 mt-3">
          {#each cl.redirect_uris || [] as uri}
            <code style="font-size: 11px; padding: 2px 8px; background: var(--nya-surface-muted); border-radius: 4px; color: var(--nya-text-secondary);">{uri}</code>
          {/each}
        </div>
      </div>
    {/each}
  </div>
{/if}

<!-- Create Modal -->
<Modal bind:open={showCreate} title="创建应用" size="md">
  <form onsubmit={handleCreate} class="space-y-4">
    {#if createError}
      <div class="px-3 py-2 rounded-lg" style="background: var(--nya-danger-soft); font-size: 12px; color: var(--nya-danger);">{createError}</div>
    {/if}
    <Input label="应用名称" bind:value={newApp.name} required placeholder="我的应用" />
    <div>
      <label class="block mb-1.5" style="font-size: 14px; font-weight: 550; color: var(--nya-text-primary);">Redirect URI <span style="font-size: 12px; color: var(--nya-text-tertiary); font-weight: 400;">(每行一个)</span></label>
      <textarea bind:value={newApp.redirect_uris} required rows="3" placeholder="https://my-app.com/callback"
        style="width: 100%; padding: 8px 12px; background: var(--nya-surface); border: 1px solid var(--nya-border-strong); border-radius: 9px; font-size: 13px; font-family: monospace; color: var(--nya-text-primary); resize: vertical;"></textarea>
    </div>
    <div class="flex justify-end gap-2 pt-2">
      <Button variant="secondary" onclick={() => (showCreate = false)}>取消</Button>
      <Button type="submit" variant="primary">创建</Button>
    </div>
  </form>
</Modal>
