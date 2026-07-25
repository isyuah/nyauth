<script lang="ts">
  import { api } from '$lib/api';
  import { onMount } from 'svelte';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Select from '$lib/components/ui/Select.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import Card from '$lib/components/ui/Card.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import EmptyState from '$lib/components/ui/EmptyState.svelte';
  import { Plus, KeyRound, CheckCircle, XCircle, ExternalLink, Loader2 } from 'lucide-svelte';

  let providers = $state<any[]>([]);
  let showCreate = $state(false);
  let showEdit = $state(false);
  let editingProvider = $state<any>(null);
  let editForm = $state({ client_id: '', client_secret: '' });
  let newProvider = $state({ name: '', type: 'github', client_id: '', client_secret: '', discovery_url: '' });
  let createError = $state('');
  let editError = $state('');
  let actionError = $state('');
  let callbackOrigin = $state('https://auth.example.com');
  let testResults = $state<Record<string, { loading?: boolean; success?: boolean; latency?: number; error?: string; status_code?: number }>>({});

  onMount(() => {
    callbackOrigin = window.location.origin;
    loadProviders();
  });

  function callbackURL(name: string): string {
    const pathName = name.trim();
    return `${callbackOrigin}/auth/${pathName ? encodeURIComponent(pathName) : '{name}'}/callback`;
  }

  async function loadProviders() {
    try { providers = await api.admin.getProviders(); actionError = ''; }
    catch (err) { actionError = err instanceof Error ? err.message : 'Provider 列表加载失败'; }
  }

  async function handleCreate(e: Event) {
    e.preventDefault();
    createError = '';
    try {
      await api.admin.createProvider(newProvider);
      showCreate = false;
      newProvider = { name: '', type: 'github', client_id: '', client_secret: '', discovery_url: '' };
      loadProviders();
    } catch (err) { createError = err instanceof Error ? err.message : '创建失败'; }
  }

  async function handleTest(name: string) {
    testResults[name] = { loading: true };
    testResults = { ...testResults };
    try {
      const res = await api.admin.testProvider(name);
      testResults[name] = { success: res.success, latency: res.latency_ms, error: res.error, status_code: res.status_code };
    } catch (err) {
      testResults[name] = { success: false, error: err instanceof Error ? err.message : '测试失败' };
    }
    testResults = { ...testResults };
  }

  function openEdit(p: any) {
    editingProvider = p;
    editForm = { client_id: '', client_secret: '' };
    editError = '';
    showEdit = true;
  }

  async function handleEdit(e: Event) {
    e.preventDefault();
    editError = '';
    try {
      const data: any = {};
      if (editForm.client_id) data.client_id = editForm.client_id;
      if (editForm.client_secret) data.client_secret = editForm.client_secret;
      await api.admin.updateProvider(editingProvider.name, data);
      showEdit = false;
      loadProviders();
    } catch (err) { editError = err instanceof Error ? err.message : '更新失败'; }
  }

  async function toggleProvider(provider: any) {
    actionError = '';
    try {
      await api.admin.updateProvider(provider.name, { enabled: !provider.enabled });
      await loadProviders();
    } catch (err) {
      actionError = err instanceof Error ? err.message : '状态更新失败';
    }
  }

  async function deleteProvider(name: string) {
    if (!confirm(`删除 Provider “${name}” 后将无法继续使用它登录或绑定。确定继续吗？`)) return;
    actionError = '';
    try {
      await api.admin.deleteProvider(name);
      await loadProviders();
    } catch (err) {
      actionError = err instanceof Error ? err.message : '删除失败';
    }
  }

  const typeLabels: Record<string, string> = { github: 'GitHub', google: 'Google', generic: '通用 OIDC' };
  const typeColors: Record<string, string> = { github: 'var(--nya-text-primary)', google: 'var(--nya-blue)', generic: 'var(--nya-orange)' };

  const setupGuides: Record<string, { title: string; url: string; steps: string[] }> = {
    github: {
      title: 'GitHub OAuth App',
      url: 'https://github.com/settings/developers',
      steps: [
        '打开 GitHub Developer Settings → OAuth Apps → New OAuth App',
        'Application name: 填写你的应用名',
        'Homepage URL: 填写你的域名',
        'Authorization callback URL：使用本页显示的回调地址',
        '创建后复制 Client ID 和 Client Secret 填入上方',
      ],
    },
    google: {
      title: 'Google Cloud Console',
      url: 'https://console.cloud.google.com/apis/credentials',
      steps: [
        '打开 Google Cloud Console → APIs & Services → Credentials',
        'Create Credentials → OAuth client ID',
        'Application type: Web application',
        'Authorized redirect URIs：添加本页显示的回调地址',
        '创建后复制 Client ID 和 Client Secret 填入上方',
      ],
    },
    generic: {
      title: '通用 OIDC Provider',
      url: '',
      steps: [
        '在你的 OIDC Provider 中创建一个 OAuth/OIDC 客户端',
        'Redirect URI：使用本页显示的回调地址',
        '填写 Provider 的 HTTPS OIDC Discovery URL',
        '确认 Provider 的 issuer、签名密钥与客户端配置一致',
        '创建后复制 Client ID 和 Client Secret 填入上方',
      ],
    },
  };
</script>

<svelte:head><title>身份提供者 - Nya</title></svelte:head>

<PageHeader title="身份提供者" description="管理外部 OAuth / OIDC 身份提供商，让用户使用第三方账号登录">
  {#snippet action()}
    <Button variant="primary" onclick={() => (showCreate = true)}><Plus size={16} /> 添加身份提供者</Button>
  {/snippet}
</PageHeader>

{#if callbackOrigin.startsWith('http://')}
  <div class="mb-4 px-4 py-3 rounded-lg" style="background: var(--nya-warning-soft); color: var(--nya-warning); font-size: 13px;">
    当前后台通过 HTTP 打开。该地址仅适用于本地开发；生产环境必须从 HTTPS issuer 打开后台，再复制下方回调地址。
  </div>
{/if}

{#if actionError}
  <div class="mb-4 px-4 py-3 rounded-lg" style="background: var(--nya-danger-soft); color: var(--nya-danger); font-size: 13px;">{actionError}</div>
{/if}

{#if providers.length === 0}
  <EmptyState title="暂无身份提供者" description="添加 GitHub、Google 或其他 OIDC 提供商，让用户使用第三方账号登录。">
    {#snippet icon()}<KeyRound size={48} />{/snippet}
    {#snippet action()}<Button variant="primary" onclick={() => (showCreate = true)}>添加身份提供者</Button>{/snippet}
  </EmptyState>
{:else}
  <div class="space-y-4">
    {#each providers as p}
      {@const test = testResults[p.name]}
      <Card>
        <div class="flex items-start justify-between">
          <div class="flex items-center gap-3">
            <div class="flex items-center justify-center rounded-lg" style="width: 44px; height: 44px; background: var(--nya-surface-muted);">
              <KeyRound size={20} style="color: {typeColors[p.type] || 'var(--nya-text-secondary)'};" />
            </div>
            <div>
              <h3 style="font-size: 15px; font-weight: 650; color: var(--nya-text-primary);">{p.name}</h3>
              <div class="flex items-center gap-2 mt-0.5">
                <Badge variant="info">{typeLabels[p.type] || p.type}</Badge>
                <Badge variant={p.enabled === false ? 'default' : 'success'}>{p.enabled === false ? '已禁用' : '已启用'}</Badge>
              </div>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <Button variant="ghost" size="sm" onclick={() => openEdit(p)}>编辑凭据</Button>
            <Button variant="ghost" size="sm" onclick={() => toggleProvider(p)}>{p.enabled === false ? '启用' : '禁用'}</Button>
            <Button variant="soft" size="sm" onclick={() => handleTest(p.name)}>
              {#if test?.loading}
                <Loader2 size={14} class="animate-spin" /> 测试中...
              {:else}
                测试连接
              {/if}
            </Button>
            <Button variant="ghost" size="sm" onclick={() => deleteProvider(p.name)}>删除</Button>
          </div>
        </div>

        <!-- 测试结果 -->
        {#if test && !test.loading}
          <div class="mt-3 px-3 py-2 rounded-lg" style="background: {test.success ? 'var(--nya-success-soft)' : 'var(--nya-danger-soft)'}; font-size: 13px;">
            {#if test.success}
              <span class="flex items-center gap-1.5" style="color: var(--nya-success);">
                <CheckCircle size={14} /> 连接成功
                {#if test.latency !== undefined}
                  <span style="color: var(--nya-text-tertiary); margin-left: 8px;">延迟 {test.latency}ms</span>
                {/if}
                {#if test.status_code}
                  <span style="color: var(--nya-text-tertiary); margin-left: 8px;">HTTP {test.status_code}</span>
                {/if}
              </span>
            {:else}
              <span class="flex items-center gap-1.5" style="color: var(--nya-danger);">
                <XCircle size={14} /> 连接失败: {test.error || '未知错误'}
              </span>
            {/if}
          </div>
        {/if}

        <!-- 配置说明 -->
        {#if setupGuides[p.type]}
          <details class="mt-3">
            <summary style="font-size: 12px; color: var(--nya-primary); cursor: pointer;">配置指南</summary>
            <div class="mt-2 px-3 py-2 rounded-lg" style="background: var(--nya-surface-muted); font-size: 12px;">
              <ol style="padding-left: 16px; line-height: 1.8; color: var(--nya-text-secondary);">
                {#each setupGuides[p.type].steps as step}
                  <li>{step}</li>
                {/each}
              </ol>
              {#if setupGuides[p.type].url}
                <a href={setupGuides[p.type].url} target="_blank" class="inline-flex items-center gap-1 mt-2" style="color: var(--nya-primary); font-size: 12px;">
                  打开管理页面 <ExternalLink size={12} />
                </a>
              {/if}
              <p class="mt-2" style="font-size: 11px; color: var(--nya-text-tertiary);">
                Callback URL: <code style="background: var(--nya-surface); padding: 1px 4px; border-radius: 4px;">{callbackURL(p.name)}</code>
              </p>
            </div>
          </details>
        {/if}
      </Card>
    {/each}
  </div>
{/if}

<!-- 添加 Modal -->
<Modal bind:open={showCreate} title="添加身份提供者" size="md">
  <form onsubmit={handleCreate} class="space-y-4">
    {#if createError}
      <div class="px-3 py-2 rounded-lg" style="background: var(--nya-danger-soft); font-size: 12px; color: var(--nya-danger);">{createError}</div>
    {/if}
    <Input label="名称" bind:value={newProvider.name} required placeholder="例如: github, google, my-sso" />
    <Select label="类型" bind:value={newProvider.type} options={[
      { value: 'github', label: 'GitHub' },
      { value: 'google', label: 'Google' },
      { value: 'generic', label: '通用 OIDC' },
    ]} />
    <Input label="Client ID" bind:value={newProvider.client_id} required mono placeholder="从 OAuth Provider 获取" />
    <Input label="Client Secret" type="password" bind:value={newProvider.client_secret} required placeholder="从 OAuth Provider 获取" />
    {#if newProvider.type === 'generic'}
      <Input label="Discovery URL" bind:value={newProvider.discovery_url} placeholder="https://idp.example.com/.well-known/openid-configuration" />
    {/if}
    {#if setupGuides[newProvider.type]}
      <div class="px-3 py-2 rounded-lg" style="background: var(--nya-info-soft); font-size: 12px; color: var(--nya-info);">
        Callback URL 需要在 {typeLabels[newProvider.type]} 中设置为:
        <code style="display: block; margin-top: 4px; background: rgba(0,0,0,0.05); padding: 2px 6px; border-radius: 4px;">
          {callbackURL(newProvider.name)}
        </code>
      </div>
    {/if}
    <div class="flex justify-end gap-2 pt-2">
      <Button variant="secondary" onclick={() => (showCreate = false)}>取消</Button>
      <Button type="submit" variant="primary">添加</Button>
    </div>
  </form>
</Modal>

<!-- 编辑凭据 Modal -->
<Modal bind:open={showEdit} title="编辑 Provider 凭据 - {editingProvider?.name || ''}" size="sm">
  <form onsubmit={handleEdit} class="space-y-4">
    {#if editError}
      <div class="px-3 py-2 rounded-lg" style="background: var(--nya-danger-soft); font-size: 12px; color: var(--nya-danger);">{editError}</div>
    {/if}
    <div class="px-3 py-2 rounded-lg" style="background: var(--nya-warning-soft); font-size: 12px; color: var(--nya-warning);">
      更新 Client Secret 后，旧 Secret 将立即失效。
    </div>
    <Input label="Client ID（留空则不更新）" bind:value={editForm.client_id} mono placeholder="留空保持不变" />
    <Input label="Client Secret（留空则不更新）" type="password" bind:value={editForm.client_secret} placeholder="留空保持不变" />
    <div class="flex justify-end gap-2 pt-2">
      <Button variant="secondary" onclick={() => (showEdit = false)}>取消</Button>
      <Button type="submit" variant="primary">保存</Button>
    </div>
  </form>
</Modal>
