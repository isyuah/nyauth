<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type CreateProviderInput,
    type ExternalProvider,
    type ProviderTestResult,
    type UpdateProviderInput,
  } from '$lib/api';
  import { parseTokenList } from '$lib/admin-form-utils';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import ProviderIcon from '$lib/components/identity/ProviderIcon.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Card from '$lib/components/ui/Card.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import Select from '$lib/components/ui/Select.svelte';
  import { CheckCircle, ExternalLink, Plus, XCircle } from 'lucide-svelte';

  type ProviderTestState = { revision: number; loading: boolean; result?: ProviderTestResult; error?: string };
  type ProviderForm = {
    name: string;
    display_name: string;
    icon_key: string;
    type: 'github' | 'google' | 'generic';
    client_id: string;
    client_secret: string;
    scopes: string;
    discovery_url: string;
    authorization_url: string;
    token_url: string;
    userinfo_url: string;
    enabled: boolean;
    import_avatar: boolean;
    avatar_allowed_hosts: string;
  };
  type ProviderEditForm = Omit<ProviderForm, 'name' | 'type'>;

  const typeLabels: Record<string, string> = { github: 'GitHub', google: 'Google', generic: '通用 OIDC' };
  const iconOptions = [
    { value: 'auto', label: '自动匹配类型' },
    { value: 'github', label: 'GitHub' },
    { value: 'google', label: 'Google' },
    { value: 'key', label: '钥匙' },
    { value: 'link', label: '链接' },
    { value: 'globe', label: '地球' },
  ];
  const setupGuides: Record<string, { title: string; url: string; steps: string[] }> = {
    github: {
      title: 'GitHub OAuth App',
      url: 'https://github.com/settings/developers',
      steps: ['创建 GitHub OAuth App', 'Homepage URL 填写你的应用地址', 'Authorization callback URL 使用本页回调地址', '复制 Client ID 和 Client Secret'],
    },
    google: {
      title: 'Google Cloud Console',
      url: 'https://console.cloud.google.com/apis/credentials',
      steps: ['创建 Web application 类型的 OAuth client', 'Authorized redirect URIs 添加本页回调地址', '复制 Client ID 和 Client Secret'],
    },
    generic: {
      title: '通用 OIDC Provider',
      url: '',
      steps: ['在上游创建 OIDC 客户端', 'Redirect URI 使用本页回调地址', '填写 HTTPS Discovery URL', '确认 issuer、签名密钥和客户端配置一致'],
    },
  };

  let providers = $state<ExternalProvider[]>([]);
  let loading = $state(true);
  let pageError = $state('');
  let issuer = $state('');
  let issuerLoading = $state(true);
  let issuerError = $state('');
  let showCreate = $state(false);
  let creating = $state(false);
  let showEdit = $state(false);
  let editingProvider = $state<ExternalProvider | null>(null);
  let editing = $state(false);
  let editForm = $state<ProviderEditForm>({ display_name: '', icon_key: 'auto', client_id: '', client_secret: '', scopes: '', discovery_url: '', authorization_url: '', token_url: '', userinfo_url: '', enabled: true, import_avatar: false, avatar_allowed_hosts: '' });
  let newProvider = $state<ProviderForm>({ name: '', display_name: '', icon_key: 'auto', type: 'github', client_id: '', client_secret: '', scopes: '', discovery_url: '', authorization_url: '', token_url: '', userinfo_url: '', enabled: true, import_avatar: false, avatar_allowed_hosts: '' });
  let createError = $state('');
  let editError = $state('');
  let testResults = $state<Record<string, ProviderTestState>>({});
  let deleteTarget = $state<ExternalProvider | null>(null);
  let deleteOpen = $state(false);
  let deleteError = $state('');

  function invalidateTestResult(name: string) {
    if (!(name in testResults)) return;
    const next = { ...testResults };
    delete next[name];
    testResults = next;
  }

  function callbackURL(name: string): string {
    if (!issuer) return '';
    const providerName = name.trim();
    return `${issuer.replace(/\/$/, '')}/auth/${providerName ? encodeURIComponent(providerName) : '{name}'}/callback`;
  }

  async function loadProviders() {
    loading = true;
    pageError = '';
    try {
      const loaded = await api.admin.getProviders();
      const revisions = new Map(loaded.map((provider) => [provider.name, provider.revision]));
      testResults = Object.fromEntries(
        Object.entries(testResults).filter(([name, state]) => revisions.get(name) === state.revision),
      );
      providers = loaded;
    } catch (cause) {
      pageError = cause instanceof Error ? cause.message : 'Provider 列表加载失败';
    } finally {
      loading = false;
    }
  }

  async function loadIssuer() {
    issuerLoading = true;
    issuerError = '';
    try {
      issuer = (await api.discovery()).issuer;
    } catch (cause) {
      issuer = '';
      issuerError = cause instanceof Error ? cause.message : 'Issuer 信息加载失败';
    } finally {
      issuerLoading = false;
    }
  }

  async function handleCreate(event: SubmitEvent) {
    event.preventDefault();
    creating = true;
    createError = '';
    try {
      const payload: CreateProviderInput = {
        name: newProvider.name.trim(),
        display_name: newProvider.display_name.trim() || undefined,
        icon_key: newProvider.icon_key,
        type: newProvider.type,
        client_id: newProvider.client_id.trim(),
        client_secret: newProvider.client_secret,
        enabled: newProvider.enabled,
        scopes: parseTokenList(newProvider.scopes),
        discovery_url: newProvider.discovery_url.trim() || undefined,
        authorization_url: newProvider.authorization_url.trim() || undefined,
        token_url: newProvider.token_url.trim() || undefined,
        userinfo_url: newProvider.userinfo_url.trim() || undefined,
        import_avatar: newProvider.import_avatar,
        avatar_allowed_hosts: newProvider.type === 'generic' ? parseTokenList(newProvider.avatar_allowed_hosts) : [],
      };
      if (newProvider.type === 'generic' && !payload.discovery_url) {
        createError = '通用 OIDC Provider 必须填写 HTTPS Discovery URL。';
        return;
      }
      if (newProvider.type === 'generic' && newProvider.import_avatar && payload.avatar_allowed_hosts?.length === 0) {
        createError = '通用 OIDC 开启头像导入时必须填写至少一个精确图片主机。';
        return;
      }
      await api.admin.createProvider(payload);
      showCreate = false;
      newProvider = { name: '', display_name: '', icon_key: 'auto', type: 'github', client_id: '', client_secret: '', scopes: '', discovery_url: '', authorization_url: '', token_url: '', userinfo_url: '', enabled: true, import_avatar: false, avatar_allowed_hosts: '' };
      await loadProviders();
    } catch (cause) {
      createError = cause instanceof Error ? cause.message : '创建失败';
    } finally {
      creating = false;
    }
  }

  async function handleTest(provider: ExternalProvider) {
    const { name, revision } = provider;
    testResults = { ...testResults, [name]: { revision, loading: true } };
    try {
      const result = await api.admin.testProvider(name);
      if (testResults[name]?.revision === revision) {
        testResults = { ...testResults, [name]: { revision, loading: false, result } };
      }
    } catch (cause) {
      if (testResults[name]?.revision === revision) {
        testResults = { ...testResults, [name]: { revision, loading: false, error: cause instanceof Error ? cause.message : '配置校验失败' } };
      }
    }
  }

  function openEdit(provider: ExternalProvider) {
    editingProvider = provider;
    editForm = {
      display_name: provider.display_name,
      icon_key: provider.icon_key,
      client_id: provider.client_id,
      client_secret: '',
      scopes: provider.scopes.join('\n'),
      discovery_url: provider.discovery_url || '',
      authorization_url: provider.authorization_url || '',
      token_url: provider.token_url || '',
      userinfo_url: provider.userinfo_url || '',
      enabled: provider.enabled,
      import_avatar: provider.import_avatar,
      avatar_allowed_hosts: provider.avatar_allowed_hosts.join('\n'),
    };
    editError = '';
    showEdit = true;
  }

  async function handleEdit(event: SubmitEvent) {
    event.preventDefault();
    if (!editingProvider) return;
    const clientID = editForm.client_id.trim();
    if (!clientID) {
      editError = 'Client ID 不能为空。';
      return;
    }
    const discoveryURL = editForm.discovery_url.trim();
    if (editingProvider.type === 'generic' && !discoveryURL) {
      editError = '通用 OIDC Provider 必须填写 HTTPS Discovery URL。';
      return;
    }
    if (editingProvider.discovery_url && !discoveryURL) {
      editError = '当前后端不允许清空已配置的 Discovery URL。';
      return;
    }
    const payload: UpdateProviderInput = {
      display_name: editForm.display_name.trim(),
      icon_key: editForm.icon_key,
      client_id: clientID,
      scopes: parseTokenList(editForm.scopes),
      authorization_url: editForm.authorization_url.trim(),
      token_url: editForm.token_url.trim(),
      userinfo_url: editForm.userinfo_url.trim(),
      enabled: editForm.enabled,
      import_avatar: editForm.import_avatar,
      avatar_allowed_hosts: editingProvider.type === 'generic' ? parseTokenList(editForm.avatar_allowed_hosts) : [],
    };
    if (discoveryURL) payload.discovery_url = discoveryURL;
    if (editingProvider.type === 'generic' && editForm.import_avatar && payload.avatar_allowed_hosts?.length === 0) {
      editError = '通用 OIDC 开启头像导入时必须填写至少一个精确图片主机。';
      return;
    }
    if (editForm.client_secret) payload.client_secret = editForm.client_secret;
    editing = true;
    editError = '';
    try {
      await api.admin.updateProvider(editingProvider.name, payload);
      invalidateTestResult(editingProvider.name);
      showEdit = false;
      await loadProviders();
    } catch (cause) {
      editError = cause instanceof Error ? cause.message : '更新失败';
    } finally {
      editing = false;
    }
  }

  async function toggleProvider(provider: ExternalProvider) {
    pageError = '';
    try {
      await api.admin.updateProvider(provider.name, { enabled: !provider.enabled });
      invalidateTestResult(provider.name);
      await loadProviders();
    } catch (cause) {
      pageError = cause instanceof Error ? cause.message : '状态更新失败';
    }
  }

  function requestDelete(provider: ExternalProvider) {
    deleteTarget = provider;
    deleteError = '';
    deleteOpen = true;
  }

  async function deleteProvider() {
    if (!deleteTarget) return;
    deleteError = '';
    try {
      await api.admin.deleteProvider(deleteTarget.name);
      await loadProviders();
    } catch (cause) {
      deleteError = cause instanceof Error ? cause.message : '删除失败';
      throw cause;
    }
  }

  function validationPassed(result: ProviderTestResult): boolean {
    return result.configuration_valid && result.authorization_endpoint_valid && result.discovery_reachable !== false;
  }

  onMount(() => {
    void loadProviders();
    void loadIssuer();
  });
</script>

<svelte:head><title>身份提供者 - Nya</title></svelte:head>

<PageHeader title="身份提供者" description="管理外部 OAuth / OIDC 登录配置">
  {#snippet action()}<Button variant="primary" onclick={() => (showCreate = true)}><Plus size={16} /> 添加身份提供者</Button>{/snippet}
</PageHeader>

{#if issuer.startsWith('http://')}
  <div class="mb-4 rounded-nya-sm bg-nya-warning-soft px-4 py-3 text-small text-nya-warning">当前 issuer 使用 HTTP，仅适合本地开发；生产环境必须使用 HTTPS。</div>
{:else if issuerError && !issuerLoading}
  <div class="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-4 py-3 text-small text-nya-danger" role="alert">
    <span>无法加载公开 Issuer 信息，暂时不能生成 Callback URL。Provider 列表和配置操作不受影响。</span>
    <Button variant="secondary" size="sm" onclick={loadIssuer}>重试</Button>
  </div>
{/if}

<ResourceState
  {loading}
  error={pageError}
  empty={providers.length === 0}
  emptyTitle="暂无身份提供者"
  emptyDescription="添加 GitHub、Google 或其他 OIDC 提供商，让用户使用第三方账号登录。"
  onretry={loadProviders}
>
  {#snippet emptyAction()}<Button variant="primary" onclick={() => (showCreate = true)}>添加身份提供者</Button>{/snippet}
  {#snippet children()}
    <div class="space-y-4">
      {#each providers as provider}
        {@const test = testResults[provider.name]?.revision === provider.revision ? testResults[provider.name] : undefined}
        <Card>
          <div class="flex flex-col justify-between gap-4 lg:flex-row lg:items-start">
            <div class="flex items-center gap-3">
              <span class="flex h-11 w-11 items-center justify-center rounded-nya-md bg-nya-surface-muted text-nya-text-primary"><ProviderIcon type={provider.type} iconKey={provider.icon_key} size={20} /></span>
              <div><h2 class="text-card-title text-nya-text-primary">{provider.display_name}</h2><p class="mt-0.5 font-mono text-micro text-nya-text-tertiary">{provider.name}</p><div class="mt-1 flex flex-wrap items-center gap-2"><Badge variant="info">{typeLabels[provider.type] || provider.type}</Badge><Badge variant={provider.enabled ? 'success' : 'default'}>{provider.enabled ? '已启用' : '已禁用'}</Badge>{#if provider.import_avatar}<Badge variant="warning">首次导入头像</Badge>{/if}<span class="text-micro text-nya-text-tertiary">配置修订 #{provider.revision}</span></div></div>
            </div>
            <div class="flex flex-wrap items-center gap-2">
              <Button variant="ghost" size="sm" onclick={() => openEdit(provider)}>编辑配置</Button>
              <Button variant="ghost" size="sm" onclick={() => toggleProvider(provider)}>{provider.enabled ? '禁用' : '启用'}</Button>
              <Button variant="soft" size="sm" onclick={() => handleTest(provider)} loading={test?.loading ?? false}>配置校验</Button>
              <Button variant="ghost" size="sm" onclick={() => requestDelete(provider)}>删除</Button>
            </div>
          </div>

          <dl class="mt-4 grid gap-2 rounded-nya-sm bg-nya-surface-muted p-3 text-small md:grid-cols-2">
            <div><dt class="text-nya-text-tertiary">Client ID</dt><dd class="truncate font-mono text-nya-text-primary" title={provider.client_id}>{provider.client_id}</dd></div>
            <div><dt class="text-nya-text-tertiary">Scopes</dt><dd class="text-nya-text-primary">{provider.scopes.length > 0 ? provider.scopes.join(' ') : '未配置'}</dd></div>
            <div class="md:col-span-2"><dt class="text-nya-text-tertiary">Discovery URL</dt><dd class="break-all font-mono text-nya-text-primary">{provider.discovery_url || '未配置'}</dd></div>
            <div><dt class="text-nya-text-tertiary">Authorization URL</dt><dd class="break-all font-mono text-nya-text-primary">{provider.authorization_url || '由 Provider 默认或 Discovery 决定'}</dd></div>
            <div><dt class="text-nya-text-tertiary">Token URL</dt><dd class="break-all font-mono text-nya-text-primary">{provider.token_url || '由 Provider 默认或 Discovery 决定'}</dd></div>
            <div class="md:col-span-2"><dt class="text-nya-text-tertiary">Userinfo URL</dt><dd class="break-all font-mono text-nya-text-primary">{provider.userinfo_url || '由 Provider 默认或 Discovery 决定'}</dd></div>
            <div class="md:col-span-2"><dt class="text-nya-text-tertiary">首次头像导入</dt><dd class="text-nya-text-primary">{provider.import_avatar ? (provider.type === 'generic' ? `已启用 · ${provider.avatar_allowed_hosts.join(', ')}` : '已启用 · 使用内置安全主机') : '关闭（默认）'}</dd></div>
          </dl>

          {#if test && !test.loading}
            {@const valid = test.result ? validationPassed(test.result) : false}
            <div class="mt-4 rounded-nya-sm px-3 py-3 text-small {valid ? 'bg-nya-success-soft' : 'bg-nya-danger-soft'}">
              {#if test.result}
                <div class="flex items-start gap-2 {valid ? 'text-nya-success' : 'text-nya-danger'}">{#if valid}<CheckCircle size={15} class="mt-0.5 shrink-0" />{:else}<XCircle size={15} class="mt-0.5 shrink-0" />{/if}<div><p class="font-semibold">{valid ? '配置有效' : '配置存在问题'}</p><p class="mt-0.5">{test.result.message}</p>{#if test.result.latency_ms !== undefined}<p class="mt-1 text-nya-text-tertiary">校验耗时 {test.result.latency_ms} ms</p>{/if}</div></div>
              {:else}
                <div class="flex items-center gap-2 text-nya-danger"><XCircle size={15} /> {test.error || '配置校验失败'}</div>
              {/if}
              <p class="mt-2 text-nya-text-tertiary">该检查不会验证 Client Secret；客户端凭据只会在真实登录时由上游验证。</p>
            </div>
          {/if}

          <details class="mt-4">
            <summary class="cursor-pointer text-small text-nya-primary">配置指南</summary>
            <div class="mt-2 rounded-nya-sm bg-nya-surface-muted px-3 py-3 text-small text-nya-text-secondary">
              <ol class="list-decimal space-y-1 pl-5">{#each setupGuides[provider.type]?.steps || [] as step}<li>{step}</li>{/each}</ol>
              {#if setupGuides[provider.type]?.url}<a href={setupGuides[provider.type].url} target="_blank" rel="noreferrer" class="mt-2 inline-flex items-center gap-1 text-nya-primary hover:underline">打开管理页面 <ExternalLink size={12} /></a>{/if}
              {#if callbackURL(provider.name)}<p class="mt-2 break-all text-micro text-nya-text-tertiary">Callback URL: <code>{callbackURL(provider.name)}</code></p>{/if}
            </div>
          </details>
        </Card>
      {/each}
    </div>
  {/snippet}
</ResourceState>

<Modal bind:open={showCreate} title="添加身份提供者" description="凭据会在服务端加密保存" size="md">
  <form onsubmit={handleCreate} class="space-y-4">
    {#if createError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{createError}</p>{/if}
    <Input id="provider-name" label="技术标识" bind:value={newProvider.name} required placeholder="例如 github 或 company-sso" />
    <Input id="provider-display-name" label="显示名称" bind:value={newProvider.display_name} placeholder="留空时使用技术标识" />
    <Select id="provider-type" label="类型" bind:value={newProvider.type} options={[{ value: 'github', label: 'GitHub' }, { value: 'google', label: 'Google' }, { value: 'generic', label: '通用 OIDC' }]} />
    <div class="grid grid-cols-[1fr_auto] items-end gap-3"><Select id="provider-icon" label="图标" bind:value={newProvider.icon_key} options={iconOptions} /><span class="flex h-[38px] w-[38px] items-center justify-center rounded-nya-sm border border-nya-border bg-nya-surface-muted text-nya-text-primary"><ProviderIcon type={newProvider.type} iconKey={newProvider.icon_key} size={19} /></span></div>
    <Input id="provider-client-id" label="Client ID" bind:value={newProvider.client_id} required mono placeholder="从上游 Provider 获取" />
    <Input id="provider-client-secret" label="Client Secret" type="password" bind:value={newProvider.client_secret} required autocomplete="off" placeholder="从上游 Provider 获取" />
    <Input id="provider-scopes" label="Scopes" bind:value={newProvider.scopes} mono placeholder="openid profile email" />
    <Input id="provider-discovery" label="Discovery URL" bind:value={newProvider.discovery_url} required={newProvider.type === 'generic'} placeholder="https://idp.example.com/.well-known/openid-configuration" />
    <div class="grid gap-4 sm:grid-cols-2"><Input id="provider-authorization-url" label="Authorization URL" bind:value={newProvider.authorization_url} placeholder="可选，自定义授权端点" /><Input id="provider-token-url" label="Token URL" bind:value={newProvider.token_url} placeholder="可选，自定义 Token 端点" /></div>
    <Input id="provider-userinfo-url" label="Userinfo URL" bind:value={newProvider.userinfo_url} placeholder="可选，自定义 Userinfo 端点" />
    <label class="flex items-start gap-2 rounded-nya-sm bg-nya-surface-muted px-3 py-2"><input type="checkbox" bind:checked={newProvider.import_avatar} class="mt-0.5" /><span><span class="block text-body text-nya-text-primary">首次建号时导入上游头像</span><span class="block text-small text-nya-text-tertiary">默认关闭；仅首次创建本地账号时异步转存，之后不会同步或覆盖用户头像。</span></span></label>
    {#if newProvider.import_avatar && newProvider.type === 'generic'}<Input id="provider-avatar-hosts" label="允许的图片主机" bind:value={newProvider.avatar_allowed_hosts} mono placeholder="images.example.com（每行一个精确主机）" />{:else if newProvider.import_avatar}<p class="rounded-nya-sm bg-nya-info-soft px-3 py-2 text-small text-nya-info">GitHub / Google 使用内置图片主机 allowlist，不接受自定义地址。</p>{/if}
    <label class="flex items-start gap-2 rounded-nya-sm bg-nya-surface-muted px-3 py-2"><input type="checkbox" bind:checked={newProvider.enabled} class="mt-0.5" /><span><span class="block text-body text-nya-text-primary">创建后立即启用</span><span class="block text-small text-nya-text-tertiary">关闭时，配置会以禁用状态一次性保存，不会进入登录运行时。</span></span></label>
    {#if callbackURL(newProvider.name)}<div class="rounded-nya-sm bg-nya-info-soft px-3 py-2 text-small text-nya-info">在上游设置 Callback URL：<code class="mt-1 block break-all">{callbackURL(newProvider.name)}</code></div>{/if}
    <div class="flex justify-end gap-2 pt-2"><Button variant="secondary" onclick={() => (showCreate = false)} disabled={creating}>取消</Button><Button type="submit" variant="primary" loading={creating}>添加</Button></div>
  </form>
</Modal>

<Modal bind:open={showEdit} title={`编辑 Provider 配置 · ${editingProvider?.display_name || ''}`} description="技术标识和类型创建后不可变更" size="lg">
  <form onsubmit={handleEdit} class="space-y-4">
    {#if editError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{editError}</p>{/if}
    <p class="rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning">当前配置修订 #{editingProvider?.revision ?? '-'}。Client Secret 留空会保持原值；填写新值则立即替换。</p>
    <div class="grid gap-4 sm:grid-cols-2"><Input id="edit-provider-display-name" label="显示名称" bind:value={editForm.display_name} required /><div><span class="mb-1.5 block text-body-medium text-nya-text-primary">技术标识 / 类型</span><p class="rounded-nya-sm bg-nya-surface-muted px-3 py-2 text-small text-nya-text-secondary">{editingProvider?.name} · {editingProvider ? (typeLabels[editingProvider.type] || editingProvider.type) : ''}</p></div></div>
    <div class="grid grid-cols-[1fr_auto] items-end gap-3"><Select id="edit-provider-icon" label="图标" bind:value={editForm.icon_key} options={iconOptions} /><span class="flex h-[38px] w-[38px] items-center justify-center rounded-nya-sm border border-nya-border bg-nya-surface-muted text-nya-text-primary"><ProviderIcon type={editingProvider?.type} iconKey={editForm.icon_key} size={19} /></span></div>
    <Input id="edit-provider-client-id" label="Client ID" bind:value={editForm.client_id} mono required />
    <Input id="edit-provider-client-secret" label="Client Secret" type="password" bind:value={editForm.client_secret} autocomplete="off" placeholder="留空保持不变" />
    <Input id="edit-provider-scopes" label="Scopes" bind:value={editForm.scopes} mono placeholder="openid profile email" />
    <Input id="edit-provider-discovery" label="Discovery URL" bind:value={editForm.discovery_url} required={editingProvider?.type === 'generic'} />
    <div class="grid gap-4 sm:grid-cols-2"><Input id="edit-provider-authorization-url" label="Authorization URL" bind:value={editForm.authorization_url} placeholder="留空以使用默认值" /><Input id="edit-provider-token-url" label="Token URL" bind:value={editForm.token_url} placeholder="留空以使用默认值" /></div>
    <Input id="edit-provider-userinfo-url" label="Userinfo URL" bind:value={editForm.userinfo_url} placeholder="留空以使用默认值" />
    <label class="flex items-start gap-2 rounded-nya-sm bg-nya-surface-muted px-3 py-2"><input type="checkbox" bind:checked={editForm.import_avatar} class="mt-0.5" /><span><span class="block text-body text-nya-text-primary">首次建号时导入上游头像</span><span class="block text-small text-nya-text-tertiary">只影响以后首次通过此 Provider 创建的账号。</span></span></label>
    {#if editForm.import_avatar && editingProvider?.type === 'generic'}<Input id="edit-provider-avatar-hosts" label="允许的图片主机" bind:value={editForm.avatar_allowed_hosts} mono placeholder="images.example.com（每行一个精确主机）" />{:else if editForm.import_avatar}<p class="rounded-nya-sm bg-nya-info-soft px-3 py-2 text-small text-nya-info">此 Provider 使用内置图片主机 allowlist。</p>{/if}
    <label class="flex items-start gap-2 rounded-nya-sm bg-nya-surface-muted px-3 py-2"><input type="checkbox" bind:checked={editForm.enabled} class="mt-0.5" /><span><span class="block text-body text-nya-text-primary">启用 Provider</span><span class="block text-small text-nya-text-tertiary">禁用后会立即从运行时 Provider 快照移除。</span></span></label>
    <div class="flex justify-end gap-2 pt-2"><Button variant="secondary" onclick={() => (showEdit = false)} disabled={editing}>取消</Button><Button type="submit" variant="primary" loading={editing}>保存</Button></div>
  </form>
</Modal>

<ConfirmDialog
  bind:open={deleteOpen}
  title="删除身份提供者"
  description={`删除后，用户将无法继续通过“${deleteTarget?.name || ''}”登录或绑定身份。`}
  confirmLabel="永久删除"
  confirmationText={deleteTarget?.name || ''}
  error={deleteError}
  onconfirm={deleteProvider}
/>
