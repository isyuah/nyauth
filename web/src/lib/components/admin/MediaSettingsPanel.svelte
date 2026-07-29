<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    isRecentAuthenticationError,
    type MediaStorageMigration,
    type MediaStorageProfile,
    type MediaStorageSettings,
  } from '$lib/api';
  import { consumeProviderAuthError } from '$lib/stores';
  import { toast } from '$lib/toast';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Switch from '$lib/components/ui/Switch.svelte';
  import { Database, HardDrive, Play, RefreshCw, RotateCcw, ShieldCheck } from 'lucide-svelte';

  type Action = 'load' | 'save' | 'test' | 'migrate' | 'fallback' | 'retry';
  interface PendingAction {
    action: Action;
    expected_revision?: number;
    profile_id?: string;
    migration_id?: string;
    draft?: Draft;
  }
  interface Draft {
    endpoint: string;
    region: string;
    bucket: string;
    prefix: string;
    path_style: boolean;
  }

  const returnTo = '/admin/settings/media';
  const storageKey = 'nyauth:reauth:media-settings';
  let settings = $state<MediaStorageSettings | null>(null);
  let loading = $state(true);
  let loadError = $state('');
  let operation = $state<Action | ''>('');
  let accessKeyID = $state('');
  let secretAccessKey = $state('');
  let sessionToken = $state('');
  let draft = $state<Draft>(emptyDraft());
  let migrationConfirmationOpen = $state(false);
  let fallbackConfirmationOpen = $state(false);
  let reauthenticationOpen = $state(false);
  let pending = $state<PendingAction | null>(null);
  let pollTimer: ReturnType<typeof setTimeout> | null = null;

  function emptyDraft(): Draft {
    return { endpoint: '', region: 'auto', bucket: '', prefix: 'nyauth', path_style: false };
  }

  function seedDraft(current: MediaStorageSettings) {
    const source = current.candidate?.settings || current.active?.settings;
    draft = source ? { ...source } : emptyDraft();
    accessKeyID = '';
    secretAccessKey = '';
    sessionToken = '';
  }

  function isMigrationActive(migration?: MediaStorageMigration): boolean {
    return !!migration && ['pending', 'running', 'applying'].includes(migration.status);
  }

  function isMigrationUnresolved(migration?: MediaStorageMigration): boolean {
    return !!migration && migration.status !== 'completed';
  }

  function schedulePoll(current: MediaStorageSettings) {
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = null;
    if (isMigrationActive(current.migration)) {
      pollTimer = setTimeout(() => void load(false, false), 2_000);
    }
  }

  async function load(seed = true, allowReauthentication = true): Promise<boolean> {
    loading = true;
    loadError = '';
    try {
      const current = await api.admin.getMediaSettings();
      settings = current;
      if (seed) seedDraft(current);
      schedulePoll(current);
      return true;
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        pending = { action: 'load' };
        reauthenticationOpen = true;
      } else {
        loadError = message(cause, '媒体存储设置加载失败');
      }
      return false;
    } finally {
      loading = false;
    }
  }

  function validateDraft(): string {
    if (!draft.region.trim()) return '请填写 S3 区域。';
    if (!draft.bucket.trim()) return '请填写私有 bucket 名称。';
    if (!accessKeyID.trim() || !secretAccessKey.trim()) return '请填写 Access Key ID 和 Secret Access Key。';
    return '';
  }

  async function saveCandidate(allowReauthentication = true, expectedRevision?: number) {
    const validation = validateDraft();
    if (validation) { toast.error(validation); return; }
    if (!settings && expectedRevision === undefined) return;
    const revision = expectedRevision ?? settings?.revision ?? 0;
    const snapshot: PendingAction = { action: 'save', expected_revision: revision, draft: { ...draft } };
    operation = 'save';
    try {
      await api.admin.saveMediaCandidate({
        expected_revision: revision,
        ...draft,
        access_key_id: accessKeyID,
        secret_access_key: secretAccessKey,
        session_token: sessionToken,
      });
      accessKeyID = ''; secretAccessKey = ''; sessionToken = '';
      toast.success('候选对象存储已保存，请先执行真实读写测试。');
      await load(true, false);
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) openReauthentication(snapshot);
      else toast.error(message(cause, '候选对象存储保存失败'));
    } finally { operation = ''; }
  }

  async function testCandidate(allowReauthentication = true, expectedRevision?: number, profileID?: string) {
    const id = profileID || settings?.candidate?.id;
    if (!settings || !id) { toast.error('请先保存候选配置。'); return; }
    const revision = expectedRevision ?? settings.revision;
    const snapshot: PendingAction = { action: 'test', expected_revision: revision, profile_id: id };
    operation = 'test';
    try {
      const result = await api.admin.testMediaCandidate(revision, id);
      if (result.candidate.test_result === 'success') toast.success('真实写入、读取、校验和删除测试均已通过。');
      else toast.error(`对象存储测试失败：${result.candidate.test_error_category || '未知错误'}。`);
      await load(false, false);
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) openReauthentication(snapshot);
      else toast.error(message(cause, '对象存储测试失败'));
    } finally { operation = ''; }
  }

  async function startMigration(allowReauthentication = true, expectedRevision?: number, profileID?: string) {
    const id = profileID || settings?.candidate?.id;
    if (!settings || !id) return;
    const revision = expectedRevision ?? settings.revision;
    const snapshot: PendingAction = { action: 'migrate', expected_revision: revision, profile_id: id };
    operation = 'migrate';
    try {
      await api.admin.startMediaMigration(revision, id);
      toast.info('媒体写入已排空，正在迁移头像对象。');
      await load(false, false);
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) openReauthentication(snapshot);
      else toast.error(message(cause, '媒体存储迁移启动失败'));
      throw cause;
    } finally { operation = ''; }
  }

  async function retryMigration(allowReauthentication = true, migrationID?: string) {
    const id = migrationID || settings?.migration?.id;
    if (!id) return;
    const snapshot: PendingAction = { action: 'retry', migration_id: id };
    operation = 'retry';
    try {
      await api.admin.retryMediaMigration(id);
      toast.info('失败项已重新排队，迁移继续执行。');
      await load(false, false);
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) openReauthentication(snapshot);
      else toast.error(message(cause, '迁移重试失败'));
    } finally { operation = ''; }
  }

  async function migrateToLocalFallback(allowReauthentication = true, expectedRevision?: number) {
    if (!settings || settings.mode !== 'dynamic' || settings.fallback?.backend !== 'local') return;
    const revision = expectedRevision ?? settings.revision;
    const snapshot: PendingAction = { action: 'fallback', expected_revision: revision };
    operation = 'fallback';
    try {
      await api.admin.migrateMediaToLocalFallback(revision);
      toast.info('本地存储检查已通过，媒体写入已排空，正在迁回头像对象。');
      await load(false, false);
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) openReauthentication(snapshot);
      else toast.error(message(cause, '迁回本地存储失败'));
      throw cause;
    } finally { operation = ''; }
  }

  function openReauthentication(snapshot: PendingAction) {
    pending = snapshot;
    reauthenticationOpen = true;
  }

  function persistProviderAction() {
    if (!pending) return;
    sessionStorage.setItem(storageKey, JSON.stringify(pending));
    accessKeyID = ''; secretAccessKey = ''; sessionToken = '';
  }

  async function retryAfterPassword() {
    const snapshot = pending;
    pending = null;
    if (snapshot) await resume(snapshot);
  }

  async function resume(snapshot: PendingAction) {
    if (snapshot.draft) draft = { ...snapshot.draft };
    switch (snapshot.action) {
      case 'load': await load(true, false); break;
      case 'save': await saveCandidate(false, snapshot.expected_revision); break;
      case 'test': await testCandidate(false, snapshot.expected_revision, snapshot.profile_id); break;
      case 'migrate': await startMigration(false, snapshot.expected_revision, snapshot.profile_id); break;
      case 'fallback': await migrateToLocalFallback(false, snapshot.expected_revision); break;
      case 'retry': await retryMigration(false, snapshot.migration_id); break;
    }
  }

  async function restoreProviderAction(): Promise<boolean> {
    const raw = sessionStorage.getItem(storageKey);
    if (!raw) return false;
    sessionStorage.removeItem(storageKey);
    const providerError = consumeProviderAuthError();
    let snapshot: PendingAction;
    try { snapshot = JSON.parse(raw) as PendingAction; }
    catch { toast.error('无法恢复待处理的媒体存储操作。'); await load(); return true; }
    if (snapshot.draft) draft = { ...snapshot.draft };
    if (providerError) { toast.error(providerError.message); await load(false); return true; }
    const loaded = await load(false, false);
    if (!loaded || !settings) return true;
    if (snapshot.expected_revision !== undefined && snapshot.expected_revision !== settings.revision) {
      toast.warning('重新认证期间媒体设置已变化，请核对后重试。');
      return true;
    }
    if (snapshot.action === 'save') {
      toast.info('身份验证已完成；凭据不会跨跳转保存，请重新输入后保存。');
      return true;
    }
    await resume(snapshot);
    return true;
  }

  function message(cause: unknown, fallback: string): string { return cause instanceof Error ? cause.message : fallback; }
  function formatDate(value?: string): string { if (!value) return '—'; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN'); }
  function profileTitle(profile: MediaStorageProfile | undefined, deploymentFallback = false): string {
    if (!profile) return '未配置';
    if (deploymentFallback) return profile.backend === 'local' ? '本地存储' : 'S3';
    if (profile.backend === 'local') return '本地存储';
    return `${profile.settings?.bucket || 'S3'}${profile.settings?.prefix ? ` / ${profile.settings.prefix}` : ''}`;
  }

  onMount(() => {
    void (async () => { if (!(await restoreProviderAction())) await load(); })();
    return () => { if (pollTimer) clearTimeout(pollTimer); };
  });
</script>

<section class="space-y-4">
  {#if loading && !settings}
    <div class="rounded-nya-md border border-nya-border bg-nya-surface p-6 text-body text-nya-text-tertiary">正在加载媒体存储设置…</div>
  {:else if loadError && !settings}
    <div class="rounded-nya-md border border-nya-danger/30 bg-nya-danger-soft p-4">
      <p class="text-body text-nya-danger">{loadError}</p>
      <Button variant="secondary" size="sm" onclick={() => load()}><RefreshCw size={15} />重试</Button>
    </div>
  {:else if settings}
    <div class="grid gap-4 lg:grid-cols-2">
      <div class="rounded-nya-md border border-nya-border bg-nya-surface p-4">
        <div><p class="text-micro uppercase text-nya-text-tertiary">当前存储</p><h3 class="mt-1 text-body-medium font-semibold text-nya-text-primary">{profileTitle(settings.active, settings.mode === 'fallback')}</h3></div>
        <p class="mt-3 text-small text-nya-text-secondary">现有头像读取会按各自绑定的存储版本路由；切换不会让旧地址失效。</p>
        {#if settings.mode === 'dynamic' && settings.fallback?.backend === 'local'}
          <div class="mt-4">
            <Button variant="secondary" requiredCapability="admin_mutations" loading={operation === 'fallback'} disabled={operation !== '' || isMigrationUnresolved(settings.migration)} onclick={() => (fallbackConfirmationOpen = true)}><HardDrive size={16} />迁回本地存储</Button>
          </div>
        {/if}
      </div>
      <div class="rounded-nya-md border border-nya-border bg-nya-surface p-4">
        <p class="text-micro uppercase text-nya-text-tertiary">安全边界</p>
        <p class="mt-2 text-small text-nya-text-secondary">后台仅接受私有 S3 兼容存储；可以迁回部署时已挂载的本地存储，但不会接受或修改任意本地路径。凭据使用主密钥加密且永不回显。</p>
      </div>
    </div>

    <form class="space-y-4 rounded-nya-md border border-nya-border bg-nya-surface p-4" onsubmit={(event) => { event.preventDefault(); void saveCandidate(); }}>
      <div><h3 class="text-body-medium font-semibold text-nya-text-primary">候选 S3 配置</h3><p class="mt-1 text-small text-nya-text-tertiary">保存不会切换存储；测试成功并完成对象迁移后才会生效。</p></div>
      <div class="grid gap-4 md:grid-cols-2">
        <Input id="media-endpoint" label="Endpoint（AWS S3 可留空）" type="url" bind:value={draft.endpoint} placeholder="https://s3.example.com" help="R2、MinIO 等兼容服务填写 HTTPS endpoint；AWS S3 留空。" />
        <Input id="media-region" label="区域" bind:value={draft.region} required placeholder="auto / us-east-1" />
        <Input id="media-bucket" label="私有 Bucket" bind:value={draft.bucket} required placeholder="nyauth-media" />
        <Input id="media-prefix" label="对象前缀" bind:value={draft.prefix} placeholder="nyauth" help="用于与 bucket 中其他应用隔离，不要以斜杠开头。" />
      </div>
      <Switch bind:checked={draft.path_style} label="使用 path-style 寻址（MinIO 常用）" />
      <div class="grid gap-4 md:grid-cols-2">
        <Input id="media-access-key" label="Access Key ID" bind:value={accessKeyID} required autocomplete="off" />
        <Input id="media-secret-key" label="Secret Access Key" type="password" bind:value={secretAccessKey} required autocomplete="new-password" />
      </div>
      <Input id="media-session-token" label="Session Token（可选）" type="password" bind:value={sessionToken} autocomplete="new-password" />
      <div class="flex flex-wrap gap-2">
        <Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={operation === 'save'} disabled={operation !== '' || isMigrationUnresolved(settings.migration)}><Database size={16} />保存候选配置</Button>
        <Button variant="ghost" onclick={() => seedDraft(settings!)} disabled={operation !== ''}><RotateCcw size={16} />恢复已保存值</Button>
      </div>
    </form>

    {#if settings.candidate}
      <div class="rounded-nya-md border border-nya-primary/30 bg-nya-primary-soft/30 p-4">
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div><h3 class="text-body-medium font-semibold text-nya-text-primary">候选：{profileTitle(settings.candidate)}</h3><p class="mt-1 text-small text-nya-text-tertiary">凭据已加密保存 · 创建于 {formatDate(settings.candidate.created_at)}</p></div>
          <Badge variant={settings.candidate.test_result === 'success' ? 'success' : settings.candidate.test_result === 'failure' ? 'danger' : 'warning'}>{settings.candidate.test_result === 'success' ? '测试通过' : settings.candidate.test_result === 'failure' ? '测试失败' : '待测试'}</Badge>
        </div>
        {#if settings.candidate.test_error}<p class="mt-3 text-small text-nya-danger">{settings.candidate.test_error}（{settings.candidate.test_error_category || 'unknown'}）</p>{/if}
        <div class="mt-4 flex flex-wrap gap-2">
          <Button variant="secondary" requiredCapability="admin_mutations" loading={operation === 'test'} disabled={operation !== '' || isMigrationUnresolved(settings.migration)} onclick={() => testCandidate()}><ShieldCheck size={16} />真实读写测试</Button>
          <Button variant="primary" requiredCapability="admin_mutations" loading={operation === 'migrate'} disabled={operation !== '' || settings.candidate.test_result !== 'success' || isMigrationUnresolved(settings.migration)} onclick={() => (migrationConfirmationOpen = true)}><Play size={16} />排空并开始迁移</Button>
        </div>
      </div>
    {/if}

    {#if settings.migration}
      <div class="rounded-nya-md border border-nya-border bg-nya-surface p-4">
        <div class="flex items-start justify-between gap-3"><div><h3 class="text-body-medium font-semibold text-nya-text-primary">存储迁移</h3><p class="mt-1 font-mono text-micro text-nya-text-tertiary">{settings.migration.id}</p></div><Badge variant={settings.migration.status === 'completed' ? 'success' : settings.migration.status === 'failed' ? 'danger' : 'warning'}>{settings.migration.status}</Badge></div>
        <div class="mt-4 h-2 overflow-hidden rounded-full bg-nya-surface-soft"><div class="h-full bg-nya-primary transition-all" style={`width:${settings.migration.total_count === 0 ? (settings.migration.status === 'completed' ? 100 : 0) : Math.round(settings.migration.completed_count / settings.migration.total_count * 100)}%`}></div></div>
        <div class="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-small text-nya-text-secondary"><span>总计 {settings.migration.total_count}</span><span>已复制 {settings.migration.copied_count}</span><span>已完成 {settings.migration.completed_count}</span><span>失败 {settings.migration.failed_count}</span></div>
        {#if settings.migration.last_error}<p class="mt-3 text-small text-nya-danger">迁移暂停：{settings.migration.last_error}</p>{/if}
        {#if settings.migration.status === 'failed'}<div class="mt-3"><Button variant="secondary" requiredCapability="admin_mutations" loading={operation === 'retry'} disabled={operation !== ''} onclick={() => retryMigration()}><RefreshCw size={16} />重试失败项</Button></div>{/if}
      </div>
    {/if}
  {/if}
</section>

<ConfirmDialog bind:open={migrationConfirmationOpen} title="迁移媒体存储" description="系统会自动暂停媒体写入，逐个复制并校验全部头像，再切换有效存储。失败时保持暂停并保留源对象。" confirmLabel="开始迁移" confirmationText="迁移媒体存储" onconfirm={() => startMigration()} />
<ConfirmDialog bind:open={fallbackConfirmationOpen} title="迁回本地存储" description="系统会先验证已挂载的本地存储，再暂停媒体写入，将全部头像从当前 S3 复制回本地。多实例部署不允许使用非共享本地存储。" confirmLabel="检查并开始迁回" confirmationText="迁回本地存储" onconfirm={() => migrateToLocalFallback()} />
<ReauthenticationDialog bind:open={reauthenticationOpen} {returnTo} description="查看或修改对象存储前需要完成近期身份验证" onauthenticated={retryAfterPassword} onbeforeprovider={persistProviderAction} />
