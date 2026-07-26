<script lang="ts">
  import { onMount } from 'svelte';
  import { api, isRecentAuthenticationError, type RegistrationMode, type RegistrationSettings, type SystemStatus } from '$lib/api';
  import { brandingStore, consumeProviderAuthError } from '$lib/stores';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import StatusBadge from '$lib/components/data-display/StatusBadge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import { Database, KeyRound, Network, Palette, Server, UserPlus } from 'lucide-svelte';

  let systemStatus = $state<SystemStatus | null>(null);
  let loading = $state(true);
  let error = $state('');

  let brandingTitle = $state('');
  let brandingLogoURL = $state('');
  let brandingSaving = $state(false);
  let brandingError = $state('');
  let brandingSaved = $state(false);
  let brandingSynced = false;

  $effect(() => {
    // Seed the form once from the loaded branding without clobbering edits.
    const branding = $brandingStore;
    if (!brandingSynced && branding.title) {
      brandingTitle = branding.title;
      brandingLogoURL = branding.logo_url;
      brandingSynced = true;
    }
  });

  async function saveBranding(event: SubmitEvent) {
    event.preventDefault();
    brandingSaving = true;
    brandingError = '';
    brandingSaved = false;
    try {
      const updated = await api.admin.updateBranding({ title: brandingTitle.trim(), logo_url: brandingLogoURL.trim() });
      brandingStore.set(updated);
      brandingTitle = updated.title;
      brandingLogoURL = updated.logo_url;
      brandingSaved = true;
    } catch (cause) {
      brandingError = cause instanceof Error ? cause.message : '保存失败';
    } finally {
      brandingSaving = false;
    }
  }

  async function loadSystemStatus() {
    loading = true;
    error = '';
    try {
      systemStatus = await api.admin.getSystemStatus();
    } catch (cause) {
      systemStatus = null;
      error = cause instanceof Error ? cause.message : '系统状态加载失败';
    } finally {
      loading = false;
    }
  }

  let regMode = $state<RegistrationMode>('closed');
  let regRequireVerification = $state(true);
  let regDomains = $state('');
  let regPendingTTL = $state('72h');
  let regInviteTTL = $state('168h');
  let regInviteMaxUses = $state('1');
  let regLoaded = $state(false);
  let regLoadError = $state('');
  let regSaving = $state(false);
  let regError = $state('');
  let regSaved = $state(false);
  let regReauthOpen = $state(false);
  let pendingRegistrationSettings = $state<RegistrationSettings | null>(null);

  const pendingSettingsStorageKey = 'nyauth:reauth:registration-settings';

  async function loadRegistrationSettings() {
    regLoadError = '';
    try {
      const current = await api.admin.getRegistrationSettings();
      regMode = current.mode;
      regRequireVerification = current.require_email_verification;
      regDomains = current.allowed_email_domains.join('\n');
      regPendingTTL = current.pending_registration_ttl;
      regInviteTTL = current.invite_default_ttl;
      regInviteMaxUses = String(current.invite_default_max_uses);
      regLoaded = true;
    } catch (cause) {
      regLoadError = cause instanceof Error ? cause.message : '注册设置加载失败';
    }
  }

  async function saveRegistrationSettings(event: SubmitEvent) {
    event.preventDefault();
    regError = '';
    regSaved = false;
    const maxUses = Number.parseInt(regInviteMaxUses.trim(), 10);
    if (!Number.isSafeInteger(maxUses) || maxUses < 1) {
      regError = '邀请默认可用次数必须是不小于 1 的整数。';
      return;
    }
    const payload: RegistrationSettings = {
      mode: regMode,
      require_email_verification: regMode === 'open' ? true : regRequireVerification,
      allowed_email_domains: regDomains.split('\n').map((line) => line.trim()).filter(Boolean),
      pending_registration_ttl: regPendingTTL.trim(),
      invite_default_ttl: regInviteTTL.trim(),
      invite_default_max_uses: maxUses,
    };
    pendingRegistrationSettings = payload;
    await executeRegistrationSettingsSave(payload, true);
  }

  async function executeRegistrationSettingsSave(payload: RegistrationSettings, allowReauthentication: boolean) {
    regSaving = true;
    try {
      const updated = await api.admin.updateRegistrationSettings(payload);
      pendingRegistrationSettings = null;
      regMode = updated.mode;
      regRequireVerification = updated.require_email_verification;
      regDomains = updated.allowed_email_domains.join('\n');
      regPendingTTL = updated.pending_registration_ttl;
      regInviteTTL = updated.invite_default_ttl;
      regInviteMaxUses = String(updated.invite_default_max_uses);
      regSaved = true;
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        regReauthOpen = true;
      } else {
        regError = cause instanceof Error ? cause.message : '保存失败';
      }
    } finally {
      regSaving = false;
    }
  }

  async function retryRegistrationSettingsSave() {
    if (pendingRegistrationSettings) {
      await executeRegistrationSettingsSave(pendingRegistrationSettings, false);
    }
  }

  function persistPendingRegistrationSettings() {
    if (pendingRegistrationSettings) {
      sessionStorage.setItem(pendingSettingsStorageKey, JSON.stringify(pendingRegistrationSettings));
    }
  }

  async function restorePendingRegistrationSettings() {
    const raw = sessionStorage.getItem(pendingSettingsStorageKey);
    if (!raw) return;
    sessionStorage.removeItem(pendingSettingsStorageKey);
    try {
      const restored = JSON.parse(raw) as RegistrationSettings;
      pendingRegistrationSettings = restored;
      regMode = restored.mode;
      regRequireVerification = restored.require_email_verification;
      regDomains = restored.allowed_email_domains.join('\n');
      regPendingTTL = restored.pending_registration_ttl;
      regInviteTTL = restored.invite_default_ttl;
      regInviteMaxUses = String(restored.invite_default_max_uses);
      const providerError = consumeProviderAuthError();
      if (providerError) {
        regError = providerError.message;
        return;
      }
      await executeRegistrationSettingsSave(restored, false);
    } catch {
      regError = '无法恢复待保存的注册设置，请重新检查表单。';
    }
  }

  function formatLatency(value: number): string {
    return Number.isFinite(value) ? `${value.toLocaleString()} ms` : '不可用';
  }

  function formatDateTime(value: string): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN');
  }

  onMount(async () => {
    void loadSystemStatus();
    await loadRegistrationSettings();
    await restorePendingRegistrationSettings();
  });
</script>

<svelte:head><title>系统状态 - Nya</title></svelte:head>

<PageHeader title="系统状态" description="查看当前版本、数据库基线与认证服务依赖的只读运行状态" />

<section class="mb-4 rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
  <div class="mb-4 flex items-center gap-2">
    <Palette size={18} class="text-nya-primary" />
    <h2 class="text-card-title text-nya-text-primary">品牌设置</h2>
  </div>
  <p class="mb-4 text-body text-nya-text-secondary">修改后无需重启，立即同步到所有实例的侧栏与登录页。Logo 留空时使用内置图标。</p>
  <form onsubmit={saveBranding} class="space-y-4">
    {#if brandingError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{brandingError}</p>{/if}
    {#if brandingSaved}<p class="rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">品牌设置已保存，立即对所有实例生效。</p>{/if}
    <div class="grid gap-4 md:grid-cols-2">
      <Input id="branding-title" label="站点名称" bind:value={brandingTitle} required placeholder="Nya" />
      <Input id="branding-logo-url" label="Logo URL（可选）" bind:value={brandingLogoURL} placeholder="https://example.com/logo.png" />
    </div>
    <Button type="submit" variant="primary" loading={brandingSaving}>保存品牌设置</Button>
  </form>
</section>

<section class="mb-4 rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
  <div class="mb-4 flex items-center gap-2">
    <UserPlus size={18} class="text-nya-primary" />
    <h2 class="text-card-title text-nya-text-primary">注册设置</h2>
  </div>
  <p class="mb-4 text-body text-nya-text-secondary">控制自助注册的开关与邀请默认值，保存后免重启即时生效。开启注册要求邮件子系统（NYAUTH_MAIL_*）已启用。</p>
  {#if regLoadError}
    <p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{regLoadError}</p>
  {:else if !regLoaded}
    <p class="text-small text-nya-text-tertiary">加载中…</p>
  {:else}
    <form onsubmit={saveRegistrationSettings} class="space-y-4">
      {#if regError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{regError}</p>{/if}
      {#if regSaved}<p class="rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">注册设置已保存，立即对所有实例生效。</p>{/if}
      <fieldset>
        <legend class="mb-2 text-body-medium text-nya-text-primary">注册模式</legend>
        <div class="grid gap-2 sm:grid-cols-3">
          {#each [
            { value: 'closed', label: '关闭', description: '仅管理员可创建账号（默认）' },
            { value: 'invite_only', label: '邀请制', description: '需要有效邀请码才能注册' },
            { value: 'open', label: '开放', description: '任何人都可注册，强制邮箱验证' },
          ] as option}
            <label class="flex cursor-pointer items-start gap-2 rounded-nya-sm border border-nya-border px-3 py-2 {regMode === option.value ? 'border-nya-primary bg-nya-primary-soft' : ''}">
              <input type="radio" name="registration-mode" value={option.value} bind:group={regMode} class="mt-0.5" />
              <span><span class="block text-small font-semibold text-nya-text-primary">{option.label}</span><span class="block text-micro text-nya-text-tertiary">{option.description}</span></span>
            </label>
          {/each}
        </div>
      </fieldset>
      <label class="flex cursor-pointer items-start gap-2">
        <input type="checkbox" checked={regMode === 'open' ? true : regRequireVerification} disabled={regMode === 'open'} onchange={(event) => (regRequireVerification = event.currentTarget.checked)} class="mt-0.5 rounded" />
        <span><span class="block text-body text-nya-text-primary">要求邮箱验证</span><span class="block text-small text-nya-text-tertiary">注册后必须完成验证邮件确认才能登录；开放模式下强制开启。</span></span>
      </label>
      <div>
        <label for="registration-domains" class="mb-1.5 block text-body-medium text-nya-text-primary">允许的邮箱域名（每行一个，留空不限制）</label>
        <textarea id="registration-domains" bind:value={regDomains} rows="3" placeholder="corp.example.com" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea>
      </div>
      <div class="grid gap-4 sm:grid-cols-3">
        <Input id="registration-pending-ttl" label="待验证注册有效期" bind:value={regPendingTTL} placeholder="72h" />
        <Input id="registration-invite-ttl" label="邀请默认有效期" bind:value={regInviteTTL} placeholder="168h" />
        <Input id="registration-invite-max-uses" label="邀请默认可用次数" bind:value={regInviteMaxUses} placeholder="1" />
      </div>
      <Button type="submit" variant="primary" loading={regSaving}>保存注册设置</Button>
    </form>
  {/if}
</section>

<ResourceState
  {loading}
  {error}
  empty={!systemStatus}
  emptyTitle="暂无系统状态"
  emptyDescription="服务尚未返回可展示的运行状态。"
  onretry={loadSystemStatus}
>
  {#snippet children()}
    {#if systemStatus}
      <div class="space-y-4">
        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="flex flex-wrap items-start justify-between gap-4">
            <div class="flex items-start gap-3">
              <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-primary-soft text-nya-primary">
                <Server size={19} />
              </span>
              <div>
                <h2 class="text-card-title text-nya-text-primary">Nyauth 服务</h2>
                <p class="mt-1 text-body text-nya-text-secondary">当前实例的总体运行状态</p>
              </div>
            </div>
            <div class="flex items-center gap-3">
              <span class="font-mono text-small text-nya-text-secondary">{systemStatus.version}</span>
              <StatusBadge status={systemStatus.status} />
            </div>
          </div>
        </section>

        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="mb-4 flex items-center gap-2">
            <Database size={18} class="text-nya-primary" />
            <h2 class="text-card-title text-nya-text-primary">数据库基线</h2>
          </div>
          <dl class="grid gap-4 sm:grid-cols-3">
            <div class="rounded-nya-md bg-nya-surface-muted p-4">
              <dt class="text-small text-nya-text-tertiary">Schema 状态</dt>
              <dd class="mt-2"><StatusBadge status={systemStatus.schema.status} /></dd>
            </div>
            <div class="rounded-nya-md bg-nya-surface-muted p-4">
              <dt class="text-small text-nya-text-tertiary">当前版本</dt>
              <dd class="mt-2 font-mono text-body-medium text-nya-text-primary">{systemStatus.schema.version}</dd>
            </div>
            <div class="rounded-nya-md bg-nya-surface-muted p-4">
              <dt class="text-small text-nya-text-tertiary">要求版本</dt>
              <dd class="mt-2 font-mono text-body-medium text-nya-text-primary">{systemStatus.schema.required_version}</dd>
            </div>
          </dl>
        </section>

        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="mb-4 flex items-center gap-2">
            <Network size={18} class="text-nya-primary" />
            <h2 class="text-card-title text-nya-text-primary">依赖服务</h2>
          </div>
          <div class="grid gap-3 md:grid-cols-2">
            <article class="rounded-nya-md border border-nya-border p-4">
              <div class="flex items-center justify-between gap-3">
                <h3 class="text-body-medium font-semibold text-nya-text-primary">PostgreSQL</h3>
                <StatusBadge status={systemStatus.services.postgresql.status} />
              </div>
              <p class="mt-3 text-small text-nya-text-tertiary">响应延迟</p>
              <p class="mt-1 font-mono text-body-medium text-nya-text-primary">{formatLatency(systemStatus.services.postgresql.latency_ms)}</p>
            </article>

            <article class="rounded-nya-md border border-nya-border p-4">
              <div class="flex items-center justify-between gap-3">
                <h3 class="text-body-medium font-semibold text-nya-text-primary">Redis</h3>
                <StatusBadge status={systemStatus.services.redis.status} />
              </div>
              <p class="mt-3 text-small text-nya-text-tertiary">响应延迟</p>
              <p class="mt-1 font-mono text-body-medium text-nya-text-primary">{formatLatency(systemStatus.services.redis.latency_ms)}</p>
            </article>

            <article class="rounded-nya-md border border-nya-border p-4">
              <div class="flex items-center justify-between gap-3">
                <h3 class="text-body-medium font-semibold text-nya-text-primary">JWK</h3>
                <StatusBadge status={systemStatus.services.jwk.status} />
              </div>
              <p class="mt-3 text-small text-nya-text-tertiary">响应延迟</p>
              <p class="mt-1 font-mono text-body-medium text-nya-text-primary">{formatLatency(systemStatus.services.jwk.latency_ms)}</p>
            </article>

            <article class="rounded-nya-md border border-nya-border p-4">
              <div class="flex items-center justify-between gap-3">
                <h3 class="text-body-medium font-semibold text-nya-text-primary">Provider 快照</h3>
                <StatusBadge status={systemStatus.services.providers.status} />
              </div>
              <dl class="mt-3 grid grid-cols-2 gap-3 text-small">
                <div>
                  <dt class="text-nya-text-tertiary">响应延迟</dt>
                  <dd class="mt-1 font-mono text-nya-text-primary">{formatLatency(systemStatus.services.providers.latency_ms)}</dd>
                </div>
                <div>
                  <dt class="text-nya-text-tertiary">快照修订</dt>
                  <dd class="mt-1 font-mono text-nya-text-primary">{systemStatus.services.providers.snapshot_revision}</dd>
                </div>
              </dl>
            </article>
          </div>
        </section>

        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="mb-4 flex items-center gap-2">
            <KeyRound size={18} class="text-nya-primary" />
            <h2 class="text-card-title text-nya-text-primary">活动签名密钥</h2>
          </div>
          {#if systemStatus.active_signing_key}
            <dl class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <div class="min-w-0">
                <dt class="text-small text-nya-text-tertiary">Key ID</dt>
                <dd class="mt-1 truncate font-mono text-body-medium text-nya-text-primary" title={systemStatus.active_signing_key.kid}>{systemStatus.active_signing_key.kid}</dd>
              </div>
              <div>
                <dt class="text-small text-nya-text-tertiary">状态</dt>
                <dd class="mt-2"><StatusBadge status={systemStatus.active_signing_key.status} /></dd>
              </div>
              <div>
                <dt class="text-small text-nya-text-tertiary">开始签名</dt>
                <dd class="mt-1 text-body-medium text-nya-text-primary">
                  <time datetime={systemStatus.active_signing_key.signing_started_at} title={systemStatus.active_signing_key.signing_started_at}>{formatDateTime(systemStatus.active_signing_key.signing_started_at)}</time>
                </dd>
              </div>
              <div>
                <dt class="text-small text-nya-text-tertiary">下次轮换</dt>
                <dd class="mt-1 text-body-medium text-nya-text-primary">
                  <time datetime={systemStatus.active_signing_key.next_rotation_at} title={systemStatus.active_signing_key.next_rotation_at}>{formatDateTime(systemStatus.active_signing_key.next_rotation_at)}</time>
                </dd>
              </div>
            </dl>
          {:else}
            <p class="rounded-nya-md bg-nya-warning-soft px-4 py-3 text-body text-nya-warning" role="status">当前没有活动签名密钥。</p>
          {/if}
        </section>
      </div>
    {/if}
  {/snippet}
</ResourceState>

<ReauthenticationDialog
  bind:open={regReauthOpen}
  returnTo="/admin/system"
  description="修改注册策略前需要验证最近 10 分钟内的身份"
  onauthenticated={retryRegistrationSettingsSave}
  onbeforeprovider={persistPendingRegistrationSettings}
/>
