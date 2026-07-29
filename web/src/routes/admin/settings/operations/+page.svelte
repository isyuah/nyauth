<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    isAPIErrorCode,
    isRecentAuthenticationError,
    type OperationsSettings,
    type ServiceCapability,
    type SessionInfo,
    type UpdateOperationsSettingsInput,
  } from '$lib/api';
  import { consumeProviderAuthError } from '$lib/stores';
  import {
    SERVICE_CAPABILITIES,
    SERVICE_CONTROL_PRESETS,
    matchesCapabilities,
    operatingStateLabel,
    serviceStatusStore,
    sortCapabilities,
  } from '$lib/service-control';
  import SettingsPageHeader from '$lib/components/admin/SettingsPageHeader.svelte';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Switch from '$lib/components/ui/Switch.svelte';
  import { AlertTriangle, Clock3, Power, RefreshCw, ServerCog } from 'lucide-svelte';

  type ExpiryMode = '30m' | '1h' | '4h' | '24h' | 'custom' | 'indefinite';

  const returnTo = '/admin/settings/operations';
  const pendingStorageKey = 'nyauth:reauth:operations-settings';
  const minute = 60_000;
  const capabilityDraft = $state<Record<ServiceCapability, boolean>>({
    self_registration: false,
    account_mutations: false,
    admin_mutations: false,
    auth_issuance: false,
    mail_delivery: false,
    media_writes: false,
  });

  let settings = $state<OperationsSettings | null>(null);
  let loading = $state(true);
  let saving = $state(false);
  let error = $state('');
  let saved = $state(false);
  let conflict = $state(false);
  let publicMessage = $state('');
  let internalReason = $state('');
  let expiryMode = $state<ExpiryMode>('1h');
  let customExpiry = $state(defaultLocalExpiry(60));
  let indefiniteConfirmed = $state(false);
  let dependencyNotice = $state('');
  let reauthOpen = $state(false);
  let pendingInput = $state<UpdateOperationsSettingsInput | null>(null);
  let pollingTimer: ReturnType<typeof setTimeout> | null = null;

  let selectedCapabilities = $derived(SERVICE_CAPABILITIES
    .filter(({ code }) => capabilityDraft[code])
    .map(({ code }) => code));
  let currentPreset = $derived(SERVICE_CONTROL_PRESETS.find((preset) =>
    matchesCapabilities(preset.capabilities, selectedCapabilities))?.id ?? 'custom');
  let applicationComplete = $derived(settings?.application_status === 'applied');

  function pad(value: number): string {
    return String(value).padStart(2, '0');
  }

  function toLocalDateTime(date: Date): string {
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function defaultLocalExpiry(minutes: number): string {
    return toLocalDateTime(new Date(Date.now() + minutes * minute));
  }

  function setDraftCapabilities(capabilities: readonly ServiceCapability[]) {
    const selected = new Set(capabilities);
    for (const { code } of SERVICE_CAPABILITIES) capabilityDraft[code] = selected.has(code);
  }

  function applySettings(next: OperationsSettings, resetForm = true) {
    settings = next;
    serviceStatusStore.setFromOperations(next);
    if (resetForm) {
      setDraftCapabilities(next.paused_capabilities);
      publicMessage = next.public_message;
      internalReason = next.internal_reason;
      if (next.expires_at) {
        expiryMode = 'custom';
        customExpiry = toLocalDateTime(new Date(next.expires_at));
      } else if (next.paused_capabilities.length > 0) {
        expiryMode = 'indefinite';
      } else {
        expiryMode = '1h';
        customExpiry = defaultLocalExpiry(60);
      }
      indefiniteConfirmed = false;
    }
    scheduleApplicationPoll(next);
  }

  async function loadSettings(resetForm = true) {
    loading = true;
    error = '';
    conflict = false;
    try {
      applySettings(await api.admin.getOperationsSettings(), resetForm);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '运行控制状态加载失败';
    } finally {
      loading = false;
    }
  }

  function scheduleApplicationPoll(current: OperationsSettings) {
    if (pollingTimer !== null) clearTimeout(pollingTimer);
    pollingTimer = null;
    if (current.application_status !== 'applying') return;
    pollingTimer = setTimeout(async () => {
      try {
        applySettings(await api.admin.getOperationsSettings(), false);
      } catch {
        pollingTimer = setTimeout(() => settings && scheduleApplicationPoll(settings), 3_000);
      }
    }, 2_000);
  }

  function applyPreset(capabilities: readonly ServiceCapability[]) {
    setDraftCapabilities(capabilities);
    dependencyNotice = '';
    if (capabilities.length > 0 && expiryMode === 'indefinite') {
      expiryMode = '1h';
      customExpiry = defaultLocalExpiry(60);
      indefiniteConfirmed = false;
    }
  }

  function enforceDependencies(changed: ServiceCapability) {
    dependencyNotice = '';
    if (changed === 'auth_issuance' && capabilityDraft.auth_issuance) {
      capabilityDraft.self_registration = true;
      dependencyNotice = '暂停认证签发时，自助注册也会一并暂停。';
    }
    if (changed === 'mail_delivery' && capabilityDraft.mail_delivery) {
      capabilityDraft.self_registration = true;
      dependencyNotice = '暂停邮件投递时，自助注册也会一并暂停，避免产生无法验证的账户。';
    }
    if (changed === 'self_registration' && !capabilityDraft.self_registration) {
      if (capabilityDraft.auth_issuance || capabilityDraft.mail_delivery) {
        capabilityDraft.auth_issuance = false;
        capabilityDraft.mail_delivery = false;
        dependencyNotice = '恢复自助注册时，认证签发和邮件投递也已恢复，以保持运行状态有效。';
      }
    }
  }

  function setQuickExpiry(mode: Exclude<ExpiryMode, 'custom' | 'indefinite'>, minutes: number) {
    expiryMode = mode;
    customExpiry = defaultLocalExpiry(minutes);
    indefiniteConfirmed = false;
  }

  function resolvedExpiry(): string | null {
    if (expiryMode === 'indefinite') return null;
    const parsed = new Date(customExpiry);
    return Number.isNaN(parsed.getTime()) ? '' : parsed.toISOString();
  }

  function validateInput(): string {
    if (selectedCapabilities.length === 0) return '';
    const reasonLength = internalReason.trim().length;
    if (reasonLength < 3 || reasonLength > 500) return '内部原因须为 3 至 500 个字符。';
    if (publicMessage.trim().length > 240) return '公开提示不能超过 240 个字符。';
    if (expiryMode === 'indefinite') return indefiniteConfirmed ? '' : '无限期暂停前必须勾选确认。';
    const expiresAt = resolvedExpiry();
    if (!expiresAt) return '请选择有效的恢复时间。';
    const delay = Date.parse(expiresAt) - Date.now();
    if (delay < minute || delay > 30 * 24 * 60 * minute) return '恢复时间须在 1 分钟至 30 天后。';
    return '';
  }

  function buildInput(): UpdateOperationsSettingsInput | null {
    if (!settings) return null;
    const paused = sortCapabilities(selectedCapabilities);
    return {
      expected_revision: settings.revision,
      paused_capabilities: paused,
      public_message: paused.length > 0 ? publicMessage.trim() : '',
      internal_reason: paused.length > 0 ? internalReason.trim() : '',
      expires_at: paused.length > 0 ? resolvedExpiry() : null,
    };
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    const validationError = validateInput();
    if (validationError) {
      error = validationError;
      return;
    }
    const input = buildInput();
    if (!input) return;
    pendingInput = input;
    await executeUpdate(input, true);
  }

  async function executeUpdate(input: UpdateOperationsSettingsInput, allowReauthentication: boolean) {
    saving = true;
    error = '';
    saved = false;
    conflict = false;
    try {
      const updated = await api.admin.updateOperationsSettings(input);
      pendingInput = null;
      applySettings(updated);
      saved = true;
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        reauthOpen = true;
      } else if (isAPIErrorCode(cause, 'service_control.revision_conflict')) {
        conflict = true;
        error = '运行状态已被其他管理员修改。请加载最新状态，确认后再提交。';
      } else {
        error = cause instanceof Error ? cause.message : '运行控制更新失败';
      }
    } finally {
      saving = false;
    }
  }

  async function retryAfterReauthentication(_session: SessionInfo) {
    if (pendingInput) await executeUpdate(pendingInput, false);
  }

  function persistPendingInput() {
    if (pendingInput) sessionStorage.setItem(pendingStorageKey, JSON.stringify(pendingInput));
  }

  async function restorePendingInput() {
    const raw = sessionStorage.getItem(pendingStorageKey);
    if (!raw) return;
    sessionStorage.removeItem(pendingStorageKey);
    try {
      const restored = JSON.parse(raw) as UpdateOperationsSettingsInput;
      if (!Number.isInteger(restored.expected_revision)
        || !Array.isArray(restored.paused_capabilities)
        || typeof restored.public_message !== 'string'
        || typeof restored.internal_reason !== 'string'
        || (restored.expires_at !== null && typeof restored.expires_at !== 'string')) {
        throw new TypeError('invalid stored operations settings');
      }
      pendingInput = { ...restored, paused_capabilities: sortCapabilities(restored.paused_capabilities) };
      const providerError = consumeProviderAuthError();
      if (providerError) {
        error = providerError.message;
        return;
      }
      await executeUpdate(pendingInput, false);
    } catch {
      error = '无法恢复待提交的运行控制设置，请重新检查表单。';
    }
  }

  onMount(() => {
    void (async () => {
      await loadSettings();
      await restorePendingInput();
    })();
    return () => {
      if (pollingTimer !== null) clearTimeout(pollingTimer);
    };
  });
</script>

<svelte:head><title>运行控制 - Nya</title></svelte:head>
<SettingsPageHeader title="运行控制" description="按能力暂停服务，并等待所有活动实例完成排空" />

<div class="mt-4 space-y-4">
  {#if loading && !settings}
    <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card"><p class="text-body text-nya-text-tertiary" role="status">正在加载运行状态…</p></section>
  {:else if !settings}
    <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
      <p class="text-small text-nya-danger" role="alert">{error || '运行控制状态不可用'}</p>
      <div class="mt-3"><Button variant="secondary" onclick={() => loadSettings()}><RefreshCw size={15} /> 重试</Button></div>
    </section>
  {:else}
    <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="flex items-start gap-3">
          <span class="flex h-10 w-10 items-center justify-center rounded-full bg-nya-primary-soft text-nya-primary"><Power size={18} /></span>
          <div><h2 class="text-card-title text-nya-text-primary">当前状态</h2><p class="mt-1 text-small text-nya-text-secondary">修订 {settings.revision} · {settings.updated_at ? new Date(settings.updated_at).toLocaleString('zh-CN') : '尚无修改记录'}</p></div>
        </div>
        <Badge variant={settings.status === 'normal' ? 'success' : settings.status === 'full_pause' ? 'danger' : 'warning'}>{operatingStateLabel(settings.status)}</Badge>
      </div>

      <div class="mt-4 rounded-nya-sm bg-nya-surface-muted p-4">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div class="flex items-center gap-2"><ServerCog size={16} class="text-nya-primary" /><p class="text-body-medium font-semibold text-nya-text-primary">实例应用进度</p></div>
          <Badge variant={applicationComplete ? 'success' : 'warning'}>{applicationComplete ? '已应用' : '应用中'}</Badge>
        </div>
        <p class="mt-2 text-small text-nya-text-secondary">{settings.applied_instances}/{settings.active_instances} 个活动实例已加载并排空至修订 {settings.revision}。</p>
        {#if settings.instances.length > 0}
          <div class="mt-3 grid gap-2 md:grid-cols-2">
            {#each settings.instances as instance}
              <div class="flex items-center justify-between gap-3 rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 text-small">
                <span class="min-w-0 truncate font-mono text-nya-text-secondary" title={instance.instance_id}>{instance.instance_id}</span>
                <span class={instance.applied_revision >= settings.revision ? 'text-nya-success' : 'text-nya-warning'}>{instance.applied_revision >= settings.revision ? '已排空' : `等待 r${instance.applied_revision}`}</span>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    </section>

    <form onsubmit={submit} class="space-y-4">
      <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
        <h2 class="text-card-title text-nya-text-primary">维护预设</h2>
        <p class="mt-1 text-small text-nya-text-secondary">预设只生成能力组合，不会作为额外状态保存。</p>
        <div class="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
          {#each SERVICE_CONTROL_PRESETS as preset}
            <button type="button" onclick={() => applyPreset(preset.capabilities)} aria-pressed={currentPreset === preset.id} class="rounded-nya-sm border px-4 py-3 text-left transition-colors {currentPreset === preset.id ? 'border-nya-primary bg-nya-primary-soft text-nya-primary' : 'border-nya-border bg-nya-surface hover:bg-nya-surface-muted'}">
              <span class="block text-body-medium font-semibold">{preset.label}</span>
              <span class="mt-1 block text-micro text-nya-text-tertiary">暂停 {preset.capabilities.length} 项能力</span>
            </button>
          {/each}
        </div>
      </section>

      <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
        <h2 class="text-card-title text-nya-text-primary">能力开关</h2>
        <p class="mt-1 text-small text-nya-text-secondary">开关打开表示暂停该能力。Discovery、撤销、登出、健康检查和安全清理始终可用。</p>
        {#if dependencyNotice}<p class="mt-3 rounded-nya-sm bg-nya-info-soft px-3 py-2 text-small text-nya-info" role="status">{dependencyNotice}</p>{/if}
        <div class="mt-4 divide-y divide-nya-divider rounded-nya-sm border border-nya-border px-4">
          {#each SERVICE_CAPABILITIES as capability}
            <div class="flex flex-col justify-between gap-3 py-4 sm:flex-row sm:items-start">
              <div class="max-w-2xl"><p class="text-body-medium font-semibold text-nya-text-primary">{capability.label}</p><p class="mt-1 text-small text-nya-text-secondary">{capability.description}</p></div>
              <Switch bind:checked={capabilityDraft[capability.code]} label={`暂停${capability.label}`} onchange={() => enforceDependencies(capability.code)} />
            </div>
          {/each}
        </div>
      </section>

      {#if selectedCapabilities.length > 0}
        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <h2 class="text-card-title text-nya-text-primary">维护说明与恢复时间</h2>
          <div class="mt-4 space-y-4">
            <div>
              <label for="operations-public-message" class="mb-1.5 block text-body-medium text-nya-text-primary">公开提示（可选）</label>
              <textarea id="operations-public-message" bind:value={publicMessage} maxlength="240" rows="2" placeholder="例如：系统正在维护，部分操作暂时不可用。" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 text-body text-nya-text-primary focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea>
              <p class="mt-1 text-right text-micro text-nya-text-tertiary">{publicMessage.length}/240</p>
            </div>
            <div>
              <label for="operations-internal-reason" class="mb-1.5 block text-body-medium text-nya-text-primary">内部原因</label>
              <textarea id="operations-internal-reason" bind:value={internalReason} maxlength="500" required rows="3" placeholder="记录操作背景、工单或负责人，仅管理员可见。" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 text-body text-nya-text-primary focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea>
            </div>
            <fieldset>
              <legend class="text-body-medium text-nya-text-primary">自动恢复</legend>
              <div class="mt-2 flex flex-wrap gap-2">
                <Button variant={expiryMode === '30m' ? 'soft' : 'secondary'} size="sm" onclick={() => setQuickExpiry('30m', 30)}>30 分钟</Button>
                <Button variant={expiryMode === '1h' ? 'soft' : 'secondary'} size="sm" onclick={() => setQuickExpiry('1h', 60)}>1 小时</Button>
                <Button variant={expiryMode === '4h' ? 'soft' : 'secondary'} size="sm" onclick={() => setQuickExpiry('4h', 240)}>4 小时</Button>
                <Button variant={expiryMode === '24h' ? 'soft' : 'secondary'} size="sm" onclick={() => setQuickExpiry('24h', 1_440)}>24 小时</Button>
                <Button variant={expiryMode === 'custom' ? 'soft' : 'secondary'} size="sm" onclick={() => { expiryMode = 'custom'; indefiniteConfirmed = false; }}>自定义</Button>
                <Button variant={expiryMode === 'indefinite' ? 'danger' : 'secondary'} size="sm" onclick={() => { expiryMode = 'indefinite'; indefiniteConfirmed = false; }}>无限期</Button>
              </div>
            </fieldset>
            {#if expiryMode !== 'indefinite'}
              <Input id="operations-expires-at" type="datetime-local" label="恢复时间" bind:value={customExpiry} oninput={() => (expiryMode = 'custom')} required />
            {:else}
              <label class="flex items-start gap-2 rounded-nya-sm border border-nya-danger/30 bg-nya-danger-soft p-3 text-small text-nya-danger">
                <input type="checkbox" bind:checked={indefiniteConfirmed} class="mt-0.5" />
                <span><strong class="block">确认无限期暂停</strong>该状态不会自动恢复，必须由管理员或 CLI 紧急解锁明确恢复。</span>
              </label>
            {/if}
            <div class="rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning">
              <div class="flex items-start gap-2"><AlertTriangle size={15} class="mt-0.5 shrink-0" /><p>保存后先停止接收受影响的新工作，再等待各实例的在途工作完成；设置不会因个别实例超时而自动回滚。</p></div>
            </div>
          </div>
        </section>
      {/if}

      {#if error}
        <div class="flex flex-wrap items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-4 py-3 text-small text-nya-danger" role="alert">
          <span>{error}</span>
          {#if conflict}<Button variant="secondary" size="sm" onclick={() => loadSettings()}><RefreshCw size={14} /> 加载最新状态</Button>{/if}
        </div>
      {/if}
      {#if saved}<p class="rounded-nya-sm bg-nya-success-soft px-4 py-3 text-small text-nya-success" role="status">运行控制已保存。{applicationComplete ? '所有活动实例均已应用。' : '正在等待其余实例完成排空。'}</p>{/if}
      <div class="flex flex-wrap items-center justify-between gap-3">
        <p class="flex items-center gap-1 text-small text-nya-text-tertiary"><Clock3 size={14} /> 服务控制和管理员近期重新认证始终保持可用。</p>
        <Button type="submit" variant={selectedCapabilities.length === 0 ? 'primary' : 'danger'} loading={saving}>{selectedCapabilities.length === 0 ? '恢复正常运行' : '应用运行控制'}</Button>
      </div>
    </form>
  {/if}
</div>

<ReauthenticationDialog
  bind:open={reauthOpen}
  {returnTo}
  description="修改运行控制前需要验证近期身份"
  onauthenticated={retryAfterReauthentication}
  onbeforeprovider={persistPendingInput}
/>
