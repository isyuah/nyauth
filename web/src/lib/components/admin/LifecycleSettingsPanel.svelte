<script lang="ts">
  import { onMount, tick } from 'svelte';
  import {
    api,
    isAPIErrorCode,
    isRecentAuthenticationError,
    type LifecycleSettings,
    type SessionInfo,
    type UpdateLifecycleSettingsInput,
  } from '$lib/api';
  import { consumeProviderAuthError } from '$lib/stores';
  import {
    lifecycleSettingsFromInput,
    lifecycleValidationError,
    retentionConfirmation,
    validateLifecycleSettings,
  } from '$lib/policy-settings';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import FormField from '$lib/components/ui/FormField.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import { toast } from '$lib/toast';
  import { AlertTriangle, Clock3, Database, RefreshCw } from 'lucide-svelte';

  const returnTo = '/admin/settings/lifecycle';
  const pendingStorageKey = 'nyauth:reauth:lifecycle-settings';
  const numberInputClass = 'h-[38px] w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 text-body text-nya-text-primary transition-all hover:border-nya-border-strong focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24';

  let settings = $state<LifecycleSettings | null>(null);
  let sessionAbsoluteTTL = $state('24h');
  let recentAuthenticationTTL = $state('10m');
  let auditRetentionDays = $state(365);
  let retentionConfirmationInput = $state('');
  let loading = $state(true);
  let saving = $state(false);
  let error = $state('');
  let conflict = $state(false);
  let fieldErrors = $state<Record<string, string>>({});
  let reauthOpen = $state(false);
  let pendingInput = $state<UpdateLifecycleSettingsInput | null>(null);

  let shortensRetention = $derived(settings !== null && auditRetentionDays < settings.audit_retention_days);
  let requiredRetentionConfirmation = $derived(retentionConfirmation(auditRetentionDays));

  function applySettings(value: LifecycleSettings) {
    settings = { ...value };
    sessionAbsoluteTTL = value.session_absolute_ttl;
    recentAuthenticationTTL = value.recent_authentication_ttl;
    auditRetentionDays = value.audit_retention_days;
    retentionConfirmationInput = '';
    conflict = false;
    fieldErrors = {};
  }

  async function loadSettings() {
    loading = true;
    error = '';
    try {
      applySettings(await api.admin.getLifecycleSettings());
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '生命周期设置加载失败';
    } finally {
      loading = false;
    }
  }

  function buildInput(): UpdateLifecycleSettingsInput | null {
    if (!settings) return null;
    const input: UpdateLifecycleSettingsInput = {
      expected_revision: settings.revision,
      session_absolute_ttl: sessionAbsoluteTTL.trim(),
      recent_authentication_ttl: recentAuthenticationTTL.trim(),
      audit_retention_days: auditRetentionDays,
    };
    if (shortensRetention) input.retention_confirmation = retentionConfirmationInput;
    return input;
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    const input = buildInput();
    if (!input) return;
    const validationError = lifecycleValidationError(input);
    if (validationError) {
      await showFieldError(validationError.field, validationError.message);
      return;
    }
    if (shortensRetention && retentionConfirmationInput !== requiredRetentionConfirmation) {
      await showFieldError('lifecycle-retention-confirmation', `缩短审计保留期前请输入精确短语 ${requiredRetentionConfirmation}。`);
      return;
    }
    pendingInput = input;
    await executeSave(input, true);
  }

  async function executeSave(input: UpdateLifecycleSettingsInput, allowReauthentication: boolean) {
    saving = true;
    error = '';
    conflict = false;
    fieldErrors = {};
    try {
      const updated = await api.admin.updateLifecycleSettings(input);
      pendingInput = null;
      applySettings(updated);
      toast.success('生命周期设置已保存，立即对所有实例生效。');
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        reauthOpen = true;
      } else if (isAPIErrorCode(cause, 'settings.revision_conflict')) {
        conflict = true;
        error = '设置已被其他管理员修改。当前表单草稿已保留，请加载最新设置后重新核对。';
      } else {
        toast.error(cause instanceof Error ? cause.message : '生命周期设置保存失败');
      }
    } finally {
      saving = false;
    }
  }

  async function retryAfterReauthentication(_session: SessionInfo) {
    if (pendingInput) await executeSave(pendingInput, false);
  }

  function persistPendingInput() {
    if (pendingInput) sessionStorage.setItem(pendingStorageKey, JSON.stringify(pendingInput));
  }

  async function restorePendingInput() {
    const raw = sessionStorage.getItem(pendingStorageKey);
    if (!raw) return;
    sessionStorage.removeItem(pendingStorageKey);
    try {
      const restored = JSON.parse(raw) as UpdateLifecycleSettingsInput;
      if (!Number.isSafeInteger(restored.expected_revision) || validateLifecycleSettings(restored) !== '') {
        throw new TypeError('invalid stored lifecycle settings');
      }
      pendingInput = restored;
      const restoredSettings = lifecycleSettingsFromInput(restored);
      sessionAbsoluteTTL = restoredSettings.session_absolute_ttl;
      recentAuthenticationTTL = restoredSettings.recent_authentication_ttl;
      auditRetentionDays = restoredSettings.audit_retention_days;
      retentionConfirmationInput = restored.retention_confirmation || '';
      const providerError = consumeProviderAuthError();
      if (providerError) {
        toast.error(providerError.message);
        return;
      }
      await executeSave(restored, false);
    } catch {
      toast.error('无法恢复待保存的生命周期设置，请重新检查表单。');
    }
  }

  async function showFieldError(field: string, message: string) {
    fieldErrors = { [field]: message };
    toast.error(message);
    await tick();
    const element = document.getElementById(field);
    element?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    element?.focus({ preventScroll: true });
  }

  function numberClass(field: string): string {
    return `${numberInputClass} ${fieldErrors[field] ? 'border-nya-danger focus:ring-nya-danger/24' : ''}`;
  }

  onMount(async () => {
    await loadSettings();
    await restorePendingInput();
  });
</script>

<section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
  <div class="flex items-start gap-3">
    <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-primary-soft text-nya-primary"><Clock3 size={18} /></span>
    <div>
      <h2 class="text-card-title text-nya-text-primary">运行时生命周期</h2>
      <p class="mt-1 text-small text-nya-text-secondary">调整会话和近期认证时限；审计保留策略由后续 maintenance 执行，不会在保存时删除数据。</p>
    </div>
  </div>

  {#if loading && !settings}
    <p class="mt-4 text-small text-nya-text-tertiary" role="status">正在加载生命周期设置…</p>
  {:else if !settings}
    <div class="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2">
      <p class="text-small text-nya-danger" role="alert">{error || '生命周期设置不可用'}</p>
      <Button variant="ghost" size="sm" onclick={loadSettings}><RefreshCw size={14} /> 重试</Button>
    </div>
  {:else}
    <form onsubmit={submit} oninput={() => (fieldErrors = {})} class="mt-5 space-y-5">
      {#if conflict}
        <div class="flex flex-wrap items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">
          <span>{error}</span>
          {#if conflict}<Button variant="secondary" size="sm" onclick={loadSettings}><RefreshCw size={14} /> 加载最新设置</Button>{/if}
        </div>
      {/if}

      <fieldset>
        <legend class="flex items-center gap-2 text-body-medium font-semibold text-nya-text-primary"><Clock3 size={16} class="text-nya-primary" /> 会话与近期认证</legend>
        <div class="mt-3 grid gap-4 sm:grid-cols-2">
          <Input id="lifecycle-session-ttl" label="会话绝对有效期" bind:value={sessionAbsoluteTTL} placeholder="24h" error={fieldErrors['lifecycle-session-ttl']} help="会话从创建时开始计算的最长生存时间。重新登录会创建新会话；重新认证不会延长这个期限。支持 15m、24h、30d 等写法。" />
          <Input id="lifecycle-recent-auth-ttl" label="近期认证有效期" bind:value={recentAuthenticationTTL} placeholder="10m" error={fieldErrors['lifecycle-recent-auth-ttl']} help="输入密码、Passkey 或 Provider 重新认证后，可执行敏感管理操作的时间窗口。到期只要求再次认证，不会结束登录会话。" />
        </div>
        <div class="mt-3 rounded-nya-sm bg-nya-surface-muted px-3 py-2 text-small text-nya-text-secondary">
          <p>会话范围：15m–720h；近期认证范围：1m–1h。缩短会话期限后，超龄会话会在下一次认证请求时失效；延长不会恢复已过期会话。</p>
        </div>
      </fieldset>

      <fieldset class="border-t border-nya-divider pt-5">
        <legend class="flex items-center gap-2 text-body-medium font-semibold text-nya-text-primary"><Database size={16} class="text-nya-primary" /> 审计数据保留</legend>
        <div class="mt-3 max-w-sm">
          <FormField id="lifecycle-audit-retention" label="保留天数" error={fieldErrors['lifecycle-audit-retention']} hint="允许 7 至 3650 天；延长保留期不会恢复已经删除的数据。" help="审计日志至少保留的天数。保存只更新策略，真正删除由 maintenance 任务执行，因此不会在点击保存时立即清理数据。">
            <input id="lifecycle-audit-retention" class={numberClass('lifecycle-audit-retention')} type="number" min="7" max="3650" step="1" bind:value={auditRetentionDays} aria-invalid={fieldErrors['lifecycle-audit-retention'] ? 'true' : undefined} aria-describedby={fieldErrors['lifecycle-audit-retention'] ? 'lifecycle-audit-retention-error' : 'lifecycle-audit-retention-hint'} />
          </FormField>
        </div>
      </fieldset>

      {#if shortensRetention}
        <div class="rounded-nya-sm border border-nya-danger/30 bg-nya-danger-soft p-4">
          <div class="flex items-start gap-2 text-nya-danger">
            <AlertTriangle size={16} class="mt-0.5 shrink-0" />
            <div>
              <p class="text-body-medium font-semibold">审计保留期将从 {settings.audit_retention_days} 天缩短为 {auditRetentionDays} 天</p>
              <p class="mt-1 text-small">本次保存只更新策略。下一次 maintenance 执行后，超出新期限的数据会被永久删除。</p>
            </div>
          </div>
          <div class="mt-3 max-w-md"><Input id="lifecycle-retention-confirmation" label={`输入“${requiredRetentionConfirmation}”以确认`} bind:value={retentionConfirmationInput} autocomplete="off" error={fieldErrors['lifecycle-retention-confirmation']} /></div>
        </div>
      {/if}

      <div class="flex items-center justify-between gap-3">
        <p class="text-micro text-nya-text-tertiary">当前修订 {settings.revision}</p>
        <Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={saving}>保存生命周期设置</Button>
      </div>
    </form>
  {/if}
</section>

<ReauthenticationDialog
  bind:open={reauthOpen}
  {returnTo}
  description="修改生命周期策略前需要重新验证身份"
  onauthenticated={retryAfterReauthentication}
  onbeforeprovider={persistPendingInput}
/>
