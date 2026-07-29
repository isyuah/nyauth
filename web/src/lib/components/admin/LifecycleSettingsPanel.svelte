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
  import { AlertTriangle, Clock3, Database, KeyRound, MonitorSmartphone, RefreshCw } from 'lucide-svelte';

  const returnTo = '/admin/settings/lifecycle';
  const pendingStorageKey = 'nyauth:reauth:lifecycle-settings';
  const numberInputClass = 'h-[38px] w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 text-body text-nya-text-primary transition-all hover:border-nya-border-strong focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24';

  let settings = $state<LifecycleSettings | null>(null);
  let sessionAbsoluteTTL = $state('24h');
  let sessionIdleTTL = $state('24h');
  let maxConcurrentSessions = $state(0);
  let recentAuthenticationTTL = $state('10m');
  let accessTokenTTL = $state('1h');
  let refreshTokenTTL = $state('720h');
  let authorizationCodeTTL = $state('5m');
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
    sessionIdleTTL = value.session_idle_ttl;
    maxConcurrentSessions = value.max_concurrent_sessions;
    recentAuthenticationTTL = value.recent_authentication_ttl;
    accessTokenTTL = value.access_token_ttl;
    refreshTokenTTL = value.refresh_token_ttl;
    authorizationCodeTTL = value.authorization_code_ttl;
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
      session_idle_ttl: sessionIdleTTL.trim(),
      max_concurrent_sessions: maxConcurrentSessions,
      recent_authentication_ttl: recentAuthenticationTTL.trim(),
      access_token_ttl: accessTokenTTL.trim(),
      refresh_token_ttl: refreshTokenTTL.trim(),
      authorization_code_ttl: authorizationCodeTTL.trim(),
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
      sessionIdleTTL = restoredSettings.session_idle_ttl;
      maxConcurrentSessions = restoredSettings.max_concurrent_sessions;
      recentAuthenticationTTL = restoredSettings.recent_authentication_ttl;
      accessTokenTTL = restoredSettings.access_token_ttl;
      refreshTokenTTL = restoredSettings.refresh_token_ttl;
      authorizationCodeTTL = restoredSettings.authorization_code_ttl;
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
      <p class="mt-1 text-small text-nya-text-secondary">调整浏览器会话、OAuth 凭据和审计数据的运行时生命周期。</p>
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
        <legend class="flex items-center gap-2 text-body-medium font-semibold text-nya-text-primary"><MonitorSmartphone size={16} class="text-nya-primary" /> 浏览器会话</legend>
        <div class="mt-3 grid gap-4 sm:grid-cols-2">
          <Input id="lifecycle-session-ttl" label="会话绝对有效期" bind:value={sessionAbsoluteTTL} placeholder="24h" error={fieldErrors['lifecycle-session-ttl']} help="会话从创建时开始计算的最长生存时间。重新登录会创建新会话；重新认证不会延长这个期限。支持 15m、24h、30d 等写法。" />
          <Input id="lifecycle-session-idle-ttl" label="会话空闲有效期" bind:value={sessionIdleTTL} placeholder="24h" error={fieldErrors['lifecycle-session-idle-ttl']} help="用户持续多长时间没有活动后结束会话。每次有效请求按需刷新空闲期限，但永远不能越过绝对有效期。" />
          <Input id="lifecycle-recent-auth-ttl" label="近期认证有效期" bind:value={recentAuthenticationTTL} placeholder="10m" error={fieldErrors['lifecycle-recent-auth-ttl']} help="输入密码、Passkey 或 Provider 重新认证后，可执行敏感管理操作的时间窗口。到期只要求再次认证，不会结束登录会话。" />
          <FormField id="lifecycle-max-concurrent-sessions" label="每位用户并发会话上限" error={fieldErrors['lifecycle-max-concurrent-sessions']} hint="0 表示不限制；允许 0 至 100。" help="限制同一用户可同时保持的浏览器会话数量。降低上限不会立刻踢出用户；该用户下一次登录时会原子淘汰最旧会话。">
            <input id="lifecycle-max-concurrent-sessions" class={numberClass('lifecycle-max-concurrent-sessions')} type="number" min="0" max="100" step="1" bind:value={maxConcurrentSessions} aria-invalid={fieldErrors['lifecycle-max-concurrent-sessions'] ? 'true' : undefined} />
          </FormField>
        </div>
        <div class="mt-3 rounded-nya-sm bg-nya-surface-muted px-3 py-2 text-small text-nya-text-secondary">
          <p>绝对期限 15m–720h，空闲期限 5m–720h 且不能超过绝对期限。缩短后，超龄会话在下一次请求时失效；延长不会恢复已过期会话。</p>
        </div>
      </fieldset>

      <fieldset class="border-t border-nya-divider pt-5">
        <legend class="flex items-center gap-2 text-body-medium font-semibold text-nya-text-primary"><KeyRound size={16} class="text-nya-primary" /> OAuth / OIDC 凭据</legend>
        <div class="mt-3 grid gap-4 sm:grid-cols-3">
          <Input id="lifecycle-access-token-ttl" label="Access Token 有效期" bind:value={accessTokenTTL} placeholder="1h" error={fieldErrors['lifecycle-access-token-ttl']} help="新签发 Access Token 与 ID Token 的有效期。已签发 Token 保持原到期时间。允许 5m–24h。" />
          <Input id="lifecycle-refresh-token-ttl" label="Refresh Token 有效期" bind:value={refreshTokenTTL} placeholder="720h" error={fieldErrors['lifecycle-refresh-token-ttl']} help="新签发或下一次轮换后的 Refresh Token 有效期。已有 Token 不会被批量延长或缩短。允许 1h–8760h。" />
          <Input id="lifecycle-authorization-code-ttl" label="授权码有效期" bind:value={authorizationCodeTTL} placeholder="5m" error={fieldErrors['lifecycle-authorization-code-ttl']} help="用户授权后生成的一次性授权码有效期。已生成授权码保持原期限。允许 30s–10m。" />
        </div>
        <div class="mt-3 rounded-nya-sm bg-nya-surface-muted px-3 py-2 text-small text-nya-text-secondary">
          <p>策略变更只影响之后新签发或轮换的凭据，不扫描 Redis，也不会隐式吊销已经签发的 Token。</p>
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
