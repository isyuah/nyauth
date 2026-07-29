<script lang="ts">
  import { onMount, tick } from 'svelte';
  import {
    api,
    isAPIErrorCode,
    isRecentAuthenticationError,
    type ProtectionSettings,
    type SessionInfo,
    type UpdateProtectionSettingsInput,
  } from '$lib/api';
  import { consumeProviderAuthError } from '$lib/stores';
  import {
    DEFAULT_PROTECTION_SETTINGS,
    DISABLE_RATE_LIMITS_CONFIRMATION,
    applyProtectionPreset,
    disabledProtectionGroups,
    matchingProtectionPreset,
    protectionValidationError,
    publishProtectionSettings,
    protectionSettingsFromInput,
    validateProtectionSettings,
    type ProtectionGroup,
    type ProtectionPreset,
  } from '$lib/policy-settings';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import FormField from '$lib/components/ui/FormField.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Switch from '$lib/components/ui/Switch.svelte';
  import { toast } from '$lib/toast';
  import { AlertTriangle, RefreshCw, Settings2, ShieldCheck } from 'lucide-svelte';

  const returnTo = '/admin/settings/protection';
  const pendingStorageKey = 'nyauth:reauth:protection-settings';
  const numberInputClass = 'h-[38px] w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 text-body text-nya-text-primary transition-all hover:border-nya-border-strong focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24';
  const presets: Array<{ id: ProtectionPreset; label: string; description: string }> = [
    { id: 'default', label: '默认', description: '使用当前代码安全基线' },
    { id: 'strict', label: '严格', description: '次数减半并向上取整' },
    { id: 'relaxed', label: '宽松', description: '次数扩大为默认值四倍' },
  ];
  const groupLabels: Record<ProtectionGroup, string> = {
    login: '登录',
    account: '账户操作',
    avatar: '头像',
    mail: 'SMTP 管理',
  };
  const protectionGroups: ProtectionGroup[] = ['login', 'account', 'avatar', 'mail'];

  let settings = $state<ProtectionSettings | null>(null);
  let draft = $state<ProtectionSettings>(cloneSettings(DEFAULT_PROTECTION_SETTINGS));
  let loading = $state(true);
  let saving = $state(false);
  let error = $state('');
  let conflict = $state(false);
  let fieldErrors = $state<Record<string, string>>({});
  let advancedOpen = $state(false);
  let disableConfirmation = $state('');
  let reauthOpen = $state(false);
  let pendingInput = $state<UpdateProtectionSettingsInput | null>(null);

  let currentPreset = $derived(matchingProtectionPreset(draft));
  let groupsBeingDisabled = $derived(settings ? disabledProtectionGroups(settings, draft) : []);
  let needsDisableConfirmation = $derived(groupsBeingDisabled.length > 0);

  function cloneSettings(value: ProtectionSettings): ProtectionSettings {
    return {
      revision: value.revision,
      login: { ...value.login },
      account: { ...value.account },
      avatar: { ...value.avatar },
      mail: { ...value.mail },
      owned_client_default_limit: value.owned_client_default_limit,
    };
  }

  function applySettings(value: ProtectionSettings) {
    settings = cloneSettings(value);
    draft = cloneSettings(value);
    publishProtectionSettings(value);
    disableConfirmation = '';
    conflict = false;
    fieldErrors = {};
  }

  async function loadSettings() {
    loading = true;
    error = '';
    try {
      applySettings(await api.admin.getProtectionSettings());
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '访问保护设置加载失败';
    } finally {
      loading = false;
    }
  }

  function applyPreset(preset: ProtectionPreset) {
    draft = applyProtectionPreset(draft, preset);
    error = '';
    fieldErrors = {};
  }

  function summary(group: ProtectionGroup): string {
    if (!draft[group].enabled) return '已关闭';
    if (group === 'login') return `${draft.login.window} · 身份 ${draft.login.identity_limit} / IP ${draft.login.ip_limit} / Passkey ${draft.login.passkey_ceremony_ip_limit}`;
    if (group === 'account') return `${draft.account.window} · 主体 ${draft.account.subject_limit} / IP ${draft.account.ip_limit}`;
    if (group === 'avatar') return `${draft.avatar.window} · 用户 ${draft.avatar.user_limit} / IP ${draft.avatar.ip_limit}`;
    return `${draft.mail.window} · 保存 ${draft.mail.save_limit} / 测试 ${draft.mail.test_limit} / IP ${draft.mail.ip_limit}`;
  }

  function buildInput(): UpdateProtectionSettingsInput | null {
    if (!settings) return null;
    const input: UpdateProtectionSettingsInput = {
      expected_revision: settings.revision,
      login: { ...draft.login, window: draft.login.window.trim() },
      account: { ...draft.account, window: draft.account.window.trim() },
      avatar: { ...draft.avatar, window: draft.avatar.window.trim() },
      mail: { ...draft.mail, window: draft.mail.window.trim() },
      owned_client_default_limit: draft.owned_client_default_limit,
    };
    if (needsDisableConfirmation) input.disable_confirmation = disableConfirmation;
    return input;
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    const input = buildInput();
    if (!input) return;
    const validationError = protectionValidationError(input);
    if (validationError) {
      await showFieldError(validationError.field, validationError.message);
      return;
    }
    if (needsDisableConfirmation && disableConfirmation !== DISABLE_RATE_LIMITS_CONFIRMATION) {
      await showFieldError('protection-disable-confirmation', `关闭限流前请输入精确短语 ${DISABLE_RATE_LIMITS_CONFIRMATION}。`);
      return;
    }
    pendingInput = input;
    await executeSave(input, true);
  }

  async function executeSave(input: UpdateProtectionSettingsInput, allowReauthentication: boolean) {
    saving = true;
    error = '';
    conflict = false;
    fieldErrors = {};
    try {
      const updated = await api.admin.updateProtectionSettings(input);
      pendingInput = null;
      applySettings(updated);
      toast.success('访问保护设置已保存，立即对所有实例生效。');
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        reauthOpen = true;
      } else if (isAPIErrorCode(cause, 'settings.revision_conflict')) {
        conflict = true;
        error = '设置已被其他管理员修改。当前表单草稿已保留，请加载最新设置后重新核对。';
      } else {
        toast.error(cause instanceof Error ? cause.message : '访问保护设置保存失败');
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

  function validStoredInput(value: UpdateProtectionSettingsInput): boolean {
    return Number.isSafeInteger(value.expected_revision)
      && ['login', 'account', 'avatar', 'mail'].every((group) => {
        const candidate = value[group as ProtectionGroup];
        return candidate && typeof candidate.enabled === 'boolean' && typeof candidate.window === 'string';
      })
      && validateProtectionSettings(value) === '';
  }

  async function restorePendingInput() {
    const raw = sessionStorage.getItem(pendingStorageKey);
    if (!raw) return;
    sessionStorage.removeItem(pendingStorageKey);
    try {
      const restored = JSON.parse(raw) as UpdateProtectionSettingsInput;
      if (!validStoredInput(restored)) throw new TypeError('invalid stored protection settings');
      pendingInput = restored;
      draft = protectionSettingsFromInput(restored);
      disableConfirmation = restored.disable_confirmation || '';
      const providerError = consumeProviderAuthError();
      if (providerError) {
        toast.error(providerError.message);
        return;
      }
      await executeSave(restored, false);
    } catch {
      toast.error('无法恢复待保存的访问保护设置，请重新检查表单。');
    }
  }

  async function showFieldError(field: string, message: string) {
    fieldErrors = { [field]: message };
    if (field !== 'protection-client-quota' && field !== 'protection-disable-confirmation') advancedOpen = true;
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
    <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-primary-soft text-nya-primary"><ShieldCheck size={18} /></span>
    <div>
      <h2 class="text-card-title text-nya-text-primary">动态访问保护</h2>
      <p class="mt-1 text-small text-nya-text-secondary">保存后所有实例即时采用新的 Redis 计数命名空间，不会继承旧策略窗口中的计数。</p>
    </div>
  </div>

  {#if loading && !settings}
    <p class="mt-4 text-small text-nya-text-tertiary" role="status">正在加载访问保护设置…</p>
  {:else if !settings}
    <div class="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2">
      <p class="text-small text-nya-danger" role="alert">{error || '访问保护设置不可用'}</p>
      <Button variant="ghost" size="sm" onclick={loadSettings}><RefreshCw size={14} /> 重试</Button>
    </div>
  {:else}
    <form onsubmit={submit} oninput={() => (fieldErrors = {})} class="mt-5 space-y-5">
      {#if conflict}
        <div class="flex flex-wrap items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">
          <span>{error}</span>
          <Button variant="secondary" size="sm" onclick={loadSettings}><RefreshCw size={14} /> 加载最新设置</Button>
        </div>
      {/if}

      <fieldset>
        <legend class="text-body-medium font-semibold text-nya-text-primary">策略模板</legend>
        <p class="mt-1 text-small text-nya-text-secondary">模板只更新四组限流，不修改独立的自助客户端配额。</p>
        <div class="mt-3 grid gap-2 sm:grid-cols-3">
          {#each presets as preset}
            <button
              type="button"
              onclick={() => applyPreset(preset.id)}
              aria-pressed={currentPreset === preset.id}
              class="rounded-nya-sm border px-4 py-3 text-left transition-colors {currentPreset === preset.id ? 'border-nya-primary bg-nya-primary-soft text-nya-primary' : 'border-nya-border bg-nya-surface hover:bg-nya-surface-muted'}"
            >
              <span class="block text-body-medium font-semibold">{preset.label}</span>
              <span class="mt-1 block text-micro text-nya-text-tertiary">{preset.description}</span>
            </button>
          {/each}
        </div>
      </fieldset>

      <div class="divide-y divide-nya-divider rounded-nya-sm border border-nya-border px-4">
        {#each protectionGroups as group}
          <div class="flex flex-col justify-between gap-3 py-4 sm:flex-row sm:items-start">
            <div>
              <div class="flex items-center gap-2">
                <p class="text-body-medium font-semibold text-nya-text-primary">{groupLabels[group]}</p>
                {#if !draft[group].enabled}<Badge variant="warning">已关闭</Badge>{/if}
              </div>
              <p class="mt-1 text-small text-nya-text-secondary">{summary(group)}</p>
            </div>
            <Switch bind:checked={draft[group].enabled} label={`启用${groupLabels[group]}限流`} />
          </div>
        {/each}
      </div>

      <div>
        <Button variant="secondary" onclick={() => (advancedOpen = !advancedOpen)} ariaLabel={advancedOpen ? '收起高级字段' : '展开高级字段'}>
          <Settings2 size={15} /> {advancedOpen ? '收起高级字段' : '展开高级字段'}
        </Button>
      </div>

      {#if advancedOpen}
        <div class="space-y-5 border-l-2 border-nya-primary/30 pl-4">
          <fieldset>
            <legend class="text-body-medium font-semibold text-nya-text-primary">登录限流</legend>
            <div class="mt-3 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <Input id="protection-login-window" label="窗口" bind:value={draft.login.window} placeholder="5m" error={fieldErrors['protection-login-window']} help="失败计数累计的时间范围；窗口到期后旧计数由 Redis 自动失效。支持 10s、5m、1h30m 等写法。" />
              <FormField id="protection-login-identity" label="身份次数" error={fieldErrors['protection-login-identity']} help="同一规范化用户名在窗口内允许的失败次数，跨 IP 共享额度，用于阻止攻击者换 IP 继续猜同一账户。"><input id="protection-login-identity" class={numberClass('protection-login-identity')} type="number" min="1" max="100000" step="1" bind:value={draft.login.identity_limit} aria-invalid={fieldErrors['protection-login-identity'] ? 'true' : undefined} aria-describedby={fieldErrors['protection-login-identity'] ? 'protection-login-identity-error' : undefined} /></FormField>
              <FormField id="protection-login-ip" label="IP 次数" error={fieldErrors['protection-login-ip']} help="同一来源 IP 在窗口内对所有身份合计允许的失败次数，用于限制单个来源批量尝试多个账户。"><input id="protection-login-ip" class={numberClass('protection-login-ip')} type="number" min="1" max="100000" step="1" bind:value={draft.login.ip_limit} aria-invalid={fieldErrors['protection-login-ip'] ? 'true' : undefined} aria-describedby={fieldErrors['protection-login-ip'] ? 'protection-login-ip-error' : undefined} /></FormField>
              <FormField id="protection-login-passkey" label="Passkey ceremony IP 次数" error={fieldErrors['protection-login-passkey']} help="同一 IP 在窗口内创建 Passkey/WebAuthn challenge 的次数上限。它独立于密码失败次数，用于防止大量创建短期 ceremony。"><input id="protection-login-passkey" class={numberClass('protection-login-passkey')} type="number" min="1" max="100000" step="1" bind:value={draft.login.passkey_ceremony_ip_limit} aria-invalid={fieldErrors['protection-login-passkey'] ? 'true' : undefined} aria-describedby={fieldErrors['protection-login-passkey'] ? 'protection-login-passkey-error' : undefined} /></FormField>
            </div>
          </fieldset>

          <fieldset>
            <legend class="text-body-medium font-semibold text-nya-text-primary">账户操作限流</legend>
            <div class="mt-3 grid gap-4 sm:grid-cols-3">
              <Input id="protection-account-window" label="窗口" bind:value={draft.account.window} placeholder="15m" error={fieldErrors['protection-account-window']} help="账户敏感操作的计数范围，包括邮件操作、重新认证及相关安全变更。支持 10s 至 24h。" />
              <FormField id="protection-account-subject" label="主体次数" error={fieldErrors['protection-account-subject']} help="同一账户或不可逆邮箱摘要在窗口内允许的操作次数，跨 IP 聚合；不会在 Redis 中保存明文邮箱。"><input id="protection-account-subject" class={numberClass('protection-account-subject')} type="number" min="1" max="100000" step="1" bind:value={draft.account.subject_limit} aria-invalid={fieldErrors['protection-account-subject'] ? 'true' : undefined} aria-describedby={fieldErrors['protection-account-subject'] ? 'protection-account-subject-error' : undefined} /></FormField>
              <FormField id="protection-account-ip" label="IP 次数" error={fieldErrors['protection-account-ip']} help="同一来源 IP 在窗口内对所有账户合计允许的账户操作次数。"><input id="protection-account-ip" class={numberClass('protection-account-ip')} type="number" min="1" max="100000" step="1" bind:value={draft.account.ip_limit} aria-invalid={fieldErrors['protection-account-ip'] ? 'true' : undefined} aria-describedby={fieldErrors['protection-account-ip'] ? 'protection-account-ip-error' : undefined} /></FormField>
            </div>
          </fieldset>

          <fieldset>
            <legend class="text-body-medium font-semibold text-nya-text-primary">头像限流</legend>
            <div class="mt-3 grid gap-4 sm:grid-cols-3">
              <Input id="protection-avatar-window" label="窗口" bind:value={draft.avatar.window} placeholder="15m" error={fieldErrors['protection-avatar-window']} help="头像上传和删除的计数范围。读取头像及后台对象清理不计入此额度。" />
              <FormField id="protection-avatar-user" label="用户次数" error={fieldErrors['protection-avatar-user']} help="单个登录用户在窗口内允许的头像写操作次数，跨 IP 共享额度。"><input id="protection-avatar-user" class={numberClass('protection-avatar-user')} type="number" min="1" max="100000" step="1" bind:value={draft.avatar.user_limit} aria-invalid={fieldErrors['protection-avatar-user'] ? 'true' : undefined} aria-describedby={fieldErrors['protection-avatar-user'] ? 'protection-avatar-user-error' : undefined} /></FormField>
              <FormField id="protection-avatar-ip" label="IP 次数" error={fieldErrors['protection-avatar-ip']} help="同一来源 IP 在窗口内对所有用户合计允许的头像写操作次数。"><input id="protection-avatar-ip" class={numberClass('protection-avatar-ip')} type="number" min="1" max="100000" step="1" bind:value={draft.avatar.ip_limit} aria-invalid={fieldErrors['protection-avatar-ip'] ? 'true' : undefined} aria-describedby={fieldErrors['protection-avatar-ip'] ? 'protection-avatar-ip-error' : undefined} /></FormField>
            </div>
          </fieldset>

          <fieldset>
            <legend class="text-body-medium font-semibold text-nya-text-primary">SMTP 管理限流</legend>
            <div class="mt-3 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <Input id="protection-mail-window" label="窗口" bind:value={draft.mail.window} placeholder="15m" error={fieldErrors['protection-mail-window']} help="SMTP 管理操作的计数范围。保存、测试、激活、回滚和禁用分别计数，IP 次数对它们合计计数。" />
              <FormField id="protection-mail-save" label="保存次数" error={fieldErrors['protection-mail-save']} help="单个管理员在窗口内保存 SMTP 候选配置的次数。"><input id="protection-mail-save" class={numberClass('protection-mail-save')} type="number" min="1" max="100000" step="1" bind:value={draft.mail.save_limit} aria-invalid={fieldErrors['protection-mail-save'] ? 'true' : undefined} aria-describedby={fieldErrors['protection-mail-save'] ? 'protection-mail-save-error' : undefined} /></FormField>
              <FormField id="protection-mail-test" label="测试次数" error={fieldErrors['protection-mail-test']} help="单个管理员在窗口内实际连接 SMTP 并发送测试邮件的次数。"><input id="protection-mail-test" class={numberClass('protection-mail-test')} type="number" min="1" max="100000" step="1" bind:value={draft.mail.test_limit} aria-invalid={fieldErrors['protection-mail-test'] ? 'true' : undefined} aria-describedby={fieldErrors['protection-mail-test'] ? 'protection-mail-test-error' : undefined} /></FormField>
              <FormField id="protection-mail-activate" label="激活次数" error={fieldErrors['protection-mail-activate']} help="单个管理员在窗口内激活已测试候选版本的次数。"><input id="protection-mail-activate" class={numberClass('protection-mail-activate')} type="number" min="1" max="100000" step="1" bind:value={draft.mail.activate_limit} aria-invalid={fieldErrors['protection-mail-activate'] ? 'true' : undefined} aria-describedby={fieldErrors['protection-mail-activate'] ? 'protection-mail-activate-error' : undefined} /></FormField>
              <FormField id="protection-mail-rollback" label="回滚次数" error={fieldErrors['protection-mail-rollback']} help="单个管理员在窗口内回滚到上一邮件配置版本的次数。"><input id="protection-mail-rollback" class={numberClass('protection-mail-rollback')} type="number" min="1" max="100000" step="1" bind:value={draft.mail.rollback_limit} aria-invalid={fieldErrors['protection-mail-rollback'] ? 'true' : undefined} aria-describedby={fieldErrors['protection-mail-rollback'] ? 'protection-mail-rollback-error' : undefined} /></FormField>
              <FormField id="protection-mail-disable" label="禁用次数" error={fieldErrors['protection-mail-disable']} help="单个管理员在窗口内禁用 SMTP 投递的次数；注册开放时后端仍会阻止禁用。"><input id="protection-mail-disable" class={numberClass('protection-mail-disable')} type="number" min="1" max="100000" step="1" bind:value={draft.mail.disable_limit} aria-invalid={fieldErrors['protection-mail-disable'] ? 'true' : undefined} aria-describedby={fieldErrors['protection-mail-disable'] ? 'protection-mail-disable-error' : undefined} /></FormField>
              <FormField id="protection-mail-ip" label="IP 次数" error={fieldErrors['protection-mail-ip']} help="同一来源 IP 在窗口内所有 SMTP 管理操作的合计次数，独立于管理员额度。"><input id="protection-mail-ip" class={numberClass('protection-mail-ip')} type="number" min="1" max="100000" step="1" bind:value={draft.mail.ip_limit} aria-invalid={fieldErrors['protection-mail-ip'] ? 'true' : undefined} aria-describedby={fieldErrors['protection-mail-ip'] ? 'protection-mail-ip-error' : undefined} /></FormField>
            </div>
          </fieldset>
        </div>
      {/if}

      <div class="border-t border-nya-divider pt-5">
        <div class="max-w-sm">
          <FormField id="protection-client-quota" label="自助客户端全局默认配额" error={fieldErrors['protection-client-quota']} hint="允许 0 至 1000；0 会阻止新建或转入，不删除已有客户端。" help="适用于没有用户级覆盖值的客户端 Owner。管理员创建的无 Owner 客户端不受此配额限制。">
            <input id="protection-client-quota" class={numberClass('protection-client-quota')} type="number" min="0" max="1000" step="1" bind:value={draft.owned_client_default_limit} aria-invalid={fieldErrors['protection-client-quota'] ? 'true' : undefined} aria-describedby={fieldErrors['protection-client-quota'] ? 'protection-client-quota-error' : 'protection-client-quota-hint'} />
          </FormField>
        </div>
      </div>

      {#if needsDisableConfirmation}
        <div class="rounded-nya-sm border border-nya-danger/30 bg-nya-danger-soft p-4">
          <div class="flex items-start gap-2 text-nya-danger">
            <AlertTriangle size={16} class="mt-0.5 shrink-0" />
            <div><p class="text-body-medium font-semibold">正在关闭 {groupsBeingDisabled.map((group) => groupLabels[group]).join('、')} 限流</p><p class="mt-1 text-small">关闭后的请求不会访问 Redis，也不会再受该组频率保护。</p></div>
          </div>
          <div class="mt-3 max-w-md"><Input id="protection-disable-confirmation" label={`输入“${DISABLE_RATE_LIMITS_CONFIRMATION}”以确认`} bind:value={disableConfirmation} autocomplete="off" error={fieldErrors['protection-disable-confirmation']} /></div>
        </div>
      {/if}

      <div class="flex items-center justify-between gap-3">
        <p class="text-micro text-nya-text-tertiary">当前修订 {settings.revision}</p>
        <Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={saving}>保存访问保护设置</Button>
      </div>
    </form>
  {/if}
</section>

<ReauthenticationDialog
  bind:open={reauthOpen}
  {returnTo}
  description="修改访问保护策略前需要重新验证身份"
  onauthenticated={retryAfterReauthentication}
  onbeforeprovider={persistPendingInput}
/>
