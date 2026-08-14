<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    isRecentAuthenticationError,
    type MFAStatus,
    type SessionInfo,
  } from '$lib/api';
  import { sessionStore } from '$lib/stores';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Switch from '$lib/components/ui/Switch.svelte';
  import { ShieldCheck } from 'lucide-svelte';

  let {
    onsessionupdated,
    onrequirementchanged,
    providerReauthenticationFailed = false,
    returnTo = '/profile/security',
  }: {
    onsessionupdated?: (session: SessionInfo) => void;
    onrequirementchanged?: () => void | Promise<void>;
    providerReauthenticationFailed?: boolean;
    returnTo?: string;
  } = $props();

  const pendingSettingStorageKey = 'nyauth:reauth:login-mfa-requirement';

  let status = $state<MFAStatus | null>(null);
  let loading = $state(true);
  let saving = $state(false);
  let loadError = $state('');
  let actionError = $state('');
  let notice = $state('');
  let pendingEnabled = $state<boolean | null>(null);
  let reauthOpen = $state(false);
  let switchRevision = $state(0);

  onMount(async () => {
    await loadStatus();
    const restored = sessionStorage.getItem(pendingSettingStorageKey);
    sessionStorage.removeItem(pendingSettingStorageKey);
    if (providerReauthenticationFailed || (restored !== 'true' && restored !== 'false')) return;
    pendingEnabled = restored === 'true';
    await updateRequirement(pendingEnabled, false);
  });

  function updateSession(next: SessionInfo) {
    if (onsessionupdated) onsessionupdated(next);
    else sessionStore.setSession(next);
  }

  async function loadStatus() {
    loading = true;
    loadError = '';
    try {
      status = await api.getMyMFA();
    } catch (cause) {
      loadError = cause instanceof Error ? cause.message : '登录两步验证状态加载失败';
    } finally {
      loading = false;
    }
  }

  async function updateRequirement(enabled: boolean, allowReauthentication = true) {
    if (saving || !status) return;
    pendingEnabled = enabled;
    saving = true;
    actionError = '';
    notice = '';
    switchRevision += 1;
    try {
      const next = await api.updateLoginMFARequirement(enabled);
      updateSession(next);
      status = {
        ...status,
        login_mfa_enabled: enabled,
        login_mfa_required: enabled || status.required_for_current_user,
        can_disable_totp: !(enabled || status.required_for_current_user) || status.passkeys_enrolled > 0,
      };
      notice = enabled
        ? '登录两步验证已开启，后续密码或外部身份登录需要完成第二项验证。'
        : '登录两步验证已关闭；Passkey 登录和应用请求的额外验证仍然可用。';
      pendingEnabled = null;
      await onrequirementchanged?.();
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        reauthOpen = true;
        return;
      }
      actionError = cause instanceof Error ? cause.message : '无法更新登录两步验证设置';
      pendingEnabled = null;
    } finally {
      saving = false;
      switchRevision += 1;
    }
  }

  async function retryAfterReauthentication(next: SessionInfo) {
    updateSession(next);
    if (pendingEnabled !== null) await updateRequirement(pendingEnabled, false);
  }

  function persistPendingSetting() {
    if (pendingEnabled !== null) {
      sessionStorage.setItem(pendingSettingStorageKey, String(pendingEnabled));
    }
  }
</script>

<section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
  <div class="flex flex-col justify-between gap-4 border-b border-nya-divider px-7 py-5 sm:flex-row sm:items-center">
    <div class="flex items-start gap-3">
      <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-primary-soft text-nya-primary"><ShieldCheck size={19} /></span>
      <div>
        <h2 class="text-card-title text-nya-text-primary">登录两步验证</h2>
        <p class="mt-1 text-body text-nya-text-secondary">决定密码或外部身份登录后，是否必须再使用已绑定的验证因素。</p>
      </div>
    </div>
    {#if status}
      <Badge variant={status.login_mfa_required ? 'success' : 'default'}>{status.login_mfa_required ? '登录时要求' : '按需使用'}</Badge>
    {/if}
  </div>

  <div class="space-y-4 px-7 py-6">
    {#if loading}
      <p class="text-body text-nya-text-tertiary" role="status">正在加载登录两步验证设置…</p>
    {:else if loadError}
      <div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2">
        <p class="text-small text-nya-danger" role="alert">{loadError}</p>
        <Button variant="ghost" size="sm" onclick={loadStatus}>重试</Button>
      </div>
    {:else if status}
      {#if actionError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{actionError}</p>{/if}
      {#if notice}<p class="rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">{notice}</p>{/if}

      <div class="flex flex-col justify-between gap-4 rounded-nya-sm bg-nya-surface-muted p-4 sm:flex-row sm:items-center">
        <div class="min-w-0">
          <p class="text-body-medium font-semibold text-nya-text-primary">每次登录都要求第二项验证</p>
          <p class="mt-1 text-small text-nya-text-secondary">默认关闭。开启后可使用 TOTP、恢复码或 Passkey 完成登录；Passkey 直接登录无需重复验证。</p>
          {#if status.required_for_current_user}
            <p class="mt-1 text-small text-nya-warning">管理员安全策略已强制要求登录两步验证，个人设置暂不可关闭。</p>
          {:else if !status.can_enable_login_mfa && !status.login_mfa_enabled}
            <p class="mt-1 text-small text-nya-warning">请先添加动态验证码或 Passkey，再开启此设置。</p>
          {/if}
        </div>
        {#key switchRevision}
          <Switch
            checked={status.login_mfa_required}
            label={status.login_mfa_required ? '已开启' : '已关闭'}
            disabled={saving || status.required_for_current_user || (!status.can_enable_login_mfa && !status.login_mfa_enabled)}
            onchange={(enabled) => void updateRequirement(enabled)}
          />
        {/key}
      </div>
    {/if}
  </div>
</section>

<ReauthenticationDialog
  bind:open={reauthOpen}
  {returnTo}
  description="修改登录两步验证设置前，需要验证近期身份"
  onauthenticated={retryAfterReauthentication}
  onbeforeprovider={persistPendingSetting}
/>
