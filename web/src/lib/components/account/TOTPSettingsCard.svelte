<script lang="ts">
  import { onMount } from 'svelte';
  import QRCode from 'qrcode';
  import {
    api,
    isRecentAuthenticationError,
    type MFAStatus,
    type SessionInfo,
    type TOTPEnrollment,
  } from '$lib/api';
  import { sessionStore } from '$lib/stores';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import CopyButton from '$lib/components/ui/CopyButton.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import CopyField from '$lib/components/data-display/CopyField.svelte';
  import ReauthenticationDialog from './ReauthenticationDialog.svelte';
  import { KeyRound, RefreshCw, ShieldCheck, ShieldOff } from 'lucide-svelte';

  type ProtectedAction = 'enroll' | 'regenerate' | 'disable';

  let {
    onsessionupdated,
    providerReauthenticationFailed = false,
    returnTo = '/profile',
  }: {
    onsessionupdated?: (session: SessionInfo) => void;
    providerReauthenticationFailed?: boolean;
    returnTo?: string;
  } = $props();

  const pendingActionStorageKey = 'nyauth:reauth:mfa-action';

  let status = $state<MFAStatus | null>(null);
  let loading = $state(true);
  let loadError = $state('');
  let actionError = $state('');
  let notice = $state('');
  let actionLoading = $state<ProtectedAction | null>(null);
  let pendingAction = $state<ProtectedAction | null>(null);
  let reauthOpen = $state(false);

  let enrollment = $state<TOTPEnrollment | null>(null);
  let enrollmentOpen = $state(false);
  let qrDataURL = $state('');
  let qrError = $state('');
  let confirmationCode = $state('');
  let confirmationError = $state('');
  let confirmationLoading = $state(false);
  let enrollmentGeneration = 0;

  let recoveryCodes = $state<string[]>([]);
  let recoveryCodesOpen = $state(false);
  let recoveryCodesTitle = $state('恢复码');
  let disableConfirmOpen = $state(false);
  let disableError = $state('');

  $effect(() => {
    if (!enrollmentOpen && enrollment) {
      enrollmentGeneration += 1;
      enrollment = null;
      qrDataURL = '';
      qrError = '';
      confirmationCode = '';
      confirmationError = '';
    }
  });

  $effect(() => {
    if (!recoveryCodesOpen && recoveryCodes.length > 0) recoveryCodes = [];
  });

  onMount(async () => {
    await loadStatus();
    const restored = sessionStorage.getItem(pendingActionStorageKey);
    sessionStorage.removeItem(pendingActionStorageKey);
    if (restored === 'enroll' || restored === 'regenerate' || restored === 'disable') {
      if (providerReauthenticationFailed) return;
      pendingAction = restored;
      try {
        await runProtectedAction(restored, false);
      } catch {
        // The card already exposes the actionable server error.
      }
    }
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
      status = null;
      loadError = cause instanceof Error ? cause.message : '多因素验证状态加载失败';
    } finally {
      loading = false;
    }
  }

  function showRecoveryCodes(codes: string[], title: string) {
    recoveryCodes = [...codes];
    recoveryCodesTitle = title;
    recoveryCodesOpen = true;
  }

  async function beginEnrollment() {
    const generation = ++enrollmentGeneration;
    const next = await api.beginTOTPEnrollment();
    enrollment = next;
    qrDataURL = '';
    qrError = '';
    confirmationCode = '';
    confirmationError = '';
    enrollmentOpen = true;
    try {
      const generated = await QRCode.toDataURL(next.otpauth_uri, {
        errorCorrectionLevel: 'M',
        margin: 1,
        width: 232,
      });
      if (generation === enrollmentGeneration && enrollmentOpen) qrDataURL = generated;
    } catch {
      if (generation === enrollmentGeneration && enrollmentOpen) {
        qrError = '二维码生成失败，请使用下方密钥手动添加。';
      }
    }
  }

  async function regenerateRecoveryCodes() {
    const result = await api.regenerateRecoveryCodes();
    if (status) status = { ...status, recovery_codes_remaining: result.recovery_codes.length };
    showRecoveryCodes(result.recovery_codes, '新的恢复码');
    notice = '旧恢复码已全部失效，请立即保存这组新恢复码。';
  }

  async function disableTOTP() {
    const next = await api.disableTOTP();
    updateSession(next);
    if (status) {
      status = { ...status, totp_enrolled: false, recovery_codes_remaining: 0 };
    }
    disableError = '';
    notice = '动态验证码已停用，相关恢复码也已失效。';
  }

  async function runProtectedAction(action: ProtectedAction, allowReauthentication: boolean) {
    pendingAction = action;
    actionLoading = action;
    actionError = '';
    notice = '';
    try {
      if (action === 'enroll') await beginEnrollment();
      else if (action === 'regenerate') await regenerateRecoveryCodes();
      else await disableTOTP();
      pendingAction = null;
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        reauthOpen = true;
        return;
      }
      const message = cause instanceof Error ? cause.message : '多因素验证操作失败';
      if (action === 'disable') disableError = message;
      else actionError = message;
      pendingAction = null;
      throw cause;
    } finally {
      actionLoading = null;
    }
  }

  async function retryProtectedAction() {
    const action = pendingAction;
    if (!action) return;
    try {
      await runProtectedAction(action, false);
    } catch {
      // The card already exposes the actionable server error.
    }
  }

  function persistPendingAction() {
    if (pendingAction) sessionStorage.setItem(pendingActionStorageKey, pendingAction);
  }

  async function confirmEnrollment(event: SubmitEvent) {
    event.preventDefault();
    const code = confirmationCode.trim();
    confirmationError = '';
    if (!/^\d{6}$/.test(code)) {
      confirmationError = '请输入身份验证器当前显示的 6 位数字。';
      return;
    }
    confirmationLoading = true;
    try {
      const result = await api.confirmTOTPEnrollment(code);
      const { recovery_codes: codes, ...nextSession } = result;
      updateSession(nextSession);
      if (status) {
        status = {
          ...status,
          totp_enrolled: true,
          recovery_codes_remaining: codes.length,
        };
      }
      enrollmentOpen = false;
      showRecoveryCodes(codes, '保存恢复码');
      notice = '动态验证码已启用。恢复码关闭后不会再次显示。';
    } catch (cause) {
      if (isRecentAuthenticationError(cause)) {
        enrollmentOpen = false;
        pendingAction = 'enroll';
        actionError = '近期身份验证已过期。重新认证后会生成一份新的设置密钥。';
        reauthOpen = true;
      } else {
        confirmationError = cause instanceof Error ? cause.message : '无法确认动态验证码';
      }
    } finally {
      confirmationLoading = false;
    }
  }

  async function confirmDisable() {
    disableError = '';
    await runProtectedAction('disable', true);
  }
</script>

<section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
  <div class="flex flex-col justify-between gap-4 border-b border-nya-divider px-7 py-5 sm:flex-row sm:items-center">
    <div class="flex items-start gap-3">
      <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-primary-soft text-nya-primary"><ShieldCheck size={19} /></span>
      <div>
        <h2 class="text-card-title text-nya-text-primary">动态验证码与恢复码</h2>
        <p class="mt-1 text-body text-nya-text-secondary">使用兼容 RFC 6238 的身份验证器为登录增加第二项验证。</p>
      </div>
    </div>
    {#if status}<Badge variant={status.totp_enrolled ? 'success' : status.totp_available ? 'warning' : 'default'}>{status.totp_enrolled ? '已启用' : status.totp_available ? '未启用' : '不可注册'}</Badge>{/if}
  </div>

  <div class="space-y-4 px-7 py-6">
    {#if loading}
      <p class="text-body text-nya-text-tertiary" role="status">正在加载多因素验证状态…</p>
    {:else if loadError}
      <div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2">
        <p class="text-small text-nya-danger" role="alert">{loadError}</p>
        <Button variant="ghost" size="sm" onclick={loadStatus}>重试</Button>
      </div>
    {:else if status}
      {#if actionError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{actionError}</p>{/if}
      {#if notice}<p class="rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">{notice}</p>{/if}

      {#if status.totp_enrolled}
        <div class="flex flex-col justify-between gap-4 rounded-nya-sm bg-nya-surface-muted p-4 sm:flex-row sm:items-center">
          <div>
            <p class="text-body-medium font-semibold text-nya-text-primary">动态验证码已保护此账户</p>
            <p class="mt-1 text-small text-nya-text-secondary">剩余 {status.recovery_codes_remaining} 枚一次性恢复码。</p>
            {#if !status.can_disable_totp}<p class="mt-1 text-small text-nya-warning">管理员安全策略要求保留至少一种多因素验证方式；注册 Passkey 后可停用动态验证码。</p>{/if}
          </div>
          <div class="flex flex-wrap gap-2">
            <Button variant="secondary" requiredCapability="account_mutations" loading={actionLoading === 'regenerate'} disabled={actionLoading !== null} onclick={() => void runProtectedAction('regenerate', true).catch(() => {})}>
              <RefreshCw size={15} /> 重新生成恢复码
            </Button>
            <Button variant="ghost" requiredCapability="account_mutations" disabled={!status.can_disable_totp || actionLoading !== null} onclick={() => { disableError = ''; disableConfirmOpen = true; }}>
              <ShieldOff size={15} /> 停用
            </Button>
          </div>
        </div>
      {:else}
        <div class="flex flex-col justify-between gap-4 rounded-nya-sm bg-nya-surface-muted p-4 sm:flex-row sm:items-center">
          <div>
            <p class="text-body-medium font-semibold text-nya-text-primary">尚未启用动态验证码</p>
            <p class="mt-1 text-small text-nya-text-secondary">启用后，密码或外部身份登录还需输入动态验证码或恢复码。</p>
            {#if !status.totp_available}<p class="mt-1 text-small text-nya-warning">管理员当前已关闭新的动态验证码注册。</p>{/if}
          </div>
          <Button variant="primary" requiredCapability="account_mutations" loading={actionLoading === 'enroll'} disabled={!status.totp_available || actionLoading !== null} onclick={() => void runProtectedAction('enroll', true).catch(() => {})}>
            <KeyRound size={16} /> 启用动态验证码
          </Button>
        </div>
      {/if}
    {/if}
  </div>
</section>

<Modal bind:open={enrollmentOpen} title="启用动态验证码" description="扫描二维码后，输入身份验证器当前显示的 6 位数字" size="md">
  {#if enrollment}
    <form onsubmit={confirmEnrollment} class="space-y-5">
      {#if confirmationError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{confirmationError}</p>{/if}
      <div class="flex min-h-[232px] items-center justify-center rounded-nya-sm bg-white p-3">
        {#if qrDataURL}
          <img src={qrDataURL} alt="用于配置动态验证码的二维码" class="h-[232px] w-[232px]" />
        {:else if qrError}
          <p class="max-w-xs text-center text-small text-nya-danger">{qrError}</p>
        {:else}
          <p class="text-small text-nya-text-tertiary" role="status">正在生成二维码…</p>
        {/if}
      </div>
      <CopyField label="无法扫描时手动输入此密钥" value={enrollment.secret} />
      <Input id="totp-enrollment-code" label="6 位动态验证码" bind:value={confirmationCode} inputmode="numeric" autocomplete="one-time-code" maxlength={6} required placeholder="123456" />
      <div class="flex justify-end gap-2">
        <Button variant="secondary" disabled={confirmationLoading} onclick={() => (enrollmentOpen = false)}>取消</Button>
        <Button type="submit" variant="primary" requiredCapability="account_mutations" loading={confirmationLoading}>确认并启用</Button>
      </div>
    </form>
  {/if}
</Modal>

<Modal bind:open={recoveryCodesOpen} title={recoveryCodesTitle} description="这些恢复码只显示这一次，每枚只能使用一次" size="md" dismissible={false}>
  <div class="space-y-4">
    <p class="rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning">请把全部 {recoveryCodes.length} 枚恢复码保存到密码管理器或其他安全位置。不要只保存在当前设备上。</p>
    <div class="grid gap-2 rounded-nya-sm border border-nya-border bg-nya-surface-muted p-4 sm:grid-cols-2">
      {#each recoveryCodes as recoveryCode, index}
        <code class="select-all rounded-nya-xs bg-nya-surface px-3 py-2 font-mono text-small text-nya-text-primary">{index + 1}. {recoveryCode}</code>
      {/each}
    </div>
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div class="flex items-center gap-2 text-small text-nya-text-secondary"><CopyButton value={recoveryCodes.join('\n')} label="复制全部恢复码" /> 复制全部恢复码</div>
      <Button variant="primary" onclick={() => (recoveryCodesOpen = false)}>我已安全保存</Button>
    </div>
  </div>
</Modal>

<ConfirmDialog
  bind:open={disableConfirmOpen}
  title="停用动态验证码"
  description="停用后，现有恢复码会全部失效；后续登录将不再要求第二项验证。"
  confirmLabel="确认停用"
  error={disableError}
  onconfirm={confirmDisable}
/>

<ReauthenticationDialog
  bind:open={reauthOpen}
  {returnTo}
  description="启用、重置或停用多因素验证前，需要验证近期身份"
  onauthenticated={retryProtectedAction}
  onbeforeprovider={persistPendingAction}
/>
