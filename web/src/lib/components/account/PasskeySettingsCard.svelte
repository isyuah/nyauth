<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    isRecentAuthenticationError,
    type MFAStatus,
    type PasskeyCredential,
    type SessionInfo,
  } from '$lib/api';
  import { sessionStore } from '$lib/stores';
  import {
    WEBAUTHN_ERROR_CODES,
    classifyWebAuthnError,
    createCredential,
    registrationCredentialToJSON,
  } from '$lib/webauthn';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import ReauthenticationDialog from './ReauthenticationDialog.svelte';
  import { Fingerprint, Pencil, Plus, ShieldAlert, Trash2 } from 'lucide-svelte';

  type PendingAction =
    | { kind: 'register'; name: string }
    | { kind: 'delete'; id: string }
    | null;

  let {
    onsessionupdated,
    providerReauthenticationFailed = false,
    returnTo = '/profile',
  }: {
    onsessionupdated?: (session: SessionInfo) => void;
    providerReauthenticationFailed?: boolean;
    returnTo?: string;
  } = $props();

  const pendingActionStorageKey = 'nyauth:reauth:passkey-action';

  let passkeys = $state<PasskeyCredential[]>([]);
  let status = $state<MFAStatus | null>(null);
  let loading = $state(true);
  let loadError = $state('');
  let actionError = $state('');
  let notice = $state('');
  let actionLoading = $state(false);
  let pendingAction = $state<PendingAction>(null);
  let reauthOpen = $state(false);
  let ceremonyController: AbortController | null = null;

  let registrationOpen = $state(false);
  let registrationName = $state('');
  let registrationError = $state('');

  let renameTarget = $state<PasskeyCredential | null>(null);
  let renameOpen = $state(false);
  let renameName = $state('');
  let renameLoading = $state(false);
  let renameError = $state('');

  let deleteTarget = $state<PasskeyCredential | null>(null);
  let deleteOpen = $state(false);
  let deleteError = $state('');

  onMount(() => {
    void initialize();
    return () => ceremonyController?.abort();
  });

  async function initialize() {
    await loadPasskeys();
    const raw = sessionStorage.getItem(pendingActionStorageKey);
    sessionStorage.removeItem(pendingActionStorageKey);
    if (!raw || providerReauthenticationFailed) return;
    try {
      const restored = JSON.parse(raw) as PendingAction;
      if (restored?.kind === 'register' && typeof restored.name === 'string') {
        pendingAction = { kind: 'register', name: restored.name };
      } else if (restored?.kind === 'delete' && typeof restored.id === 'string') {
        pendingAction = { kind: 'delete', id: restored.id };
      }
      if (pendingAction) await retryProtectedAction();
    } catch {
      actionError = '无法恢复待执行的 Passkey 操作，请重新发起。';
      pendingAction = null;
    }
  }

  function updateSession(next: SessionInfo) {
    if (onsessionupdated) onsessionupdated(next);
    else sessionStore.setSession(next);
  }

  async function loadPasskeys() {
    loading = true;
    loadError = '';
    try {
      const [list, currentStatus] = await Promise.all([api.getMyPasskeys(), api.getMyMFA()]);
      passkeys = list.passkeys;
      status = currentStatus;
    } catch (cause) {
      loadError = cause instanceof Error ? cause.message : 'Passkey 列表加载失败';
    } finally {
      loading = false;
    }
  }

  function openRegistration() {
    registrationName = '';
    registrationError = '';
    registrationOpen = true;
  }

  function openRename(passkey: PasskeyCredential) {
    renameTarget = passkey;
    renameName = passkey.name;
    renameError = '';
    renameOpen = true;
  }

  function openDelete(passkey: PasskeyCredential) {
    deleteTarget = passkey;
    deleteError = '';
    deleteOpen = true;
  }

  function passkeyErrorMessage(cause: unknown): string {
    switch (classifyWebAuthnError(cause)) {
      case WEBAUTHN_ERROR_CODES.notAllowed:
        return '未完成 Passkey 注册，系统验证窗口可能已关闭。';
      case WEBAUTHN_ERROR_CODES.invalidState:
        return '这枚 Passkey 已经注册，或当前设备拒绝重复创建。';
      case WEBAUTHN_ERROR_CODES.notSupported:
        return '当前浏览器或设备不支持创建 Passkey。';
      case WEBAUTHN_ERROR_CODES.security:
        return '当前页面不满足 Passkey 的安全环境要求，请使用 HTTPS 或 localhost。';
      default:
        return cause instanceof Error ? cause.message : 'Passkey 操作失败';
    }
  }

  async function registerPasskey(name: string) {
    ceremonyController?.abort();
    const controller = new AbortController();
    ceremonyController = controller;
    const options = await api.beginPasskeyRegistration(name, controller.signal);
    const credential = await createCredential(options.public_key, { signal: controller.signal });
    const result = await api.finishPasskeyRegistration(
      options.ceremony_id,
      registrationCredentialToJSON(credential),
      controller.signal,
    );
    ceremonyController = null;
    const { passkey, ...nextSession } = result;
    updateSession(nextSession);
    passkeys = [passkey, ...passkeys.filter((item) => item.id !== passkey.id)];
    if (status) status = { ...status, passkeys_enrolled: passkeys.length };
    registrationOpen = false;
    registrationName = '';
    notice = `Passkey“${passkey.name}”已注册，当前会话已安全轮换。`;
  }

  async function removePasskey(id: string) {
    const next = await api.deletePasskey(id);
    updateSession(next);
    passkeys = passkeys.filter((item) => item.id !== id);
    if (status) {
      const remaining = passkeys.length;
      status = {
        ...status,
        passkeys_enrolled: remaining,
        can_disable_totp: !status.required_for_current_user || remaining > 0,
      };
    }
    deleteOpen = false;
    deleteTarget = null;
    notice = 'Passkey 已删除，当前会话已安全轮换。';
  }

  async function runProtectedAction(action: Exclude<PendingAction, null>, allowReauthentication: boolean) {
    pendingAction = action;
    actionLoading = true;
    actionError = '';
    registrationError = '';
    deleteError = '';
    notice = '';
    try {
      if (action.kind === 'register') await registerPasskey(action.name);
      else await removePasskey(action.id);
      pendingAction = null;
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        registrationOpen = false;
        deleteOpen = false;
        reauthOpen = true;
        return;
      }
      if (classifyWebAuthnError(cause) === WEBAUTHN_ERROR_CODES.aborted) {
        pendingAction = null;
        return;
      }
      const message = passkeyErrorMessage(cause);
      if (action.kind === 'register') registrationError = message;
      else deleteError = message;
      actionError = message;
      pendingAction = null;
      throw cause;
    } finally {
      actionLoading = false;
      ceremonyController = null;
    }
  }

  async function submitRegistration(event: SubmitEvent) {
    event.preventDefault();
    const name = registrationName.trim();
    registrationError = '';
    if (!name || [...name].length > 64) {
      registrationError = 'Passkey 名称须为 1 至 64 个字符。';
      return;
    }
    try {
      await runProtectedAction({ kind: 'register', name }, true);
    } catch {
      // The modal and card expose the actionable error.
    }
  }

  async function submitRename(event: SubmitEvent) {
    event.preventDefault();
    const target = renameTarget;
    if (!target) return;
    const name = renameName.trim();
    renameError = '';
    if (!name || [...name].length > 64) {
      renameError = 'Passkey 名称须为 1 至 64 个字符。';
      return;
    }
    renameLoading = true;
    try {
      const updated = await api.renamePasskey(target.id, name);
      passkeys = passkeys.map((item) => item.id === updated.id ? updated : item);
      renameOpen = false;
      renameTarget = null;
      notice = 'Passkey 名称已更新。';
    } catch (cause) {
      renameError = cause instanceof Error ? cause.message : '无法重命名 Passkey';
    } finally {
      renameLoading = false;
    }
  }

  async function confirmDelete() {
    const target = deleteTarget;
    if (!target) return;
    await runProtectedAction({ kind: 'delete', id: target.id }, true);
  }

  async function retryProtectedAction() {
    const action = pendingAction;
    if (!action) return;
    try {
      await runProtectedAction(action, false);
    } catch {
      // The card exposes the actionable error.
    }
  }

  function persistPendingAction() {
    if (pendingAction) sessionStorage.setItem(pendingActionStorageKey, JSON.stringify(pendingAction));
  }

  function formatDate(value?: string | null): string {
    if (!value) return '从未使用';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN');
  }
</script>

<section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
  <div class="flex flex-col justify-between gap-4 border-b border-nya-divider px-7 py-5 sm:flex-row sm:items-center">
    <div class="flex items-start gap-3">
      <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-primary-soft text-nya-primary"><Fingerprint size={20} /></span>
      <div>
        <h2 class="text-card-title text-nya-text-primary">Passkey</h2>
        <p class="mt-1 text-body text-nya-text-secondary">使用设备解锁、指纹、面容或安全密钥登录，并可作为多因素验证。</p>
      </div>
    </div>
    {#if status}<Badge variant={passkeys.length > 0 ? 'success' : status.passkeys_available ? 'warning' : 'default'}>{passkeys.length > 0 ? `${passkeys.length} 枚` : status.passkeys_available ? '未注册' : '不可注册'}</Badge>{/if}
  </div>

  <div class="space-y-4 px-7 py-6">
    {#if loading}
      <p class="text-body text-nya-text-tertiary" role="status">正在加载 Passkey…</p>
    {:else if loadError}
      <div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2">
        <p class="text-small text-nya-danger" role="alert">{loadError}</p>
        <Button variant="ghost" size="sm" onclick={loadPasskeys}>重试</Button>
      </div>
    {:else}
      {#if actionError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{actionError}</p>{/if}
      {#if notice}<p class="rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">{notice}</p>{/if}

      {#if passkeys.some((item) => item.clone_warning)}
        <div class="flex gap-3 rounded-nya-sm bg-nya-danger-soft px-4 py-3 text-small text-nya-danger" role="alert">
          <ShieldAlert size={18} class="mt-0.5 shrink-0" />
          <p>服务器检测到至少一枚 Passkey 的签名计数异常，可能存在凭据复制。请确认设备安全，并删除不认识的凭据。</p>
        </div>
      {/if}

      {#if passkeys.length === 0}
        <div class="rounded-nya-sm bg-nya-surface-muted p-4">
          <p class="text-body-medium font-semibold text-nya-text-primary">尚未注册 Passkey</p>
          <p class="mt-1 text-small text-nya-text-secondary">注册后可无密码登录，也可在需要 MFA 或近期重新认证时使用。</p>
        </div>
      {:else}
        <div class="space-y-3">
          {#each passkeys as passkey (passkey.id)}
            <article class="rounded-nya-sm border border-nya-border bg-nya-surface-muted p-4">
              <div class="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
                <div class="min-w-0">
                  <div class="flex flex-wrap items-center gap-2">
                    <p class="truncate text-body-medium font-semibold text-nya-text-primary">{passkey.name}</p>
                    {#if passkey.clone_warning}<Badge variant="danger">计数异常</Badge>{/if}
                    {#if passkey.backup_eligible}<Badge variant={passkey.backup_state ? 'success' : 'default'}>{passkey.backup_state ? '已同步备份' : '可备份'}</Badge>{:else}<Badge variant="default">设备绑定</Badge>{/if}
                  </div>
                  <p class="mt-1 text-small text-nya-text-secondary">{passkey.attachment === 'cross-platform' ? '外部安全密钥' : passkey.attachment === 'platform' ? '当前设备凭据' : 'Passkey 凭据'} · 创建于 {formatDate(passkey.created_at)}</p>
                  <p class="mt-1 text-micro text-nya-text-tertiary">最近使用：{formatDate(passkey.last_used_at)}{passkey.transports.length > 0 ? ` · ${passkey.transports.join(' / ')}` : ''}</p>
                </div>
                <div class="flex shrink-0 gap-2">
                  <Button variant="ghost" size="sm" requiredCapability="account_mutations" ariaLabel={`重命名 ${passkey.name}`} disabled={actionLoading} onclick={() => openRename(passkey)}><Pencil size={14} /> 重命名</Button>
                  <Button variant="ghost" size="sm" requiredCapability="account_mutations" ariaLabel={`删除 ${passkey.name}`} disabled={actionLoading} onclick={() => openDelete(passkey)}><Trash2 size={14} /> 删除</Button>
                </div>
              </div>
            </article>
          {/each}
        </div>
      {/if}

      <div class="flex flex-wrap items-center justify-between gap-3">
        <p class="text-small text-nya-text-tertiary">注册和删除要求最近 10 分钟内完成身份验证。</p>
        <Button variant="primary" requiredCapability="account_mutations" disabled={!status?.passkeys_available || actionLoading} onclick={openRegistration}><Plus size={16} /> 注册 Passkey</Button>
      </div>
      {#if status && !status.passkeys_available}<p class="text-small text-nya-warning">管理员当前已关闭新的 Passkey 注册；已有凭据仍可正常使用。</p>{/if}
    {/if}
  </div>
</section>

<Modal bind:open={registrationOpen} title="注册 Passkey" description="名称只用于帮助你识别设备，不会发送给认证器" size="sm" dismissible={!actionLoading}>
  <form onsubmit={submitRegistration} class="space-y-4">
    {#if registrationError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{registrationError}</p>{/if}
    <Input id="passkey-name" label="Passkey 名称" bind:value={registrationName} required maxlength={64} autocomplete="off" placeholder="例如：Windows Hello" />
    <div class="flex justify-end gap-2">
      <Button variant="secondary" disabled={actionLoading} onclick={() => (registrationOpen = false)}>取消</Button>
      <Button type="submit" variant="primary" requiredCapability="account_mutations" loading={actionLoading}><Fingerprint size={16} /> 继续注册</Button>
    </div>
  </form>
</Modal>

<Modal bind:open={renameOpen} title="重命名 Passkey" size="sm">
  <form onsubmit={submitRename} class="space-y-4">
    {#if renameError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{renameError}</p>{/if}
    <Input id="passkey-rename" label="Passkey 名称" bind:value={renameName} required maxlength={64} autocomplete="off" />
    <div class="flex justify-end gap-2">
      <Button variant="secondary" disabled={renameLoading} onclick={() => (renameOpen = false)}>取消</Button>
      <Button type="submit" variant="primary" requiredCapability="account_mutations" loading={renameLoading}>保存名称</Button>
    </div>
  </form>
</Modal>

<ConfirmDialog
  bind:open={deleteOpen}
  title="删除 Passkey"
  description={`删除“${deleteTarget?.name || ''}”后，它将不能再用于登录或验证。若这是最后一种登录方式，服务器会拒绝操作。`}
  confirmLabel="确认删除"
  confirmationText={deleteTarget?.name || ''}
  error={deleteError}
  onconfirm={confirmDelete}
/>

<ReauthenticationDialog
  bind:open={reauthOpen}
  {returnTo}
  description="注册或删除 Passkey 前，需要验证最近 10 分钟内的身份"
  onauthenticated={retryProtectedAction}
  onbeforeprovider={persistPendingAction}
/>
