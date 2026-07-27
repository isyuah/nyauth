<script lang="ts">
  import {
    api,
    ApiError,
    isMFARequiredResponse,
    type ExternalIdentity,
    type MFAMethod,
    type MFARequiredResponse,
    type SessionInfo,
  } from '$lib/api';
  import { sessionStore } from '$lib/stores';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import {
    WEBAUTHN_ERROR_CODES,
    authenticationCredentialToJSON,
    classifyWebAuthnError,
    getCredential,
  } from '$lib/webauthn';
  import { ExternalLink, Fingerprint, KeyRound } from 'lucide-svelte';

  interface Props {
    open: boolean;
    returnTo: string;
    description?: string;
    onauthenticated: (session: SessionInfo) => void | Promise<void>;
    onbeforeprovider?: () => void;
  }

  let {
    open = $bindable(false),
    returnTo,
    description = '完成后，当前敏感操作将在 10 分钟内可用',
    onauthenticated,
    onbeforeprovider,
  }: Props = $props();

  let password = $state('');
  let passwordLoading = $state(false);
  let providerLoading = $state('');
  let identities = $state<ExternalIdentity[]>([]);
  let identitiesLoading = $state(false);
  let passkeysLoading = $state(false);
  let passkeysError = $state('');
  let passkeysEnrolled = $state(0);
  let passkeyLoading = $state(false);
  let loadedForOpen = $state(false);
  let error = $state('');
  let mfaChallenge = $state<MFARequiredResponse | null>(null);
  let mfaMethod = $state<MFAMethod>('totp');
  let mfaCode = $state('');
  let mfaError = $state('');
  let mfaLoading = $state(false);
  let mfaGeneration = 0;
  let dialogGeneration = 0;
  let passkeyController: AbortController | null = null;

  let hasPassword = $derived($sessionStore.session?.has_password ?? false);
  let providers = $derived(Array.from(new Set(identities.map((identity) => identity.provider))));
  let mfaExpiryLabel = $derived(mfaChallenge ? formatExpiry(mfaChallenge.expires_at) : '');
  let dialogBusy = $derived(passwordLoading || providerLoading !== '' || mfaLoading || passkeyLoading);

  function abortPasskeyOperation() {
    const controller = passkeyController;
    passkeyController = null;
    controller?.abort();
    passkeyLoading = false;
  }

  $effect(() => {
    if (open && !loadedForOpen) {
      loadedForOpen = true;
      const generation = ++dialogGeneration;
      password = '';
      error = '';
      passkeysError = '';
      void loadIdentities(generation);
      void loadPasskeyStatus(generation);
    }
    if (!open) {
      loadedForOpen = false;
      dialogGeneration += 1;
      abortPasskeyOperation();
      passwordLoading = false;
      providerLoading = '';
      identitiesLoading = false;
      passkeysLoading = false;
      passkeysError = '';
      const pendingCsrf = mfaChallenge?.csrf_token;
      resetMFAState();
      if (pendingCsrf) void api.cancelLoginMFA(pendingCsrf).catch(() => {});
    }
  });

  $effect(() => {
    if (mfaChallenge && !mfaChallenge.methods.includes(mfaMethod)) {
      mfaMethod = mfaChallenge.methods[0] ?? 'totp';
      mfaCode = '';
    }
  });

  function formatExpiry(value: string): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
  }

  function setMFAChallenge(challenge: MFARequiredResponse) {
    if (challenge.purpose !== 'reauthentication') {
      throw new Error('服务返回了不匹配的多因素验证用途，请取消后重试。');
    }
    mfaChallenge = challenge;
    mfaMethod = challenge.methods[0] ?? 'totp';
    mfaCode = '';
  }

  function resetMFAState() {
    mfaGeneration += 1;
    abortPasskeyOperation();
    mfaChallenge = null;
    mfaMethod = 'totp';
    mfaCode = '';
    mfaError = '';
    mfaLoading = false;
  }

  async function restoreMFAChallenge() {
    const generation = ++mfaGeneration;
    mfaLoading = true;
    mfaError = '';
    try {
      const restored = await api.getLoginMFA();
      if (generation !== mfaGeneration || !open) return;
      setMFAChallenge(restored);
    } catch (cause) {
      if (generation === mfaGeneration && open) {
        mfaError = cause instanceof Error ? cause.message : '无法恢复多因素验证状态';
      }
    } finally {
      if (generation === mfaGeneration) mfaLoading = false;
    }
  }

  async function loadIdentities(generation: number) {
    identitiesLoading = true;
    try {
      const loaded = await api.getMyIdentities();
      if (!open || generation !== dialogGeneration) return;
      identities = loaded;
    } catch (cause) {
      if (!open || generation !== dialogGeneration) return;
      identities = [];
      error = cause instanceof Error ? cause.message : '重新认证方式加载失败';
    } finally {
      if (open && generation === dialogGeneration) identitiesLoading = false;
    }
  }

  async function loadPasskeyStatus(generation: number) {
    passkeysLoading = true;
    passkeysError = '';
    try {
      const status = await api.getMyMFA();
      if (!open || generation !== dialogGeneration) return;
      passkeysEnrolled = status.passkeys_enrolled;
    } catch (cause) {
      if (!open || generation !== dialogGeneration) return;
      passkeysError = cause instanceof Error ? cause.message : 'Passkey 状态加载失败';
    } finally {
      if (open && generation === dialogGeneration) passkeysLoading = false;
    }
  }

  async function submitPassword(event: SubmitEvent) {
    event.preventDefault();
    if (passwordLoading || providerLoading !== '') return;
    abortPasskeyOperation();
    const generation = ++mfaGeneration;
    error = '';
    passwordLoading = true;
    try {
      const result = await api.reauthenticateWithPassword(password);
      if (generation !== mfaGeneration || !open) return;
      password = '';
      if (isMFARequiredResponse(result)) {
        setMFAChallenge(result);
        return;
      }
      sessionStore.setSession(result);
      open = false;
      await onauthenticated(result);
    } catch (cause) {
      if (generation === mfaGeneration && open) {
        error = cause instanceof Error ? cause.message : '重新认证失败';
      }
    } finally {
      if (generation === mfaGeneration) passwordLoading = false;
    }
  }

  function selectMFAMethod(method: MFAMethod) {
    if (mfaLoading) return;
    mfaGeneration += 1;
    abortPasskeyOperation();
    mfaMethod = method;
    mfaCode = '';
    mfaError = '';
  }

  async function submitMFA(event: SubmitEvent) {
    event.preventDefault();
    if (mfaLoading) return;
    const pending = mfaChallenge;
    if (!pending) return;
    if (mfaMethod === 'passkey') {
      await submitMFAPasskey();
      return;
    }
    const code = mfaCode.trim();
    mfaError = '';
    if (!code) {
      mfaError = mfaMethod === 'totp' ? '请输入 6 位动态验证码。' : '请输入一枚恢复码。';
      return;
    }
    if (mfaMethod === 'totp' && !/^\d{6}$/.test(code)) {
      mfaError = '动态验证码应为 6 位数字。';
      return;
    }

    const generation = ++mfaGeneration;
    mfaLoading = true;
    try {
      const updated = await api.verifyLoginMFA(mfaMethod, code, pending.csrf_token);
      if (generation !== mfaGeneration || !open) return;
      resetMFAState();
      sessionStore.setSession(updated);
      open = false;
      await onauthenticated(updated);
    } catch (cause) {
      if (generation === mfaGeneration && open) {
        if (cause instanceof ApiError && cause.status === 429 && cause.retryAfter) {
          mfaError = `验证尝试过于频繁，请在 ${cause.retryAfter} 秒后重试。`;
        } else {
          mfaError = cause instanceof Error ? cause.message : '多因素验证失败';
        }
      }
    } finally {
      if (generation === mfaGeneration) mfaLoading = false;
    }
  }

  function passkeyErrorMessage(cause: unknown): string {
    switch (classifyWebAuthnError(cause)) {
      case WEBAUTHN_ERROR_CODES.notAllowed:
        return '未完成 Passkey 验证，系统验证窗口可能已关闭。';
      case WEBAUTHN_ERROR_CODES.notSupported:
        return '当前浏览器或设备不支持 Passkey。';
      case WEBAUTHN_ERROR_CODES.security:
        return '当前页面不满足 Passkey 的安全环境要求。';
      default:
        return cause instanceof Error ? cause.message : 'Passkey 验证失败';
    }
  }

  async function submitMFAPasskey() {
    const pending = mfaChallenge;
    if (!pending || !pending.methods.includes('passkey')) return;
    passkeyController?.abort();
    const controller = new AbortController();
    const generation = ++mfaGeneration;
    passkeyController = controller;
    mfaLoading = true;
    mfaError = '';
    try {
      const options = await api.beginMFAPasskey(pending.csrf_token, controller.signal);
      if (!open || controller.signal.aborted || generation !== mfaGeneration) return;
      const credential = await getCredential(options.public_key, {
        mediation: options.mediation ?? 'required',
        signal: controller.signal,
      });
      if (!open || controller.signal.aborted || generation !== mfaGeneration) return;
      const updated = await api.finishMFAPasskey(
        options.ceremony_id,
        authenticationCredentialToJSON(credential),
        pending.csrf_token,
        controller.signal,
      );
      if (!open || controller.signal.aborted || generation !== mfaGeneration) return;
      passkeyController = null;
      resetMFAState();
      sessionStore.setSession(updated);
      open = false;
      await onauthenticated(updated);
    } catch (cause) {
      if (open && generation === mfaGeneration && classifyWebAuthnError(cause) !== WEBAUTHN_ERROR_CODES.aborted) {
        if (cause instanceof ApiError && cause.status === 429 && cause.retryAfter) {
          mfaError = `验证尝试过于频繁，请在 ${cause.retryAfter} 秒后重试。`;
        } else {
          mfaError = passkeyErrorMessage(cause);
        }
      }
    } finally {
      if (passkeyController === controller) passkeyController = null;
      if (generation === mfaGeneration) mfaLoading = false;
    }
  }

  async function submitPasskeyReauthentication() {
    if (passwordLoading || providerLoading !== '' || passkeyLoading) return;
    abortPasskeyOperation();
    const controller = new AbortController();
    const generation = ++mfaGeneration;
    passkeyController = controller;
    passkeyLoading = true;
    error = '';
    try {
      const options = await api.beginPasskeyReauthentication(controller.signal);
      if (!open || controller.signal.aborted || generation !== mfaGeneration) return;
      const credential = await getCredential(options.public_key, {
        mediation: options.mediation ?? 'required',
        signal: controller.signal,
      });
      if (!open || controller.signal.aborted || generation !== mfaGeneration) return;
      const updated = await api.finishPasskeyReauthentication(
        options.ceremony_id,
        authenticationCredentialToJSON(credential),
        controller.signal,
      );
      if (!open || controller.signal.aborted || generation !== mfaGeneration) return;
      passkeyController = null;
      sessionStore.setSession(updated);
      open = false;
      await onauthenticated(updated);
    } catch (cause) {
      if (open && generation === mfaGeneration && classifyWebAuthnError(cause) !== WEBAUTHN_ERROR_CODES.aborted) {
        error = passkeyErrorMessage(cause);
      }
    } finally {
      if (passkeyController === controller) passkeyController = null;
      if (generation === mfaGeneration) passkeyLoading = false;
    }
  }

  async function cancelMFAChallenge() {
    const pending = mfaChallenge;
    if (!pending) return;
    mfaLoading = true;
    mfaError = '';
    try {
      await api.cancelLoginMFA(pending.csrf_token);
      resetMFAState();
      open = false;
    } catch (cause) {
      mfaError = cause instanceof Error ? cause.message : '无法取消多因素验证';
    } finally {
      mfaLoading = false;
    }
  }

  async function beginProvider(provider: string) {
    if (passwordLoading || providerLoading !== '' || passkeyLoading) return;
    abortPasskeyOperation();
    const generation = dialogGeneration;
    error = '';
    providerLoading = provider;
    try {
      const result = await api.reauthenticateWithProvider(provider, returnTo);
      if (!open || generation !== dialogGeneration) return;
      onbeforeprovider?.();
      window.location.assign(result.redirect_url);
    } catch (cause) {
      if (open && generation === dialogGeneration) {
        error = cause instanceof Error ? cause.message : '无法发起外部身份重新认证';
        providerLoading = '';
      }
    }
  }
</script>

<Modal bind:open title="重新验证身份" {description} size="sm" dismissible={!dialogBusy}>
  <div class="space-y-4">
    {#if mfaChallenge}
      <div class="rounded-nya-sm bg-nya-primary-soft px-3 py-2">
        <p class="text-small font-semibold text-nya-text-primary">密码已通过，请完成第二项验证</p>
        <p class="mt-1 text-micro text-nya-text-secondary">正在验证 @{mfaChallenge.username}，本次挑战约于 {mfaExpiryLabel} 过期。</p>
      </div>
      {#if mfaChallenge.methods.length > 1}
        <div class="grid gap-2 sm:grid-cols-3" aria-label="选择验证方式">
          {#each mfaChallenge.methods as method}
            <button type="button" aria-pressed={mfaMethod === method} disabled={mfaLoading} onclick={() => selectMFAMethod(method)} class="rounded-nya-sm border px-3 py-2 text-small font-semibold {mfaMethod === method ? 'border-nya-primary bg-nya-primary-soft text-nya-primary' : 'border-nya-border text-nya-text-secondary'}">{method === 'totp' ? '动态验证码' : method === 'recovery_code' ? '恢复码' : 'Passkey'}</button>
          {/each}
        </div>
      {/if}
      <form onsubmit={submitMFA} class="space-y-3">
        {#if mfaError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{mfaError}</p>{/if}
        {#if mfaMethod === 'passkey'}
          <p class="rounded-nya-sm bg-nya-surface-muted px-3 py-3 text-small text-nya-text-secondary">使用设备解锁、指纹、面容或安全密钥完成第二项验证。</p>
        {:else}
          <Input
            id="sensitive-action-mfa-code"
            label={mfaMethod === 'totp' ? '6 位动态验证码' : '恢复码'}
            bind:value={mfaCode}
            inputmode={mfaMethod === 'totp' ? 'numeric' : 'text'}
            autocomplete="one-time-code"
            disabled={mfaLoading}
            maxlength={mfaMethod === 'totp' ? 6 : undefined}
            mono={mfaMethod === 'recovery_code'}
            required
            placeholder={mfaMethod === 'totp' ? '123456' : 'XXXXXXXX-XXXXXXXXXXXXXXXX'}
          />
        {/if}
        <Button type="submit" variant="primary" loading={mfaLoading} fullWidth>{#if mfaMethod === 'passkey'}<Fingerprint size={16} />{:else}<KeyRound size={16} />{/if} 完成重新认证</Button>
      </form>
      <div class="flex items-center justify-between gap-2">
        <Button variant="ghost" size="sm" onclick={restoreMFAChallenge} disabled={mfaLoading}>刷新验证状态</Button>
        <Button variant="ghost" onclick={cancelMFAChallenge} disabled={mfaLoading}>取消</Button>
      </div>
    {:else}
      {#if error}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{error}</p>{/if}
      {#if hasPassword}
        <form onsubmit={submitPassword} class="space-y-3">
          <Input id="sensitive-action-password" label="当前密码" type="password" bind:value={password} autocomplete="current-password" disabled={passkeyLoading || providerLoading !== ''} required />
          <Button type="submit" variant="primary" loading={passwordLoading} disabled={passkeyLoading || providerLoading !== ''} fullWidth><KeyRound size={16} /> 使用密码验证</Button>
        </form>
      {/if}
      {#if passkeysLoading}
        <p class="text-center text-small text-nya-text-tertiary" role="status">正在检查 Passkey…</p>
      {:else if passkeysError}
        <div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-warning-soft px-3 py-2">
          <p class="text-small text-nya-warning" role="alert">{passkeysError}</p>
          <Button variant="ghost" size="sm" onclick={() => loadPasskeyStatus(dialogGeneration)}>重试</Button>
        </div>
      {:else if passkeysEnrolled > 0}
        <Button variant="secondary" loading={passkeyLoading} disabled={passwordLoading || providerLoading !== ''} fullWidth onclick={submitPasskeyReauthentication}>
          <Fingerprint size={16} /> 使用 Passkey 验证
        </Button>
      {/if}
      {#if identitiesLoading}
        <p class="text-center text-small text-nya-text-tertiary" role="status">正在加载外部认证方式…</p>
      {:else if providers.length > 0}
        <div class="space-y-2">
          {#each providers as provider}
            <Button variant="secondary" loading={providerLoading === provider} disabled={passwordLoading || passkeyLoading || (providerLoading !== '' && providerLoading !== provider)} fullWidth onclick={() => beginProvider(provider)}>
              <ExternalLink size={16} /> 使用 {provider} 验证
            </Button>
          {/each}
        </div>
      {:else if !hasPassword && passkeysEnrolled === 0 && !passkeysLoading && !passkeysError && !error}
        <p class="rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning">当前账户没有可用的重新认证方式，请联系管理员。</p>
      {/if}
      <div class="flex justify-end"><Button variant="ghost" onclick={() => (open = false)} disabled={passwordLoading || passkeyLoading || providerLoading !== ''}>取消</Button></div>
    {/if}
  </div>
</Modal>
