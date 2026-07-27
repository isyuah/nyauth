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
  import { ExternalLink, KeyRound } from 'lucide-svelte';

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
  let loadedForOpen = $state(false);
  let error = $state('');
  let mfaChallenge = $state<MFARequiredResponse | null>(null);
  let mfaMethod = $state<MFAMethod>('totp');
  let mfaCode = $state('');
  let mfaError = $state('');
  let mfaLoading = $state(false);
  let mfaGeneration = 0;

  let hasPassword = $derived($sessionStore.session?.has_password ?? false);
  let providers = $derived(Array.from(new Set(identities.map((identity) => identity.provider))));
  let mfaExpiryLabel = $derived(mfaChallenge ? formatExpiry(mfaChallenge.expires_at) : '');

  $effect(() => {
    if (open && !loadedForOpen) {
      loadedForOpen = true;
      password = '';
      error = '';
      void loadIdentities();
    }
    if (!open) {
      loadedForOpen = false;
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

  async function loadIdentities() {
    identitiesLoading = true;
    try {
      identities = await api.getMyIdentities();
    } catch (cause) {
      identities = [];
      error = cause instanceof Error ? cause.message : '重新认证方式加载失败';
    } finally {
      identitiesLoading = false;
    }
  }

  async function submitPassword(event: SubmitEvent) {
    event.preventDefault();
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
      error = cause instanceof Error ? cause.message : '重新认证失败';
    } finally {
      passwordLoading = false;
    }
  }

  function selectMFAMethod(method: MFAMethod) {
    mfaMethod = method;
    mfaCode = '';
    mfaError = '';
  }

  async function submitMFA(event: SubmitEvent) {
    event.preventDefault();
    const pending = mfaChallenge;
    if (!pending) return;
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

    mfaLoading = true;
    try {
      const updated = await api.verifyLoginMFA(mfaMethod, code, pending.csrf_token);
      resetMFAState();
      sessionStore.setSession(updated);
      open = false;
      await onauthenticated(updated);
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 429 && cause.retryAfter) {
        mfaError = `验证尝试过于频繁，请在 ${cause.retryAfter} 秒后重试。`;
      } else {
        mfaError = cause instanceof Error ? cause.message : '多因素验证失败';
      }
    } finally {
      mfaLoading = false;
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
    error = '';
    providerLoading = provider;
    try {
      const result = await api.reauthenticateWithProvider(provider, returnTo);
      onbeforeprovider?.();
      window.location.assign(result.redirect_url);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '无法发起外部身份重新认证';
      providerLoading = '';
    }
  }
</script>

<Modal bind:open title="重新验证身份" {description} size="sm">
  <div class="space-y-4">
    {#if mfaChallenge}
      <div class="rounded-nya-sm bg-nya-primary-soft px-3 py-2">
        <p class="text-small font-semibold text-nya-text-primary">密码已通过，请完成第二项验证</p>
        <p class="mt-1 text-micro text-nya-text-secondary">正在验证 @{mfaChallenge.username}，本次挑战约于 {mfaExpiryLabel} 过期。</p>
      </div>
      {#if mfaChallenge.methods.length > 1}
        <div class="grid grid-cols-2 gap-2" aria-label="选择验证方式">
          <button type="button" aria-pressed={mfaMethod === 'totp'} onclick={() => selectMFAMethod('totp')} class="rounded-nya-sm border px-3 py-2 text-small font-semibold {mfaMethod === 'totp' ? 'border-nya-primary bg-nya-primary-soft text-nya-primary' : 'border-nya-border text-nya-text-secondary'}">动态验证码</button>
          <button type="button" aria-pressed={mfaMethod === 'recovery_code'} onclick={() => selectMFAMethod('recovery_code')} class="rounded-nya-sm border px-3 py-2 text-small font-semibold {mfaMethod === 'recovery_code' ? 'border-nya-primary bg-nya-primary-soft text-nya-primary' : 'border-nya-border text-nya-text-secondary'}">恢复码</button>
        </div>
      {/if}
      <form onsubmit={submitMFA} class="space-y-3">
        {#if mfaError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{mfaError}</p>{/if}
        <Input
          id="sensitive-action-mfa-code"
          label={mfaMethod === 'totp' ? '6 位动态验证码' : '恢复码'}
          bind:value={mfaCode}
          inputmode={mfaMethod === 'totp' ? 'numeric' : 'text'}
          autocomplete="one-time-code"
          maxlength={mfaMethod === 'totp' ? 6 : undefined}
          mono={mfaMethod === 'recovery_code'}
          required
          placeholder={mfaMethod === 'totp' ? '123456' : 'XXXXXXXX-XXXXXXXXXXXXXXXX'}
        />
        <Button type="submit" variant="primary" loading={mfaLoading} fullWidth><KeyRound size={16} /> 完成重新认证</Button>
      </form>
      <div class="flex items-center justify-between gap-2">
        <Button variant="ghost" size="sm" onclick={restoreMFAChallenge} disabled={mfaLoading}>刷新验证状态</Button>
        <Button variant="ghost" onclick={cancelMFAChallenge} disabled={mfaLoading}>取消</Button>
      </div>
    {:else}
      {#if error}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{error}</p>{/if}
      {#if hasPassword}
        <form onsubmit={submitPassword} class="space-y-3">
          <Input id="sensitive-action-password" label="当前密码" type="password" bind:value={password} autocomplete="current-password" required />
          <Button type="submit" variant="primary" loading={passwordLoading} fullWidth><KeyRound size={16} /> 使用密码验证</Button>
        </form>
      {/if}
      {#if identitiesLoading}
        <p class="text-center text-small text-nya-text-tertiary" role="status">正在加载外部认证方式…</p>
      {:else if providers.length > 0}
        <div class="space-y-2">
          {#each providers as provider}
            <Button variant="secondary" loading={providerLoading === provider} disabled={passwordLoading || (providerLoading !== '' && providerLoading !== provider)} fullWidth onclick={() => beginProvider(provider)}>
              <ExternalLink size={16} /> 使用 {provider} 验证
            </Button>
          {/each}
        </div>
      {:else if !hasPassword && !error}
        <p class="rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning">当前账户没有可用的重新认证方式，请联系管理员。</p>
      {/if}
      <div class="flex justify-end"><Button variant="ghost" onclick={() => (open = false)} disabled={passwordLoading || providerLoading !== ''}>取消</Button></div>
    {/if}
  </div>
</Modal>
