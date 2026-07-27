<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { api, ApiError, type MFAMethod, type MFAPurpose, type MFARequiredResponse, type SessionInfo } from '$lib/api';
  import { brandingStore, safeReturnPath, sessionStore } from '$lib/stores';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import {
    WEBAUTHN_ERROR_CODES,
    authenticationCredentialToJSON,
    classifyWebAuthnError,
    getCredential,
  } from '$lib/webauthn';
  import { Fingerprint, KeyRound, ShieldCheck } from 'lucide-svelte';

  let challenge = $state<MFARequiredResponse | null>(null);
  let selectedMethod = $state<MFAMethod>('totp');
  let code = $state('');
  let loading = $state(true);
  let submitting = $state(false);
  let cancelling = $state(false);
  let error = $state('');
  let challengeExpired = $state(false);
  let now = $state(Date.now());
  let passkeyController: AbortController | null = null;
  let passkeyGeneration = 0;

  let returnTo = $derived(safeReturnPath($page.url.searchParams.get('return_to'), '/dashboard'));
  let requestedPurpose: MFAPurpose = $derived($page.url.searchParams.get('purpose') === 'reauthentication' ? 'reauthentication' : 'login');
  let activePurpose = $derived(challenge?.purpose ?? requestedPurpose);
  let expiryTime = $derived(challenge ? Date.parse(challenge.expires_at) : Number.NaN);
  let remainingSeconds = $derived(Number.isFinite(expiryTime) ? Math.max(0, Math.ceil((expiryTime - now) / 1000)) : 0);

  $effect(() => {
    if (challenge && !challenge.methods.includes(selectedMethod)) {
      selectedMethod = challenge.methods[0] ?? 'totp';
      code = '';
    }
  });

  onMount(() => {
    const timer = window.setInterval(() => (now = Date.now()), 1_000);
    void restoreChallenge();
    return () => {
      window.clearInterval(timer);
      passkeyGeneration += 1;
      passkeyController?.abort();
    };
  });

  async function restoreChallenge() {
    loading = true;
    error = '';
    challengeExpired = false;
    try {
      challenge = await api.getLoginMFA();
      now = Date.now();
    } catch (cause) {
      challenge = null;
      challengeExpired = cause instanceof ApiError && cause.status === 401;
      error = cause instanceof Error ? cause.message : '无法恢复多因素验证状态';
    } finally {
      loading = false;
    }
  }

  function selectMethod(method: MFAMethod) {
    if (submitting || cancelling) return;
    passkeyGeneration += 1;
    passkeyController?.abort();
    passkeyController = null;
    selectedMethod = method;
    code = '';
    error = '';
  }

  async function finishMFA(session: SessionInfo, purpose: MFAPurpose) {
    sessionStore.setSession(session);
    if (purpose === 'reauthentication') {
      await goto(returnTo);
      return;
    }
    if (session.must_change_password) {
      await goto(`/change-password?return_to=${encodeURIComponent(returnTo)}`);
    } else if (returnTo.startsWith('/authorize')) {
      window.location.href = returnTo;
    } else {
      await goto(returnTo);
    }
  }

  async function verify(event: SubmitEvent) {
    event.preventDefault();
    if (submitting || cancelling) return;
    const pending = challenge;
    if (!pending) return;
    if (selectedMethod === 'passkey') {
      await verifyPasskey();
      return;
    }
    const submittedCode = code.trim();
    error = '';
    if (!submittedCode) {
      error = selectedMethod === 'totp' ? '请输入 6 位动态验证码。' : '请输入一枚恢复码。';
      return;
    }
    if (selectedMethod === 'totp' && !/^\d{6}$/.test(submittedCode)) {
      error = '动态验证码应为 6 位数字。';
      return;
    }

    const generation = ++passkeyGeneration;
    submitting = true;
    try {
      const purpose = pending.purpose;
      const session = await api.verifyLoginMFA(selectedMethod, submittedCode, pending.csrf_token);
      if (generation !== passkeyGeneration) return;
      code = '';
      await finishMFA(session, purpose);
    } catch (cause) {
      if (generation !== passkeyGeneration) return;
      if (cause instanceof ApiError && cause.status === 429 && cause.retryAfter) {
        error = `验证尝试过于频繁，请在 ${cause.retryAfter} 秒后重试。`;
      } else {
        error = cause instanceof Error ? cause.message : '验证失败';
      }
      if (cause instanceof ApiError && cause.serverMessage.trim().toLowerCase() === 'mfa challenge expired') {
        challengeExpired = true;
        challenge = null;
      }
    } finally {
      if (generation === passkeyGeneration) submitting = false;
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

  async function verifyPasskey() {
    const pending = challenge;
    if (!pending || !pending.methods.includes('passkey')) return;
    passkeyController?.abort();
    const controller = new AbortController();
    const generation = ++passkeyGeneration;
    passkeyController = controller;
    error = '';
    submitting = true;
    try {
      const options = await api.beginMFAPasskey(pending.csrf_token, controller.signal);
      if (controller.signal.aborted || generation !== passkeyGeneration) return;
      const credential = await getCredential(options.public_key, {
        mediation: options.mediation ?? 'required',
        signal: controller.signal,
      });
      if (controller.signal.aborted || generation !== passkeyGeneration) return;
      const session = await api.finishMFAPasskey(
        options.ceremony_id,
        authenticationCredentialToJSON(credential),
        pending.csrf_token,
        controller.signal,
      );
      if (controller.signal.aborted || generation !== passkeyGeneration) return;
      passkeyController = null;
      await finishMFA(session, pending.purpose);
    } catch (cause) {
      if (classifyWebAuthnError(cause) !== WEBAUTHN_ERROR_CODES.aborted) {
        if (cause instanceof ApiError && cause.status === 429 && cause.retryAfter) {
          error = `验证尝试过于频繁，请在 ${cause.retryAfter} 秒后重试。`;
        } else {
          error = passkeyErrorMessage(cause);
        }
      }
      if (cause instanceof ApiError && cause.serverMessage.trim().toLowerCase() === 'mfa challenge expired') {
        challengeExpired = true;
        challenge = null;
      }
    } finally {
      if (passkeyController === controller) passkeyController = null;
      if (generation === passkeyGeneration) submitting = false;
    }
  }

  async function cancelChallenge() {
    const pending = challenge;
    if (!pending) return;
    cancelling = true;
    passkeyGeneration += 1;
    passkeyController?.abort();
    passkeyController = null;
    error = '';
    try {
      await api.cancelLoginMFA(pending.csrf_token);
      if (activePurpose === 'reauthentication') await goto(returnTo);
      else await goto(`/login?return_to=${encodeURIComponent(returnTo)}`);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '无法取消本次验证';
    } finally {
      cancelling = false;
    }
  }
</script>

<svelte:head><title>{activePurpose === 'reauthentication' ? '重新验证身份' : '多因素验证'} - Nya</title></svelte:head>

<main class="flex min-h-screen items-center justify-center px-4" style="background: var(--nya-gradient-soft)">
  <div class="w-full max-w-[430px]">
    <div class="mb-7 text-center">
      <img src={$brandingStore.logo_url || '/logo.png'} alt="" class="mx-auto mb-3 h-14 w-14 select-none" draggable="false" />
      <h1 class="text-2xl font-bold text-nya-text-primary">{activePurpose === 'reauthentication' ? '完成重新认证' : '完成多因素验证'}</h1>
      <p class="mt-2 text-body text-nya-text-secondary">{activePurpose === 'reauthentication' ? '验证第二项凭据后返回刚才的敏感操作。' : '验证第二项凭据后才会创建完整登录会话。'}</p>
    </div>

    <div class="rounded-nya-lg border border-nya-border bg-nya-surface p-7 shadow-nya-sm">
      {#if loading}
        <p class="py-8 text-center text-body text-nya-text-tertiary" role="status">正在恢复验证状态…</p>
      {:else if !challenge}
        <div class="space-y-4 text-center">
          <span class="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-nya-warning-soft text-nya-warning"><KeyRound size={22} /></span>
          <div>
            <h2 class="text-card-title text-nya-text-primary">{challengeExpired ? '验证已过期' : '无法继续验证'}</h2>
            {#if error}<p class="mt-2 text-small text-nya-danger" role="alert">{error}</p>{/if}
          </div>
          <div class="flex justify-center gap-2">
            <Button variant="secondary" onclick={restoreChallenge}>重试恢复</Button>
            <Button variant="primary" onclick={() => activePurpose === 'reauthentication' ? goto(returnTo) : goto(`/login?return_to=${encodeURIComponent(returnTo)}`)}>{activePurpose === 'reauthentication' ? '返回原页面' : '重新登录'}</Button>
          </div>
        </div>
      {:else}
        <div class="mb-5 flex items-start gap-3 rounded-nya-sm bg-nya-primary-soft px-4 py-3">
          <ShieldCheck size={19} class="mt-0.5 shrink-0 text-nya-primary" />
          <div>
            <p class="text-body-medium font-semibold text-nya-text-primary">{challenge.purpose === 'reauthentication' ? '正在重新验证' : '正在验证'} @{challenge.username}</p>
            <p class="mt-1 text-small text-nya-text-secondary">
              {remainingSeconds > 0 ? `本次验证将在 ${Math.ceil(remainingSeconds / 60)} 分钟内过期` : '本次验证已到期，请重新登录'}
            </p>
          </div>
        </div>

        {#if challenge.methods.length > 1}
          <div class="mb-4 grid gap-2 sm:grid-cols-3" aria-label="选择验证方式">
            {#each challenge.methods as method}
              <button
                type="button"
                aria-pressed={selectedMethod === method}
                disabled={submitting || cancelling}
                onclick={() => selectMethod(method)}
                class="rounded-nya-sm border px-3 py-2 text-small font-semibold transition-colors {selectedMethod === method ? 'border-nya-primary bg-nya-primary-soft text-nya-primary' : 'border-nya-border text-nya-text-secondary hover:bg-nya-surface-hover'}"
              >{method === 'totp' ? '动态验证码' : method === 'recovery_code' ? '恢复码' : 'Passkey'}</button>
            {/each}
          </div>
        {/if}

        <form onsubmit={verify} class="space-y-4">
          {#if error}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{error}</p>{/if}
          {#if selectedMethod === 'passkey'}
            <div class="rounded-nya-sm bg-nya-surface-muted px-4 py-4 text-center">
              <Fingerprint size={26} class="mx-auto text-nya-primary" />
              <p class="mt-2 text-body-medium font-semibold text-nya-text-primary">使用已注册的 Passkey</p>
              <p class="mt-1 text-small text-nya-text-secondary">系统会调用设备解锁、指纹、面容或安全密钥完成验证。</p>
            </div>
          {:else if selectedMethod === 'totp'}
            <Input
              id="mfa-totp-code"
              label="6 位动态验证码"
              bind:value={code}
              inputmode="numeric"
              autocomplete="one-time-code"
              disabled={submitting || cancelling}
              maxlength={6}
              required
              placeholder="123456"
            />
            <p class="text-small text-nya-text-tertiary">打开身份验证器，输入当前显示的 6 位数字。</p>
          {:else}
            <Input
              id="mfa-recovery-code"
              label="恢复码"
              bind:value={code}
              autocomplete="one-time-code"
              disabled={submitting || cancelling}
              required
              placeholder="XXXXXXXX-XXXXXXXXXXXXXXXX"
              mono
            />
            <p class="text-small text-nya-text-tertiary">每枚恢复码只能使用一次，使用后请从安全中心查看剩余数量。</p>
          {/if}
          <Button type="submit" variant="primary" size="lg" loading={submitting} disabled={remainingSeconds <= 0 || cancelling} fullWidth>
            {#if selectedMethod === 'passkey'}<Fingerprint size={17} />{/if}
            {selectedMethod === 'passkey' ? '使用 Passkey 验证' : challenge.purpose === 'reauthentication' ? '验证并返回' : '验证并登录'}
          </Button>
        </form>

        <div class="mt-4 flex justify-center">
          <Button variant="ghost" loading={cancelling} disabled={submitting} onclick={cancelChallenge}>{challenge.purpose === 'reauthentication' ? '取消并返回原页面' : '取消并返回登录'}</Button>
        </div>
      {/if}
    </div>
  </div>
</main>
