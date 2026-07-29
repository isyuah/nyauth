<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { api, isRecentAuthenticationError, type ExternalIdentity, type SessionInfo } from '$lib/api';
  import { consumeProviderAuthError, sessionStore } from '$lib/stores';
  import { PASSWORD_REQUIREMENT, passwordPolicyError } from '$lib/password-policy';
  import PasskeySettingsCard from '$lib/components/account/PasskeySettingsCard.svelte';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import TOTPSettingsCard from '$lib/components/account/TOTPSettingsCard.svelte';
  import ProviderIcon from '$lib/components/identity/ProviderIcon.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import { KeyRound } from 'lucide-svelte';

  const returnTo = '/profile/security';
  const initialProviderAuthError = consumeProviderAuthError();
  let session = $derived($sessionStore.session);
  let identities = $state<ExternalIdentity[]>([]);
  let identitiesLoading = $state(true);
  let identitiesError = $state('');
  let actionError = $state('');
  let notice = $state(initialProviderAuthError?.message ?? '');
  let reauthOpen = $state(false);
  let reauthProvider = $state('');
  let setPasswordOpen = $state(false);
  let setPasswordValue = $state('');
  let setPasswordConfirmation = $state('');
  let setPasswordLoading = $state(false);
  let setPasswordError = $state('');
  let authenticationClock = $state(Date.now());
  let mfaFactorsRevision = $state(0);

  let hasPassword = $derived(session?.has_password ?? false);
  let recentAuthenticationValid = $derived(hasRecentAuthentication(session?.recent_authentication_expires_at, authenticationClock));

  function hasRecentAuthentication(expiresAt: string | undefined, now: number): boolean {
    if (!expiresAt) return false;
    const expiry = Date.parse(expiresAt);
    return Number.isFinite(expiry) && now <= expiry;
  }

  function applySession(next: SessionInfo) {
    authenticationClock = Date.now();
    sessionStore.setSession(next);
  }

  function applyPasskeySession(next: SessionInfo) {
    applySession(next);
    mfaFactorsRevision += 1;
  }

  async function loadIdentities() {
    identitiesLoading = true;
    identitiesError = '';
    try {
      identities = await api.getMyIdentities();
    } catch (cause) {
      identitiesError = cause instanceof Error ? cause.message : '外部身份加载失败';
    } finally {
      identitiesLoading = false;
    }
  }

  onMount(() => {
    const timer = window.setInterval(() => (authenticationClock = Date.now()), 30_000);
    void loadIdentities();
    return () => window.clearInterval(timer);
  });

  function handleReauthenticated(next: SessionInfo) {
    applySession(next);
    actionError = '';
    notice = '身份验证已刷新，敏感操作可在当前近期认证有效期内完成。';
  }

  async function beginProviderReauthentication(provider: string) {
    reauthProvider = provider;
    actionError = '';
    try {
      const result = await api.reauthenticateWithProvider(provider, returnTo);
      window.location.assign(result.redirect_url);
    } catch (cause) {
      actionError = cause instanceof Error ? cause.message : '无法发起外部身份重新认证';
      reauthProvider = '';
    }
  }

  function openSetPassword() {
    setPasswordValue = '';
    setPasswordConfirmation = '';
    setPasswordError = '';
    setPasswordOpen = true;
  }

  async function handleSetPassword(event: SubmitEvent) {
    event.preventDefault();
    authenticationClock = Date.now();
    if (!hasRecentAuthentication(session?.recent_authentication_expires_at, authenticationClock)) {
      setPasswordError = '请先通过已绑定的外部身份完成重新认证。';
      return;
    }
    setPasswordError = '';
    const policyError = passwordPolicyError(setPasswordValue);
    if (policyError) {
      setPasswordError = policyError;
      return;
    }
    if (setPasswordValue !== setPasswordConfirmation) {
      setPasswordError = '两次输入的新密码不一致。';
      return;
    }
    setPasswordLoading = true;
    try {
      const next = await api.setPassword(setPasswordValue);
      applySession(next);
      setPasswordValue = '';
      setPasswordConfirmation = '';
      setPasswordOpen = false;
      notice = '本地密码已设置，当前会话已安全轮换。';
    } catch (cause) {
      if (isRecentAuthenticationError(cause)) authenticationClock = Date.now();
      setPasswordError = cause instanceof Error ? cause.message : '无法设置本地密码';
    } finally {
      setPasswordLoading = false;
    }
  }
</script>

<svelte:head><title>账户安全 - Nya</title></svelte:head>

{#if notice}<div class="mb-4 rounded-nya-sm bg-nya-warning-soft px-4 py-3 text-small text-nya-warning" role="status">{notice}</div>{/if}
{#if actionError}<div class="mb-4 rounded-nya-sm bg-nya-danger-soft px-4 py-3 text-small text-nya-danger" role="alert">{actionError}</div>{/if}

<div class="space-y-5">
  <section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
    <div class="flex flex-col justify-between gap-4 px-7 py-5 sm:flex-row sm:items-center">
      <div>
        <h2 class="text-card-title text-nya-text-primary">密码安全</h2>
        {#if hasPassword}<p class="mt-1 text-body text-nya-text-secondary">修改密码会退出其他设备并撤销已有令牌。</p>{:else}<p class="mt-1 text-body text-nya-text-secondary">此账户当前仅通过外部身份登录，可以额外设置本地密码。</p>{/if}
      </div>
      {#if hasPassword}
        <Button variant="secondary" requiredCapability="account_mutations" onclick={() => goto(`/change-password?return_to=${encodeURIComponent(returnTo)}`)}><KeyRound size={16} /> 修改密码</Button>
      {:else}
        <Button variant="secondary" requiredCapability="account_mutations" onclick={openSetPassword}><KeyRound size={16} /> 设置本地密码</Button>
      {/if}
    </div>
  </section>

  {#key mfaFactorsRevision}
    <TOTPSettingsCard
      {returnTo}
      onsessionupdated={applySession}
      providerReauthenticationFailed={initialProviderAuthError !== null}
    />
  {/key}

  <PasskeySettingsCard
    {returnTo}
    onsessionupdated={applyPasskeySession}
    providerReauthenticationFailed={initialProviderAuthError !== null}
  />

  <section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
    <div class="flex flex-col justify-between gap-4 border-b border-nya-divider px-7 py-5 sm:flex-row sm:items-center">
      <div>
        <h2 class="text-card-title text-nya-text-primary">近期重新认证</h2>
        <p class="mt-1 text-body text-nya-text-secondary">邮箱变更、设置密码和身份解绑要求在当前近期认证有效期内完成。</p>
      </div>
      <Badge variant={recentAuthenticationValid ? 'success' : 'warning'}>{recentAuthenticationValid ? '认证有效' : '需要重新认证'}</Badge>
    </div>
    <div class="flex flex-wrap gap-3 px-7 py-5">
      <Button variant="secondary" onclick={() => (reauthOpen = true)}><KeyRound size={15} /> 选择认证方式</Button>
      {#if identitiesLoading}
        <p class="text-body text-nya-text-tertiary" role="status">正在加载外部认证方式…</p>
      {:else if identitiesError}
        <div class="flex items-center gap-2"><p class="text-body text-nya-warning">{identitiesError}</p><Button variant="ghost" size="sm" onclick={loadIdentities}>重试</Button></div>
      {:else}
        {#each identities as identity}
          <Button variant="secondary" loading={reauthProvider === identity.provider} onclick={() => beginProviderReauthentication(identity.provider)}><ProviderIcon type={identity.provider_type} iconKey={identity.provider_icon_key} size={16} /> 使用 {identity.provider_display_name || identity.provider}</Button>
        {/each}
      {/if}
    </div>
  </section>
</div>

<ReauthenticationDialog
  bind:open={reauthOpen}
  {returnTo}
  description="成功后，敏感账户操作可在当前近期认证有效期内完成"
  onauthenticated={handleReauthenticated}
/>

<Modal bind:open={setPasswordOpen} title="设置本地密码" description="设置后可以同时使用用户名密码和外部身份登录" size="sm">
  {#if recentAuthenticationValid}
    <form onsubmit={handleSetPassword} class="space-y-4">
      {#if setPasswordError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{setPasswordError}</p>{/if}
      <div><Input id="set-local-password" label="新密码" type="password" bind:value={setPasswordValue} autocomplete="new-password" required /><p class="mt-1.5 text-small text-nya-text-tertiary">{PASSWORD_REQUIREMENT}</p></div>
      <Input id="set-local-password-confirmation" label="确认新密码" type="password" bind:value={setPasswordConfirmation} autocomplete="new-password" required />
      <div class="flex justify-end gap-2"><Button variant="secondary" onclick={() => (setPasswordOpen = false)} disabled={setPasswordLoading}>取消</Button><Button type="submit" variant="primary" requiredCapability="account_mutations" loading={setPasswordLoading}>设置密码</Button></div>
    </form>
  {:else}
    <div class="space-y-4">
      <p class="rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning">设置密码前，请先通过已绑定的外部身份完成重新认证。</p>
      {#if identitiesLoading}
        <p class="text-small text-nya-text-tertiary">正在加载外部身份…</p>
      {:else if identitiesError}
        <p class="text-small text-nya-danger">{identitiesError}</p>
      {:else}
        <div class="flex flex-wrap gap-2">{#each identities as identity}<Button variant="secondary" loading={reauthProvider === identity.provider} onclick={() => beginProviderReauthentication(identity.provider)}><ProviderIcon type={identity.provider_type} iconKey={identity.provider_icon_key} size={16} /> 使用 {identity.provider_display_name || identity.provider} 重新认证</Button>{/each}</div>
        {#if identities.length === 0}<p class="text-small text-nya-danger">没有可用于重新认证的外部身份，请联系管理员。</p>{/if}
      {/if}
    </div>
  {/if}
</Modal>
