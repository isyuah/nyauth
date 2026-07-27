<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import {
    api,
    isRecentAuthenticationError,
    type BrowserSession,
    type ExternalIdentity,
    type OAuthAuthorization,
    type ProviderSummary,
    type SessionInfo,
    type User,
  } from '$lib/api';
  import { consumeProviderAuthError, sessionStore } from '$lib/stores';
  import { PASSWORD_REQUIREMENT, passwordPolicyError } from '$lib/password-policy';
  import AppShell from '$lib/components/layout/AppShell.svelte';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import AvatarCropper from '$lib/components/account/AvatarCropper.svelte';
  import PasskeySettingsCard from '$lib/components/account/PasskeySettingsCard.svelte';
  import TOTPSettingsCard from '$lib/components/account/TOTPSettingsCard.svelte';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import { AppWindow, Calendar, CheckCircle, KeyRound, Link2, LogOut, Mail, MonitorSmartphone, Save, Send, Shield } from 'lucide-svelte';

  type SessionAction = { kind: 'single'; session: BrowserSession } | { kind: 'others' } | null;

  const initialProviderAuthError = consumeProviderAuthError();

  let session = $state<SessionInfo | null>(null);
  let me = $state<User | null>(null);
  let identities = $state<ExternalIdentity[]>([]);
  let availableProviders = $state<ProviderSummary[]>([]);
  let browserSessions = $state<BrowserSession[]>([]);
  let authorizations = $state<OAuthAuthorization[]>([]);
  let displayName = $state('');
  let newEmail = $state('');
  let saving = $state(false);
  let saved = $state(false);
  let loadError = $state('');
  let actionError = $state('');
  let notice = $state(initialProviderAuthError?.message ?? '');
  let loading = $state(true);
  let identitiesLoading = $state(false);
  let identitiesError = $state('');
  let providersLoading = $state(false);
  let providersError = $state('');
  let sessionsLoading = $state(false);
  let sessionsError = $state('');
  let authorizationsLoading = $state(false);
  let authorizationsError = $state('');
  let authorizationTarget = $state<OAuthAuthorization | null>(null);
  let authorizationConfirmOpen = $state(false);
  let authorizationActionError = $state('');
  let reauthOpen = $state(false);
  let reauthProvider = $state('');
  let setPasswordOpen = $state(false);
  let setPasswordValue = $state('');
  let setPasswordConfirmation = $state('');
  let setPasswordLoading = $state(false);
  let setPasswordError = $state('');
  let identityTarget = $state<ExternalIdentity | null>(null);
  let identityConfirmOpen = $state(false);
  let identityActionError = $state('');
  let bindingProvider = $state('');
  let verificationLoading = $state(false);
  let verificationSent = $state(false);
  let emailChangeLoading = $state(false);
  let emailChangeSent = $state(false);
  let sessionAction = $state<SessionAction>(null);
  let sessionConfirmOpen = $state(false);
  let sessionActionError = $state('');
  let authenticationClock = $state(Date.now());
  let mfaFactorsRevision = $state(0);

  let hasPassword = $derived(session?.has_password ?? false);
  let emailVerified = $derived(session?.email_verified ?? false);
  let otherSessionCount = $derived(browserSessions.filter((item) => !item.current).length);
  let recentAuthenticationValid = $derived(hasRecentAuthentication(session?.authenticated_at, authenticationClock));

  const providerIcons: Record<string, string> = { github: '🐙', google: '🔵', generic: '🔗' };

  function hasRecentAuthentication(value: string | undefined, now: number): boolean {
    if (!value) return false;
    const authenticatedAt = Date.parse(value);
    if (!Number.isFinite(authenticatedAt)) return false;
    const age = now - authenticatedAt;
    return age >= -60_000 && age <= 10 * 60_000;
  }

  function applySession(next: SessionInfo) {
    authenticationClock = Date.now();
    session = next;
    me = next.user;
    sessionStore.setSession(next);
  }

  function applyPasskeySession(next: SessionInfo) {
    applySession(next);
    mfaFactorsRevision += 1;
  }

  function promptForReauthentication(message = '此操作需要最近 10 分钟内重新验证身份。') {
    actionError = message;
    reauthOpen = true;
  }

  function requireRecentAuthentication(): boolean {
    authenticationClock = Date.now();
    if (hasRecentAuthentication(session?.authenticated_at, authenticationClock)) return true;
    promptForReauthentication();
    return false;
  }

  function deviceLabel(userAgent = ''): string {
    const browser = /Edg\//.test(userAgent) ? 'Edge' : /Firefox\//.test(userAgent) ? 'Firefox' : /Chrome\//.test(userAgent) ? 'Chrome' : /Safari\//.test(userAgent) ? 'Safari' : '未知浏览器';
    const system = /Windows/.test(userAgent) ? 'Windows' : /Android/.test(userAgent) ? 'Android' : /iPhone|iPad/.test(userAgent) ? 'iOS' : /Mac OS/.test(userAgent) ? 'macOS' : /Linux/.test(userAgent) ? 'Linux' : '未知系统';
    return `${browser} · ${system}`;
  }

  async function loadSessions() {
    sessionsLoading = true;
    sessionsError = '';
    try {
      browserSessions = await api.getMySessions();
    } catch (cause) {
      sessionsError = cause instanceof Error ? cause.message : '设备会话加载失败';
    } finally {
      sessionsLoading = false;
    }
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

  async function loadProviders() {
    providersLoading = true;
    providersError = '';
    try {
      availableProviders = await api.getProviders();
    } catch (cause) {
      providersError = cause instanceof Error ? cause.message : '身份提供商加载失败';
    } finally {
      providersLoading = false;
    }
  }

  async function loadAuthorizations() {
    authorizationsLoading = true;
    authorizationsError = '';
    try {
      authorizations = await api.getMyAuthorizations();
    } catch (cause) {
      authorizationsError = cause instanceof Error ? cause.message : 'OAuth 授权加载失败';
    } finally {
      authorizationsLoading = false;
    }
  }

  async function loadProfile() {
    loading = true;
    loadError = '';
    actionError = '';
    try {
      session = await sessionStore.initialize(true);
      if (!session) {
        await goto(`/login?return_to=${encodeURIComponent('/profile')}`);
        return;
      }
      if (session.must_change_password) {
        await goto(`/change-password?return_to=${encodeURIComponent('/profile')}`);
        return;
      }

      const user = await api.getMe();
      me = user;
      displayName = user.display_name || '';
      void loadIdentities();
      void loadProviders();
      void loadSessions();
      void loadAuthorizations();
    } catch (cause) {
      loadError = cause instanceof Error ? cause.message : '个人资料加载失败';
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    const timer = window.setInterval(() => (authenticationClock = Date.now()), 30_000);
    void loadProfile();
    return () => window.clearInterval(timer);
  });

  async function handleSave() {
    if (!session) return;
    saving = true;
    actionError = '';
    saved = false;
    try {
      me = await api.updateMe({
        display_name: displayName || null,
      });
      session = { ...session, user: me };
      sessionStore.setSession(session);
      saved = true;
      setTimeout(() => (saved = false), 3000);
    } catch (cause) {
      actionError = cause instanceof Error ? cause.message : '保存失败';
    } finally {
      saving = false;
    }
  }

  function applyAvatarUser(updated: User) {
    me = updated;
    if (session) {
      session = { ...session, user: updated };
      sessionStore.setSession(session);
    }
  }

  async function uploadAvatar(blob: Blob) {
    applyAvatarUser(await api.uploadAvatar(blob));
  }

  async function removeAvatar() {
    applyAvatarUser(await api.removeAvatar());
  }

  async function requestEmailVerification() {
    verificationLoading = true;
    actionError = '';
    try {
      await api.account.requestEmailVerification();
      verificationSent = true;
    } catch (cause) {
      actionError = cause instanceof Error ? cause.message : '无法发送验证邮件';
    } finally {
      verificationLoading = false;
    }
  }

  async function requestEmailChange(event: SubmitEvent) {
    event.preventDefault();
    if (!requireRecentAuthentication()) return;
    emailChangeLoading = true;
    emailChangeSent = false;
    actionError = '';
    try {
      await api.account.requestEmailChange(newEmail);
      emailChangeSent = true;
      newEmail = '';
    } catch (cause) {
      if (isRecentAuthenticationError(cause)) {
        authenticationClock = Date.now();
        promptForReauthentication();
      } else {
        actionError = cause instanceof Error ? cause.message : '无法发起邮箱变更';
      }
    } finally {
      emailChangeLoading = false;
    }
  }

  async function bindProvider(name: string) {
    bindingProvider = name;
    actionError = '';
    try {
      const result = await api.bindIdentity(name, '/profile');
      window.location.assign(result.redirect_url);
    } catch (cause) {
      actionError = cause instanceof Error ? cause.message : '无法发起身份绑定';
      bindingProvider = '';
    }
  }

  function handleProfileReauthenticated(next: SessionInfo) {
    applySession(next);
    actionError = '';
    notice = '身份验证已刷新，敏感操作将在 10 分钟内可用。';
  }

  async function beginProviderReauthentication(provider: string) {
    reauthProvider = provider;
    actionError = '';
    try {
      const result = await api.reauthenticateWithProvider(provider, '/profile');
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
    if (!hasRecentAuthentication(session?.authenticated_at, authenticationClock)) {
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

  function requestIdentityRemoval(identity: ExternalIdentity) {
    if (!requireRecentAuthentication()) return;
    identityTarget = identity;
    identityActionError = '';
    identityConfirmOpen = true;
  }

  async function removeIdentity() {
    const target = identityTarget;
    if (!target) return;
    identityActionError = '';
    try {
      const next = await api.deleteMyIdentity(target.id);
      applySession(next);
      identities = identities.filter((identity) => identity.id !== target.id);
      notice = `已解绑 ${target.provider} 身份，当前会话已安全轮换。`;
    } catch (cause) {
      if (isRecentAuthenticationError(cause)) {
        authenticationClock = Date.now();
        identityConfirmOpen = false;
        promptForReauthentication();
        return;
      }
      identityActionError = cause instanceof Error ? cause.message : '无法解绑外部身份';
      throw cause;
    }
  }

  function requestSessionAction(action: SessionAction) {
    sessionAction = action;
    sessionActionError = '';
    sessionConfirmOpen = true;
  }

  async function runSessionAction() {
    const action = sessionAction;
    if (!action) return;
    sessionActionError = '';
    try {
      if (action.kind === 'others') {
        await api.revokeOtherSessions();
        browserSessions = browserSessions.filter((item) => item.current);
        return;
      }
      await api.revokeMySession(action.session.id);
      if (action.session.current) {
        sessionStore.clear();
        await goto('/login');
      } else {
        browserSessions = browserSessions.filter((item) => item.id !== action.session.id);
      }
    } catch (cause) {
      sessionActionError = cause instanceof Error ? cause.message : '无法撤销会话';
      throw cause;
    }
  }

  function requestAuthorizationRevocation(authorization: OAuthAuthorization) {
    authorizationTarget = authorization;
    authorizationActionError = '';
    authorizationConfirmOpen = true;
  }

  async function revokeAuthorization() {
    const target = authorizationTarget;
    if (!target) return;
    authorizationActionError = '';
    try {
      await api.revokeMyAuthorization(target.client_id);
      authorizations = authorizations.filter((item) => item.client_id !== target.client_id);
    } catch (cause) {
      authorizationActionError = cause instanceof Error ? cause.message : '无法撤销 OAuth 授权';
      throw cause;
    }
  }
</script>

<svelte:head><title>个人资料 - Nya</title></svelte:head>

{#if loading || !session}
  <div class="min-h-screen bg-nya-bg p-6"><div class="mx-auto max-w-2xl pt-20"><ResourceState {loading} error={loadError} onretry={loadProfile}>{#snippet children()}{/snippet}</ResourceState></div></div>
{:else}
  <AppShell section="user">
    <div class="mx-auto max-w-4xl">
      <PageHeader title="个人资料" description="管理账户资料、安全设置、设备会话和外部身份" />

      {#if notice}<div class="mb-4 rounded-nya-sm bg-nya-warning-soft px-4 py-3 text-small text-nya-warning" role="status">{notice}</div>{/if}
      {#if actionError}<div class="mb-4 rounded-nya-sm bg-nya-danger-soft px-4 py-3 text-small text-nya-danger" role="alert">{actionError}</div>{/if}

      <ResourceState loading={false} error={loadError} empty={!me} emptyTitle="无法显示个人资料" onretry={loadProfile}>
        {#snippet children()}
          {#if me}
            <div class="space-y-5">
              <section class="overflow-hidden rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
                <div class="h-20 bg-gradient-to-br from-[#f1edff] via-[#fff0f6] to-[#edf8ff]"></div>
                <div class="px-7 pb-6"><div class="-mt-9 flex items-end gap-5"><div class="flex h-[88px] w-[88px] shrink-0 items-center justify-center overflow-hidden rounded-full border-4 border-nya-surface bg-nya-primary-soft text-[32px] font-bold text-nya-primary">{#if me.avatar_url}<img src={me.avatar_url} alt="用户头像" class="h-full w-full object-cover" />{:else}{me.username.slice(0, 1).toUpperCase()}{/if}</div><div class="min-w-0 flex-1 pb-1"><h2 class="truncate text-xl font-bold text-nya-text-primary">{me.display_name || me.username}</h2><p class="text-body text-nya-text-secondary">@{me.username}</p></div><Badge variant={me.role === 'admin' ? 'pink' : 'primary'}>{me.role === 'admin' ? '管理员' : '用户'}</Badge></div><div class="mt-4 flex flex-wrap gap-4 text-small text-nya-text-tertiary"><span class="flex items-center gap-1"><Mail size={13} /> {me.email || '未设置邮箱'}</span><span class="flex items-center gap-1"><Calendar size={13} /> 注册于 {new Date(me.created_at).toLocaleDateString()}</span>{#if me.last_login_at}<span class="flex items-center gap-1"><Shield size={13} /> 最后登录 {new Date(me.last_login_at).toLocaleString()}</span>{/if}</div></div>
              </section>

              <section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
                <div class="border-b border-nya-divider px-7 py-5"><h2 class="text-card-title text-nya-text-primary">编辑资料</h2></div>
                <div class="space-y-5 px-7 py-6">{#if saved}<div class="flex items-center gap-2 rounded-nya-sm bg-nya-success-soft px-4 py-3 text-small text-nya-success" role="status"><CheckCircle size={16} /> 保存成功</div>{/if}<Input id="profile-display-name" label="显示名称" bind:value={displayName} placeholder="给自己取个名字" /><div><p class="mb-2 text-body-medium text-nya-text-primary">头像</p><AvatarCropper currentUrl={me.avatar_url} onupload={uploadAvatar} onremove={removeAvatar} /></div><div class="flex justify-end"><Button variant="primary" onclick={handleSave} loading={saving}><Save size={16} /> 保存更改</Button></div></div>
              </section>

              <section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
                <div class="border-b border-nya-divider px-7 py-5"><h2 class="text-card-title text-nya-text-primary">邮箱与账户恢复</h2><p class="mt-1 text-body text-nya-text-secondary">邮箱只有在邮件链接中确认后才会变更。</p></div>
                <div class="space-y-5 px-7 py-6">
                  <div class="flex flex-col justify-between gap-3 rounded-nya-sm bg-nya-surface-muted p-4 sm:flex-row sm:items-center"><div><p class="text-body-medium font-semibold text-nya-text-primary">{me.email || '尚未设置邮箱'}</p><p class="mt-1 text-small text-nya-text-tertiary">{emailVerified ? '已验证，可用于密码找回' : '未验证，暂不能用于密码找回'}</p></div><div class="flex items-center gap-2"><Badge variant={emailVerified ? 'success' : 'warning'}>{emailVerified ? '已验证' : '未验证'}</Badge>{#if me.email && !emailVerified}<Button variant="secondary" size="sm" onclick={requestEmailVerification} loading={verificationLoading}><Send size={14} /> {verificationSent ? '已发送' : '发送验证邮件'}</Button>{/if}</div></div>
                  {#if verificationSent}<p class="rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">如果邮件服务可用，验证邮件会很快送达。</p>{/if}
                  <form onsubmit={requestEmailChange} class="space-y-3"><Input id="new-email" label={me.email ? '更换邮箱' : '设置邮箱'} type="email" bind:value={newEmail} autocomplete="email" required placeholder="new@example.com" /><p class="text-small text-nya-text-tertiary">此操作要求近期登录。确认新邮箱后，现有会话和令牌会失效。</p>{#if emailChangeSent}<p class="rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">确认邮件已提交发送，请前往新邮箱完成操作。</p>{/if}<div class="flex justify-end"><Button type="submit" variant="secondary" loading={emailChangeLoading}><Mail size={15} /> 发送确认邮件</Button></div></form>
                </div>
              </section>

              <section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
                <div class="flex flex-col justify-between gap-4 px-7 py-5 sm:flex-row sm:items-center"><div><h2 class="text-card-title text-nya-text-primary">密码安全</h2>{#if hasPassword}<p class="mt-1 text-body text-nya-text-secondary">修改密码会退出其他设备并撤销已有令牌。</p>{:else}<p class="mt-1 text-body text-nya-text-secondary">此账户当前仅通过外部身份登录，可以额外设置本地密码。</p>{/if}</div>{#if hasPassword}<Button variant="secondary" onclick={() => goto('/change-password?return_to=/profile')}><KeyRound size={16} /> 修改密码</Button>{:else}<Button variant="secondary" onclick={openSetPassword}><KeyRound size={16} /> 设置本地密码</Button>{/if}</div>
              </section>

              {#key mfaFactorsRevision}
                <TOTPSettingsCard
                  onsessionupdated={applySession}
                  providerReauthenticationFailed={initialProviderAuthError !== null}
                />
              {/key}

              <PasskeySettingsCard
                onsessionupdated={applyPasskeySession}
                providerReauthenticationFailed={initialProviderAuthError !== null}
              />

              <section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
                <div class="flex flex-col justify-between gap-4 border-b border-nya-divider px-7 py-5 sm:flex-row sm:items-center"><div><h2 class="text-card-title text-nya-text-primary">近期重新认证</h2><p class="mt-1 text-body text-nya-text-secondary">邮箱变更、设置密码和身份解绑要求最近 10 分钟内重新验证身份。</p></div><Badge variant={recentAuthenticationValid ? 'success' : 'warning'}>{recentAuthenticationValid ? '认证有效' : '需要重新认证'}</Badge></div>
                <div class="flex flex-wrap gap-3 px-7 py-5"><Button variant="secondary" onclick={() => (reauthOpen = true)}><KeyRound size={15} /> 选择认证方式</Button>{#if identitiesLoading}<p class="text-body text-nya-text-tertiary" role="status">正在加载外部认证方式…</p>{:else if identitiesError}<p class="text-body text-nya-warning">外部身份暂时不可用，请在下方重试。</p>{:else}{#each identities as identity}<Button variant="secondary" loading={reauthProvider === identity.provider} onclick={() => beginProviderReauthentication(identity.provider)}><span>{providerIcons[identity.provider] || '🔗'}</span> 使用 {identity.provider}</Button>{/each}{/if}</div>
              </section>

              <section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
                <div class="flex items-center justify-between gap-4 border-b border-nya-divider px-7 py-5"><div><h2 class="text-card-title text-nya-text-primary">设备会话</h2><p class="mt-1 text-body text-nya-text-secondary">查看已登录设备，并立即撤销不认识的会话。</p></div>{#if otherSessionCount > 0}<Button variant="secondary" size="sm" onclick={() => requestSessionAction({ kind: 'others' })}><LogOut size={14} /> 退出其他设备</Button>{/if}</div>
                <div class="px-7 py-6">
                  {#if sessionsLoading}<p class="text-body text-nya-text-tertiary">正在加载设备会话…</p>
                  {:else if sessionsError}<div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2"><p class="text-small text-nya-danger">{sessionsError}</p><Button variant="ghost" size="sm" onclick={loadSessions}>重试</Button></div>
                  {:else if browserSessions.length === 0}<p class="text-body text-nya-text-tertiary">暂无可显示的设备会话。</p>
                  {:else}<div class="divide-y divide-nya-divider">{#each browserSessions as item}<div class="flex flex-col justify-between gap-3 py-4 sm:flex-row sm:items-center"><div class="flex min-w-0 items-start gap-3"><span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-primary-soft"><MonitorSmartphone size={19} class="text-nya-primary" /></span><div class="min-w-0"><p class="text-body-medium font-semibold text-nya-text-primary">{deviceLabel(item.user_agent)} {#if item.current}<Badge variant="success">当前设备</Badge>{/if}</p><p class="mt-1 text-small text-nya-text-tertiary">IP {item.ip_address || '未知'} · 最后活动 {new Date(item.last_seen_at).toLocaleString()}</p><p class="mt-0.5 truncate text-micro text-nya-text-tertiary" title={item.user_agent}>{item.user_agent || '未提供 User-Agent'}</p></div></div><Button variant="ghost" size="sm" onclick={() => requestSessionAction({ kind: 'single', session: item })}>{item.current ? '退出此设备' : '撤销会话'}</Button></div>{/each}</div>{/if}
                </div>
              </section>

              <section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
                <div class="border-b border-nya-divider px-7 py-5"><h2 class="text-card-title text-nya-text-primary">OAuth 应用授权</h2><p class="mt-1 text-body text-nya-text-secondary">查看已获准访问账户信息的应用，并立即撤销其 Token 与后续刷新能力。</p></div>
                <div class="px-7 py-6">
                  {#if authorizationsLoading}<p class="text-body text-nya-text-tertiary">正在加载应用授权…</p>
                  {:else if authorizationsError}<div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2"><p class="text-small text-nya-danger">{authorizationsError}</p><Button variant="ghost" size="sm" onclick={loadAuthorizations}>重试</Button></div>
                  {:else if authorizations.length === 0}<p class="text-body text-nya-text-tertiary">当前没有活动的 OAuth 应用授权。</p>
                  {:else}<div class="divide-y divide-nya-divider">{#each authorizations as authorization}<div class="flex flex-col justify-between gap-3 py-4 sm:flex-row sm:items-center"><div class="flex min-w-0 items-start gap-3"><span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-blue-soft"><AppWindow size={19} class="text-nya-blue" /></span><div class="min-w-0"><p class="text-body-medium font-semibold text-nya-text-primary">{authorization.client_name}</p><p class="mt-1 text-small text-nya-text-tertiary">授权于 {new Date(authorization.granted_at).toLocaleString()}{#if authorization.last_used_at} · 最近使用 {new Date(authorization.last_used_at).toLocaleString()}{/if}</p><div class="mt-2 flex flex-wrap gap-1.5">{#each authorization.scopes as scope}<Badge variant={scope === 'offline_access' ? 'warning' : 'default'}>{scope}</Badge>{/each}</div></div></div><Button variant="ghost" size="sm" onclick={() => requestAuthorizationRevocation(authorization)}>撤销授权</Button></div>{/each}</div>{/if}
                </div>
              </section>

              <section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
                <div class="flex items-center justify-between border-b border-nya-divider px-7 py-5"><div class="flex items-center gap-2"><KeyRound size={18} class="text-nya-primary" /><h2 class="text-card-title text-nya-text-primary">外部身份</h2></div><Badge variant="default">{identitiesLoading ? '加载中' : `${identities.length} 个已绑定`}</Badge></div>
                <div class="space-y-5 px-7 py-6">
                  {#if identitiesLoading}
                    <p class="text-body text-nya-text-tertiary" role="status">正在加载外部身份…</p>
                  {:else if identitiesError}
                    <div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2"><p class="text-small text-nya-danger" role="alert">{identitiesError}</p><Button variant="ghost" size="sm" onclick={loadIdentities}>重试</Button></div>
                  {:else}
                    {#if identities.length > 0}<div class="space-y-3">{#each identities as identity}<div class="flex items-center justify-between gap-4 rounded-nya-sm border border-nya-border p-3.5"><div class="flex min-w-0 items-center gap-3"><span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-nya-surface-muted text-lg">{providerIcons[identity.provider] || '🔗'}</span><div class="min-w-0"><p class="text-body-medium font-semibold text-nya-text-primary">{identity.provider}</p><p class="truncate text-small text-nya-text-secondary">{identity.external_username || identity.external_id}</p></div></div><div class="flex items-center gap-2"><Badge variant="success">已绑定</Badge><Button variant="ghost" size="sm" onclick={() => requestIdentityRemoval(identity)}>解绑</Button></div></div>{/each}</div>{:else}<p class="rounded-nya-sm bg-nya-surface-muted px-4 py-5 text-center text-body text-nya-text-tertiary">尚未绑定外部身份</p>{/if}
                  {/if}
                  <div>
                    <p class="mb-2 text-small font-semibold uppercase tracking-wide text-nya-text-secondary">可绑定的提供商</p>
                    {#if providersLoading}
                      <p class="text-body text-nya-text-tertiary" role="status">正在加载身份提供商…</p>
                    {:else if providersError}
                      <div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2"><p class="text-small text-nya-danger" role="alert">{providersError}</p><Button variant="ghost" size="sm" onclick={loadProviders}>重试</Button></div>
                    {:else if availableProviders.length > 0}
                      <div class="flex flex-wrap gap-3">{#each availableProviders as provider}{@const alreadyBound = identities.some((identity) => identity.provider === provider.name)}<Button variant="secondary" disabled={identitiesLoading || !!identitiesError || alreadyBound} loading={bindingProvider === provider.name} onclick={() => bindProvider(provider.name)}><span>{providerIcons[provider.type] || '🔗'}</span>{provider.name}{#if alreadyBound}<CheckCircle size={14} />{:else}<Link2 size={14} />{/if}</Button>{/each}</div>
                    {:else}
                      <p class="text-body text-nya-text-tertiary">当前没有启用的身份提供商。</p>
                    {/if}
                  </div>
                </div>
              </section>
            </div>
          {/if}
        {/snippet}
      </ResourceState>
    </div>
  </AppShell>
{/if}

<ConfirmDialog
  bind:open={sessionConfirmOpen}
  title={sessionAction?.kind === 'others' ? '退出其他设备' : sessionAction?.session.current ? '退出当前设备' : '撤销设备会话'}
  description={sessionAction?.kind === 'others' ? `将撤销其他 ${otherSessionCount} 个设备会话，当前设备保持登录。` : sessionAction?.session.current ? '当前会话会立即结束，你需要重新登录。' : '该设备会立即退出登录。'}
  confirmLabel={sessionAction?.kind === 'others' ? '退出其他设备' : '撤销会话'}
  error={sessionActionError}
  onconfirm={runSessionAction}
/>

<ConfirmDialog
  bind:open={authorizationConfirmOpen}
  title="撤销 OAuth 应用授权"
  description={`撤销后，“${authorizationTarget?.client_name || ''}”现有的访问令牌和刷新令牌将失效；再次使用时需要重新授权。`}
  confirmLabel="撤销授权"
  error={authorizationActionError}
  onconfirm={revokeAuthorization}
/>

<ConfirmDialog
  bind:open={identityConfirmOpen}
  title="解绑外部身份"
  description={`解绑“${identityTarget?.provider || ''}”后，将无法再使用该身份登录。若这是最后一种登录方式，服务器会拒绝操作。`}
  confirmLabel="确认解绑"
  confirmationText={identityTarget?.provider || ''}
  error={identityActionError}
  onconfirm={removeIdentity}
/>

<ReauthenticationDialog
  bind:open={reauthOpen}
  returnTo="/profile"
  description="成功后，敏感账户操作将在 10 分钟内可用"
  onauthenticated={handleProfileReauthenticated}
/>

<Modal bind:open={setPasswordOpen} title="设置本地密码" description="设置后可以同时使用用户名密码和外部身份登录" size="sm">
  {#if recentAuthenticationValid}
    <form onsubmit={handleSetPassword} class="space-y-4">
      {#if setPasswordError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{setPasswordError}</p>{/if}
      <div><Input id="set-local-password" label="新密码" type="password" bind:value={setPasswordValue} autocomplete="new-password" required /><p class="mt-1.5 text-small text-nya-text-tertiary">{PASSWORD_REQUIREMENT}</p></div>
      <Input id="set-local-password-confirmation" label="确认新密码" type="password" bind:value={setPasswordConfirmation} autocomplete="new-password" required />
      <div class="flex justify-end gap-2"><Button variant="secondary" onclick={() => (setPasswordOpen = false)} disabled={setPasswordLoading}>取消</Button><Button type="submit" variant="primary" loading={setPasswordLoading}>设置密码</Button></div>
    </form>
  {:else}
    <div class="space-y-4">
      <p class="rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning">设置密码前，请先通过已绑定的外部身份完成重新认证。</p>
      <div class="flex flex-wrap gap-2">{#each identities as identity}<Button variant="secondary" loading={reauthProvider === identity.provider} onclick={() => beginProviderReauthentication(identity.provider)}><span>{providerIcons[identity.provider] || '🔗'}</span> 使用 {identity.provider} 重新认证</Button>{/each}</div>
      {#if identities.length === 0}<p class="text-small text-nya-danger">没有可用于重新认证的外部身份，请联系管理员。</p>{/if}
    </div>
  {/if}
</Modal>
