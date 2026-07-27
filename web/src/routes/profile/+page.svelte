<script lang="ts">
  import { onMount } from 'svelte';
  import { api, isRecentAuthenticationError, type SessionInfo, type User } from '$lib/api';
  import { consumeProviderAuthError, sessionStore } from '$lib/stores';
  import AvatarCropper from '$lib/components/account/AvatarCropper.svelte';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import { Calendar, CheckCircle, Mail, Save, Send, Shield } from 'lucide-svelte';

  const initialProviderAuthError = consumeProviderAuthError();

  let session = $derived($sessionStore.session);
  let me = $state<User | null>(null);
  let displayName = $state('');
  let newEmail = $state('');
  let saving = $state(false);
  let saved = $state(false);
  let loading = $state(true);
  let loadError = $state('');
  let actionError = $state('');
  let notice = $state(initialProviderAuthError?.message ?? '');
  let verificationLoading = $state(false);
  let verificationSent = $state(false);
  let emailChangeLoading = $state(false);
  let emailChangeSent = $state(false);
  let reauthOpen = $state(false);

  let emailVerified = $derived(session?.email_verified ?? false);

  function hasRecentAuthentication(value?: string): boolean {
    if (!value) return false;
    const authenticatedAt = Date.parse(value);
    if (!Number.isFinite(authenticatedAt)) return false;
    const age = Date.now() - authenticatedAt;
    return age >= -60_000 && age <= 10 * 60_000;
  }

  function promptForReauthentication(message = '此操作需要最近 10 分钟内重新验证身份。') {
    actionError = message;
    reauthOpen = true;
  }

  function requireRecentAuthentication(): boolean {
    if (hasRecentAuthentication(session?.authenticated_at)) return true;
    promptForReauthentication();
    return false;
  }

  async function loadProfile() {
    loading = true;
    loadError = '';
    try {
      const user = await api.getMe();
      me = user;
      displayName = user.display_name || '';
    } catch (cause) {
      loadError = cause instanceof Error ? cause.message : '个人资料加载失败';
    } finally {
      loading = false;
    }
  }

  onMount(loadProfile);

  async function handleSave() {
    const currentSession = session;
    if (!currentSession) return;
    saving = true;
    actionError = '';
    saved = false;
    try {
      const updated = await api.updateMe({ display_name: displayName || null });
      me = updated;
      sessionStore.setSession({ ...currentSession, user: updated });
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
    if (session) sessionStore.setSession({ ...session, user: updated });
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
      if (isRecentAuthenticationError(cause)) promptForReauthentication();
      else actionError = cause instanceof Error ? cause.message : '无法发起邮箱变更';
    } finally {
      emailChangeLoading = false;
    }
  }

  function handleProfileReauthenticated(next: SessionInfo) {
    sessionStore.setSession(next);
    me = next.user;
    actionError = '';
    notice = '身份验证已刷新，敏感操作将在 10 分钟内可用。';
  }
</script>

<svelte:head><title>个人资料 - Nya</title></svelte:head>

{#if notice}<div class="mb-4 rounded-nya-sm bg-nya-warning-soft px-4 py-3 text-small text-nya-warning" role="status">{notice}</div>{/if}
{#if actionError}<div class="mb-4 rounded-nya-sm bg-nya-danger-soft px-4 py-3 text-small text-nya-danger" role="alert">{actionError}</div>{/if}

<ResourceState {loading} error={loadError} empty={!me} emptyTitle="无法显示个人资料" onretry={loadProfile}>
  {#snippet children()}
    {#if me}
      <div class="space-y-5">
        <section class="overflow-hidden rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
          <div class="h-20 bg-gradient-to-br from-[#f1edff] via-[#fff0f6] to-[#edf8ff]"></div>
          <div class="px-7 pb-6">
            <div class="-mt-9 flex items-end gap-5">
              <div class="flex h-[88px] w-[88px] shrink-0 items-center justify-center overflow-hidden rounded-full border-4 border-nya-surface bg-nya-primary-soft text-[32px] font-bold text-nya-primary">
                {#if me.avatar_url}<img src={me.avatar_url} alt="用户头像" class="h-full w-full object-cover" />{:else}{me.username.slice(0, 1).toUpperCase()}{/if}
              </div>
              <div class="min-w-0 flex-1 pb-1">
                <h2 class="truncate text-xl font-bold text-nya-text-primary">{me.display_name || me.username}</h2>
                <p class="text-body text-nya-text-secondary">@{me.username}</p>
              </div>
              <Badge variant={me.role === 'admin' ? 'pink' : 'primary'}>{me.role === 'admin' ? '管理员' : '用户'}</Badge>
            </div>
            <div class="mt-4 flex flex-wrap gap-4 text-small text-nya-text-tertiary">
              <span class="flex items-center gap-1"><Mail size={13} /> {me.email || '未设置邮箱'}</span>
              <span class="flex items-center gap-1"><Calendar size={13} /> 注册于 {new Date(me.created_at).toLocaleDateString()}</span>
              {#if me.last_login_at}<span class="flex items-center gap-1"><Shield size={13} /> 最后登录 {new Date(me.last_login_at).toLocaleString()}</span>{/if}
            </div>
          </div>
        </section>

        <section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
          <div class="border-b border-nya-divider px-7 py-5"><h2 class="text-card-title text-nya-text-primary">编辑资料</h2></div>
          <div class="space-y-5 px-7 py-6">
            {#if saved}<div class="flex items-center gap-2 rounded-nya-sm bg-nya-success-soft px-4 py-3 text-small text-nya-success" role="status"><CheckCircle size={16} /> 保存成功</div>{/if}
            <Input id="profile-display-name" label="显示名称" bind:value={displayName} placeholder="给自己取个名字" />
            <div><p class="mb-2 text-body-medium text-nya-text-primary">头像</p><AvatarCropper currentUrl={me.avatar_url} onupload={uploadAvatar} onremove={removeAvatar} /></div>
            <div class="flex justify-end"><Button variant="primary" onclick={handleSave} loading={saving}><Save size={16} /> 保存更改</Button></div>
          </div>
        </section>

        <section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
          <div class="border-b border-nya-divider px-7 py-5">
            <h2 class="text-card-title text-nya-text-primary">邮箱与账户恢复</h2>
            <p class="mt-1 text-body text-nya-text-secondary">邮箱只有在邮件链接中确认后才会变更。</p>
          </div>
          <div class="space-y-5 px-7 py-6">
            <div class="flex flex-col justify-between gap-3 rounded-nya-sm bg-nya-surface-muted p-4 sm:flex-row sm:items-center">
              <div>
                <p class="text-body-medium font-semibold text-nya-text-primary">{me.email || '尚未设置邮箱'}</p>
                <p class="mt-1 text-small text-nya-text-tertiary">{emailVerified ? '已验证，可用于密码找回' : '未验证，暂不能用于密码找回'}</p>
              </div>
              <div class="flex items-center gap-2">
                <Badge variant={emailVerified ? 'success' : 'warning'}>{emailVerified ? '已验证' : '未验证'}</Badge>
                {#if me.email && !emailVerified}<Button variant="secondary" size="sm" onclick={requestEmailVerification} loading={verificationLoading}><Send size={14} /> {verificationSent ? '已发送' : '发送验证邮件'}</Button>{/if}
              </div>
            </div>
            {#if verificationSent}<p class="rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">如果邮件服务可用，验证邮件会很快送达。</p>{/if}
            <form onsubmit={requestEmailChange} class="space-y-3">
              <Input id="new-email" label={me.email ? '更换邮箱' : '设置邮箱'} type="email" bind:value={newEmail} autocomplete="email" required placeholder="new@example.com" />
              <p class="text-small text-nya-text-tertiary">此操作要求近期登录。确认新邮箱后，现有会话和令牌会失效。</p>
              {#if emailChangeSent}<p class="rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">确认邮件已提交发送，请前往新邮箱完成操作。</p>{/if}
              <div class="flex justify-end"><Button type="submit" variant="secondary" loading={emailChangeLoading}><Mail size={15} /> 发送确认邮件</Button></div>
            </form>
          </div>
        </section>
      </div>
    {/if}
  {/snippet}
</ResourceState>

<ReauthenticationDialog
  bind:open={reauthOpen}
  returnTo="/profile"
  description="修改邮箱前需要验证最近 10 分钟内的身份"
  onauthenticated={handleProfileReauthenticated}
/>
