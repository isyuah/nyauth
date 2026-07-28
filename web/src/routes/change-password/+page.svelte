<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { api } from '$lib/api';
  import { PASSWORD_REQUIREMENT, passwordPolicyError } from '$lib/password-policy';
  import { safeReturnPath, sessionStore } from '$lib/stores';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import { ArrowLeft, KeyRound } from 'lucide-svelte';

  let currentPassword = $state('');
  let newPassword = $state('');
  let confirmation = $state('');
  let error = $state('');
  let loading = $state(false);
  let ready = $state(false);
  let sessionError = $state('');
  let canReturn = $state(false);
  let roleHome = $state('/dashboard');
  let returnTo = $derived(safeReturnPath($page.url.searchParams.get('return_to'), '/dashboard'));
  let backTarget = $derived(returnTo === '/change-password' ? roleHome : returnTo);
  let backLabel = $derived(backTarget === '/profile' ? '返回个人资料' : backTarget.startsWith('/admin') ? '返回管理后台' : '返回用户中心');

  async function initialize() {
    sessionError = '';
    try {
      const session = await sessionStore.initialize(true);
      if (!session) {
        const path = `/change-password?return_to=${encodeURIComponent(returnTo)}`;
        await goto(`/login?return_to=${encodeURIComponent(path)}`);
      } else if (!session.has_password) {
        await goto('/profile');
      } else {
        roleHome = session.user.role === 'admin' ? '/admin' : '/dashboard';
        canReturn = !session.must_change_password;
        ready = true;
      }
    } catch (cause) {
      sessionError = cause instanceof Error ? cause.message : '无法验证当前会话';
    }
  }

  onMount(initialize);

  async function submit(event: Event) {
    event.preventDefault();
    error = '';
    const policyError = passwordPolicyError(newPassword);
    if (policyError) {
      error = policyError;
      return;
    }
    if (newPassword !== confirmation) {
      error = '两次输入的新密码不一致';
      return;
    }
    loading = true;
    try {
      const session = await api.changePassword(currentPassword, newPassword);
      sessionStore.setSession(session);
      const destination = returnTo === '/change-password'
        ? (session.user.role === 'admin' ? '/admin' : '/dashboard')
        : returnTo;
      goto(destination);
    } catch (err) {
      error = err instanceof Error ? err.message : '密码修改失败';
    } finally {
      loading = false;
    }
  }
</script>

<svelte:head><title>修改密码 - Nya</title></svelte:head>

{#if sessionError}
  <div class="min-h-screen bg-nya-bg p-6"><div class="mx-auto max-w-xl pt-24"><ResourceState loading={false} error={sessionError} onretry={initialize}>{#snippet children()}{/snippet}</ResourceState></div></div>
{:else if ready}
  <div class="min-h-screen flex items-center justify-center px-4 bg-[var(--nya-bg)]">
    <div class="w-full max-w-[420px] bg-[var(--nya-surface)] border border-[var(--nya-border)] p-8" style="border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card);">
      {#if canReturn}
        <div class="mb-5"><Button variant="ghost" size="sm" onclick={() => goto(backTarget)}><ArrowLeft size={15} /> {backLabel}</Button></div>
      {/if}
      <div class="flex items-center gap-3 mb-2">
        <KeyRound size={22} style="color: var(--nya-primary);" />
        <h1 style="font-size: 20px; font-weight: 700;">修改密码</h1>
      </div>
      <p class="mb-6" style="font-size: 13px; color: var(--nya-text-secondary);">更新密码后，其他已登录设备和现有令牌会立即失效。</p>
      {#if error}
        <div class="mb-4 px-4 py-3 rounded-lg" style="background: var(--nya-danger-soft); color: var(--nya-danger); font-size: 13px;" role="alert" aria-live="assertive">{error}</div>
      {/if}
      <form onsubmit={submit} class="space-y-4">
        <Input id="current-password" label="当前密码" type="password" bind:value={currentPassword} required autocomplete="current-password" />
        <div><Input id="new-password" label="新密码" type="password" bind:value={newPassword} required autocomplete="new-password" /><p class="mt-1.5 text-small text-nya-text-tertiary">{PASSWORD_REQUIREMENT}</p></div>
        <Input id="confirm-password" label="确认新密码" type="password" bind:value={confirmation} required autocomplete="new-password" />
        <Button type="submit" variant="primary" size="lg" requiredCapability="account_mutations" {loading} fullWidth>确认修改</Button>
      </form>
    </div>
  </div>
{/if}
