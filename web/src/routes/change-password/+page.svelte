<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { api } from '$lib/api';
  import { safeReturnPath, sessionStore } from '$lib/stores';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import { KeyRound } from 'lucide-svelte';

  let currentPassword = $state('');
  let newPassword = $state('');
  let confirmation = $state('');
  let error = $state('');
  let loading = $state(false);
  let ready = $state(false);
  let returnTo = $derived(safeReturnPath($page.url.searchParams.get('return_to'), '/dashboard'));

  onMount(async () => {
    const session = await sessionStore.initialize();
    if (!session) goto(`/login?return_to=${encodeURIComponent('/change-password')}`);
    else ready = true;
  });

  async function submit(event: Event) {
    event.preventDefault();
    error = '';
    if (newPassword.length < 12) {
      error = '新密码至少需要 12 个字符';
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

{#if ready}
  <div class="min-h-screen flex items-center justify-center px-4 bg-[var(--nya-bg)]">
    <div class="w-full max-w-[420px] bg-[var(--nya-surface)] border border-[var(--nya-border)] p-8" style="border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card);">
      <div class="flex items-center gap-3 mb-2">
        <KeyRound size={22} style="color: var(--nya-primary);" />
        <h1 style="font-size: 20px; font-weight: 700;">修改密码</h1>
      </div>
      <p class="mb-6" style="font-size: 13px; color: var(--nya-text-secondary);">更新密码后，其他已登录设备和现有令牌会立即失效。</p>
      {#if error}
        <div class="mb-4 px-4 py-3 rounded-lg" style="background: var(--nya-danger-soft); color: var(--nya-danger); font-size: 13px;">{error}</div>
      {/if}
      <form onsubmit={submit} class="space-y-4">
        <Input label="当前密码" type="password" bind:value={currentPassword} required autocomplete="current-password" />
        <Input label="新密码" type="password" bind:value={newPassword} required autocomplete="new-password" />
        <Input label="确认新密码" type="password" bind:value={confirmation} required autocomplete="new-password" />
        <Button type="submit" variant="primary" size="lg" {loading}>确认修改</Button>
      </form>
    </div>
  </div>
{/if}
