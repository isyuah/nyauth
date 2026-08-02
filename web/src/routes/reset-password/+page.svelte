<script lang="ts">
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { api } from '$lib/api';
	import { brandingStore, sessionStore } from '$lib/stores';
  import AccountActionCard from '$lib/components/account/AccountActionCard.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import { PASSWORD_REQUIREMENT, passwordPolicyError } from '$lib/password-policy';
  import { takeQuerySecret } from '$lib/query-secret';
  import { CheckCircle, KeyRound } from 'lucide-svelte';

  let token = $state($page.url.searchParams.get('token') || '');
  let newPassword = $state('');
  let confirmation = $state('');
  let loading = $state(false);
  let error = $state('');
  let complete = $state(false);

  onMount(() => {
    token = takeQuerySecret('token') || token;
  });

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    error = '';
    if (!token) { error = '重置链接缺少一次性令牌。'; return; }
    const policyError = passwordPolicyError(newPassword);
    if (policyError) { error = policyError; return; }
    if (newPassword !== confirmation) { error = '两次输入的新密码不一致。'; return; }
    loading = true;
    try {
      await api.account.confirmPasswordReset(token, newPassword);
      sessionStore.clear();
      complete = true;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '重置链接无效或已过期';
    } finally {
      loading = false;
    }
  }
</script>

<svelte:head><title>重置密码 - {$brandingStore.title}</title></svelte:head>

<AccountActionCard title="重置密码" description="链接只会在你确认后使用，不会因邮件预览而自动生效">
  {#if complete}
    <div class="text-center"><CheckCircle size={36} class="mx-auto mb-3 text-nya-success" /><p class="text-body text-nya-text-primary">密码已更新，所有旧会话和令牌均已失效。</p><a href="/login" class="mt-5 inline-block text-body-medium text-nya-primary hover:underline">使用新密码登录</a></div>
  {:else if !token}
    <div class="text-center"><p class="rounded-nya-sm bg-nya-danger-soft px-3 py-3 text-body text-nya-danger" role="alert">重置链接不完整，请重新发起密码找回。</p><a href="/forgot-password" class="mt-5 inline-block text-body-medium text-nya-primary hover:underline">重新发送邮件</a></div>
  {:else}
    <form onsubmit={submit} class="space-y-4">
      {#if error}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{error}</p>{/if}
      <div><Input id="reset-new-password" label="新密码" type="password" bind:value={newPassword} autocomplete="new-password" required /><p class="mt-1.5 text-small text-nya-text-tertiary">{PASSWORD_REQUIREMENT}</p></div>
      <Input id="reset-confirm-password" label="确认新密码" type="password" bind:value={confirmation} autocomplete="new-password" required />
      <Button type="submit" variant="primary" size="lg" loading={loading} fullWidth><KeyRound size={16} /> 确认重置</Button>
    </form>
  {/if}
</AccountActionCard>
