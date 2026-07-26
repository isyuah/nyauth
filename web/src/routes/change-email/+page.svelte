<script lang="ts">
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { api } from '$lib/api';
  import { takeQuerySecret } from '$lib/query-secret';
  import { sessionStore } from '$lib/stores';
  import AccountActionCard from '$lib/components/account/AccountActionCard.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import { CheckCircle, MailCheck } from 'lucide-svelte';

  let token = $state($page.url.searchParams.get('token') || '');
  let loading = $state(false);
  let error = $state('');
  let complete = $state(false);

  onMount(() => {
    token = takeQuerySecret('token') || token;
  });

  async function confirm() {
    if (!token || loading) return;
    loading = true;
    error = '';
    try {
      await api.account.confirmEmailChange(token);
      sessionStore.clear();
      complete = true;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '确认链接无效或已过期';
    } finally {
      loading = false;
    }
  }
</script>

<svelte:head><title>确认邮箱变更 - Nya</title></svelte:head>

<AccountActionCard title="确认邮箱变更" description="请主动确认操作；打开邮件或安全扫描不会自动修改账户">
  {#if complete}
    <div class="text-center"><CheckCircle size={36} class="mx-auto mb-3 text-nya-success" /><p class="text-body text-nya-text-primary">新邮箱已生效。为保护账户安全，请重新登录。</p><a href="/login" class="mt-5 inline-block text-body-medium text-nya-primary hover:underline">重新登录</a></div>
  {:else if !token}
    <p class="rounded-nya-sm bg-nya-danger-soft px-3 py-3 text-center text-body text-nya-danger" role="alert">确认链接不完整，请从个人资料页重新发起邮箱变更。</p>
  {:else}
    <div class="space-y-4 text-center">{#if error}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{error}</p>{/if}<MailCheck size={40} class="mx-auto text-nya-primary" /><p class="text-body text-nya-text-secondary">确认后，旧会话和令牌会立即失效。</p><Button variant="primary" size="lg" onclick={confirm} loading={loading} fullWidth>确认更换邮箱</Button></div>
  {/if}
</AccountActionCard>
