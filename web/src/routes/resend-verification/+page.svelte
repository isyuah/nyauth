<script lang="ts">
  import { api, ApiError } from '$lib/api';
  import AccountActionCard from '$lib/components/account/AccountActionCard.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import { MailCheck, Send } from 'lucide-svelte';

  let email = $state('');
  let loading = $state(false);
  let accepted = $state(false);
  let error = $state('');

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    accepted = false;
    error = '';
    loading = true;
    try {
      await api.resendPendingEmailVerification(email.trim());
      accepted = true;
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 429 && cause.retryAfter) {
        error = `请求过于频繁，请在 ${cause.retryAfter} 秒后重试。`;
      } else {
        error = cause instanceof Error ? cause.message : '请求失败，请稍后重试。';
      }
    } finally {
      loading = false;
    }
  }
</script>

<svelte:head><title>重发验证邮件 - Nya</title></svelte:head>

<AccountActionCard title="重发验证邮件" description="为尚未完成验证的注册重新生成确认链接">
  {#if accepted}
    <div class="text-center">
      <MailCheck size={36} class="mx-auto mb-3 text-nya-primary" />
      <p class="text-body text-nya-text-primary">如果该邮箱对应仍有效的待验证注册，新邮件已成功加入发送队列。</p>
      <p class="mt-2 text-small text-nya-text-tertiary">重发不会延长原注册截止时间。</p>
      <div class="mt-5 flex flex-wrap justify-center gap-4">
        <button type="button" class="text-body-medium text-nya-primary hover:underline" onclick={() => (accepted = false)}>再次请求</button>
        <a href="/login" class="text-body-medium text-nya-primary hover:underline">返回登录</a>
      </div>
    </div>
  {:else}
    <form onsubmit={submit} class="space-y-4">
      {#if error}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{error}</p>{/if}
      <Input id="resend-verification-email" label="注册邮箱" type="email" bind:value={email} required autocomplete="email" placeholder="name@example.com" />
      <Button type="submit" variant="primary" size="lg" loading={loading} fullWidth><Send size={16} /> 提交重发请求</Button>
      <p class="text-center"><a href="/login" class="text-small text-nya-primary hover:underline">返回登录</a></p>
    </form>
  {/if}
</AccountActionCard>
