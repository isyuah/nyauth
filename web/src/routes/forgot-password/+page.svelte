<script lang="ts">
  import { api, type HumanVerificationChallenge, type HumanVerificationProof } from '$lib/api';
  import AccountActionCard from '$lib/components/account/AccountActionCard.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import HumanVerificationWidget from '$lib/components/security/HumanVerificationWidget.svelte';
  import { onMount } from 'svelte';
  import { CheckCircle, Mail } from 'lucide-svelte';

  let email = $state('');
  let loading = $state(false);
  let error = $state('');
  let sent = $state(false);
  let humanChallenge = $state<HumanVerificationChallenge | null>(null);
  let humanProof = $state<HumanVerificationProof | null>(null);
  let humanWidgetKey = $state(0);

  onMount(async () => {
    try { humanChallenge = await api.getHumanVerification('password_reset'); }
    catch { error = '暂时无法加载人机验证配置。'; }
  });

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    loading = true;
    error = '';
    if (humanChallenge?.required && !humanProof) {
      loading = false;
      error = '请先完成人机验证。';
      return;
    }
    try {
      await api.account.requestPasswordReset(email, humanProof ?? undefined);
      sent = true;
    } catch (cause) {
      if (humanChallenge?.required) { humanProof = null; humanWidgetKey += 1; }
      error = cause instanceof Error ? cause.message : '暂时无法提交请求';
    } finally {
      loading = false;
    }
  }
</script>

<svelte:head><title>找回密码 - Nya</title></svelte:head>

<AccountActionCard title="找回密码" description="输入账户邮箱，我们会发送一次性重置链接">
  {#if sent}
    <div class="text-center"><CheckCircle size={36} class="mx-auto mb-3 text-nya-success" /><p class="text-body text-nya-text-primary">如果该邮箱已绑定到可恢复的账户，重置邮件会很快送达。</p><p class="mt-2 text-small text-nya-text-tertiary">为保护账户隐私，此页面不会确认邮箱是否存在。</p><a href="/login" class="mt-5 inline-block text-body-medium text-nya-primary hover:underline">返回登录</a></div>
  {:else}
    <form onsubmit={submit} class="space-y-4">
      {#if error}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{error}</p>{/if}
      <Input id="recovery-email" label="邮箱地址" type="email" bind:value={email} autocomplete="email" required placeholder="name@example.com" />
      {#if humanChallenge?.required}
        {#key humanWidgetKey}<HumanVerificationWidget challenge={humanChallenge} bind:proof={humanProof} onerror={(message) => (error = message)} />{/key}
      {/if}
      <Button type="submit" variant="primary" size="lg" requiredCapability="account_mutations" loading={loading} fullWidth><Mail size={16} /> 发送重置邮件</Button>
      <p class="text-center"><a href="/login" class="text-small text-nya-primary hover:underline">返回登录</a></p>
    </form>
  {/if}
</AccountActionCard>
