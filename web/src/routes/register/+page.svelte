<script lang="ts">
  import { onMount } from 'svelte';
  import { ApiError, api, humanVerificationChallengeFromError, type HumanVerificationChallenge, type HumanVerificationProof, type RegistrationOptions } from '$lib/api';
  import AccountActionCard from '$lib/components/account/AccountActionCard.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import HumanVerificationWidget from '$lib/components/security/HumanVerificationWidget.svelte';
  import { PASSWORD_REQUIREMENT, passwordPolicyError } from '$lib/password-policy';
  import { takeQuerySecret } from '$lib/query-secret';
	import { brandingStore } from '$lib/stores';
  import { capabilityPauseReason, isCapabilityPaused, serviceStatusStore } from '$lib/service-control';
  import { CheckCircle, MailCheck, UserPlus } from 'lucide-svelte';

  let options = $state<RegistrationOptions | null>(null);
  let optionsError = $state('');
  let username = $state('');
  let email = $state('');
  let password = $state('');
  let confirmation = $state('');
  let inviteCode = $state('');
  let loading = $state(false);
  let error = $state('');
  let result = $state<'pending_verification' | 'registered' | ''>('');
  let verificationExpiresAt = $state('');
  let humanChallenge = $state<HumanVerificationChallenge | null>(null);
  let humanProof = $state<HumanVerificationProof | null>(null);
  let humanWidgetKey = $state(0);
  let registrationPaused = $derived(isCapabilityPaused($serviceStatusStore.value, 'self_registration'));

  function formatDeadline(value: string): string {
    const deadline = new Date(value);
    return Number.isNaN(deadline.getTime()) ? value : deadline.toLocaleString('zh-CN');
  }

  onMount(async () => {
    inviteCode = takeQuerySecret('invite') || '';
    try {
      const [registrationOptions, challenge] = await Promise.all([
        api.getRegistrationOptions(), api.getHumanVerification('register').catch(() => null),
      ]);
      options = registrationOptions;
      humanChallenge = challenge;
    } catch {
      optionsError = '暂时无法加载注册信息，请稍后重试。';
    }
  });

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    error = '';
    if (registrationPaused) {
      error = capabilityPauseReason($serviceStatusStore.value, 'self_registration');
      return;
    }
    const policyError = passwordPolicyError(password);
    if (policyError) { error = policyError; return; }
    if (password !== confirmation) { error = '两次输入的密码不一致。'; return; }
    if (humanChallenge?.required && !humanProof) { error = '请先完成人机验证。'; return; }
    loading = true;
    try {
      const payload = { username: username.trim(), email: email.trim(), password } as Parameters<typeof api.register>[0];
      if (options?.mode === 'invite_only') payload.invite_code = inviteCode.trim();
      if (humanProof) payload.human_verification = humanProof;
      const response = await api.register(payload);
      result = response.status;
      verificationExpiresAt = response.verification_expires_at || '';
    } catch (cause) {
      const requiredChallenge = humanVerificationChallengeFromError(cause);
      if (requiredChallenge) {
        humanChallenge = requiredChallenge;
        humanProof = null;
        humanWidgetKey += 1;
        error = '请完成人机验证后再次提交。';
      } else {
        if (humanChallenge?.required) {
          humanProof = null;
          humanWidgetKey += 1;
        }
        if (cause instanceof ApiError && cause.status === 503) {
          error = cause.retryAfter
            ? `注册邮件服务正在恢复，请在 ${cause.retryAfter} 秒后重试。你填写的内容尚未提交。`
            : '注册暂时不可用，邮件服务可能尚未配置或正在恢复，请稍后重试。';
        } else {
          error = cause instanceof Error ? cause.message : '注册失败，请稍后重试';
        }
      }
    } finally {
      loading = false;
    }
  }
</script>

<svelte:head><title>注册 - {$brandingStore.title}</title></svelte:head>

<AccountActionCard title="注册账号" description="注册完成后即可登录用户中心并授权应用">
  {#if result === 'pending_verification'}
    <div class="text-center"><MailCheck size={36} class="mx-auto mb-3 text-nya-primary" /><p class="text-body text-nya-text-primary">验证邮件已成功加入发送队列，收件地址为 <span class="font-semibold">{email}</span>。</p>{#if verificationExpiresAt}<p class="mt-2 text-small text-nya-text-tertiary">请在 {formatDeadline(verificationExpiresAt)} 前完成验证，截止时间不会因重发而延长。</p>{/if}<div class="mt-5 flex flex-wrap justify-center gap-4"><a href="/resend-verification" class="text-body-medium text-nya-primary hover:underline">重发验证邮件</a><a href="/login" class="text-body-medium text-nya-primary hover:underline">返回登录</a></div></div>
  {:else if result === 'registered'}
    <div class="text-center"><CheckCircle size={36} class="mx-auto mb-3 text-nya-success" /><p class="text-body text-nya-text-primary">注册成功，现在就可以登录了。</p><a href="/login" class="mt-5 inline-block text-body-medium text-nya-primary hover:underline">前往登录</a></div>
  {:else if optionsError}
    <p class="rounded-nya-sm bg-nya-danger-soft px-3 py-3 text-center text-body text-nya-danger" role="alert">{optionsError}</p>
  {:else if !options}
    <p class="text-center text-body text-nya-text-tertiary">加载中…</p>
  {:else if options.mode === 'closed'}
    <div class="text-center"><p class="rounded-nya-sm bg-nya-warning-soft px-3 py-3 text-body text-nya-warning" role="alert">当前未开放注册，请联系管理员创建账号。</p><a href="/login" class="mt-5 inline-block text-body-medium text-nya-primary hover:underline">返回登录</a></div>
  {:else if !options.available}
    <div class="text-center"><p class="rounded-nya-sm bg-nya-warning-soft px-3 py-3 text-body text-nya-warning" role="alert">注册入口已开启，但邮件服务当前不可用。系统不会创建无法接收验证邮件的待验证账号，请稍后再试或联系管理员。</p><a href="/login" class="mt-5 inline-block text-body-medium text-nya-primary hover:underline">返回登录</a></div>
  {:else}
    <form onsubmit={submit} class="space-y-4">
      {#if error}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{error}</p>{/if}
      {#if options.mode === 'invite_only'}
        <Input id="register-invite" label="邀请码" bind:value={inviteCode} required autocomplete="off" placeholder="粘贴收到的邀请码" />
      {/if}
      <Input id="register-username" label="用户名" bind:value={username} required autocomplete="username" placeholder="3-64 位字母、数字或 _ - ." />
      <div>
        <Input id="register-email" label="邮箱地址" type="email" bind:value={email} required autocomplete="email" placeholder="name@example.com" />
        {#if options.allowed_email_domains.length > 0}
          <p class="mt-1.5 text-small text-nya-text-tertiary">仅允许以下域名的邮箱：{options.allowed_email_domains.join('、')}</p>
        {/if}
      </div>
      <div><Input id="register-password" label="密码" type="password" bind:value={password} required autocomplete="new-password" /><p class="mt-1.5 text-small text-nya-text-tertiary">{PASSWORD_REQUIREMENT}</p></div>
      <Input id="register-confirm" label="确认密码" type="password" bind:value={confirmation} required autocomplete="new-password" />
      {#if options.require_email_verification}
        <p class="text-small text-nya-text-tertiary">注册后需要完成邮箱验证才能登录。</p>
      {/if}
      {#if humanChallenge?.required}
        {#key humanWidgetKey}
          <HumanVerificationWidget challenge={humanChallenge} bind:proof={humanProof} onerror={(message) => (error = message)} />
        {/key}
      {/if}
      <Button type="submit" variant="primary" size="lg" loading={loading} requiredCapability="self_registration" fullWidth><UserPlus size={16} /> 注册</Button>
      <p class="text-center"><a href="/login" class="text-small text-nya-primary hover:underline">已有账号？返回登录</a></p>
    </form>
  {/if}
</AccountActionCard>
