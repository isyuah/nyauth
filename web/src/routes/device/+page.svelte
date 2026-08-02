<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { api } from '$lib/api';
  import { sessionStore } from '$lib/stores';
  import Button from '$lib/components/ui/Button.svelte';
  import Card from '$lib/components/ui/Card.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import { CheckCircle, KeyRound, MonitorCheck, ShieldCheck, XCircle } from 'lucide-svelte';

  type ResultState = 'approved' | 'denied' | '';

  let userCode = $state('');
  let loading = $state(true);
  let submitting = $state(false);
  let error = $state('');
  let result = $state<ResultState>('');

  function formatUserCode(value: string): string {
    const normalized = value.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
    return normalized.length > 4 ? `${normalized.slice(0, 4)}-${normalized.slice(4)}` : normalized;
  }

  function handleCodeInput(event: Event) {
    userCode = formatUserCode((event.currentTarget as HTMLInputElement).value);
    error = '';
  }

  onMount(async () => {
    const status = $page.url.searchParams.get('status');
    if (status === 'approved' || status === 'denied') {
      result = status;
      sessionStorage.removeItem('nya_device_verification_pending');
      loading = false;
      return;
    }
    userCode = formatUserCode($page.url.searchParams.get('user_code') || '');
    const returnTo = `/device${userCode ? `?user_code=${encodeURIComponent(userCode)}` : ''}`;
    try {
      const session = await sessionStore.initialize(true);
      if (!session) {
        await goto(`/login?return_to=${encodeURIComponent(returnTo)}`);
        return;
      }
      if (session.must_change_password) {
        await goto(`/change-password?return_to=${encodeURIComponent(returnTo)}`);
        return;
      }
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '暂时无法检查登录状态';
    } finally {
      loading = false;
    }
  });

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    error = '';
    if (userCode.replace('-', '').length !== 8) {
      error = '请输入设备上显示的 8 位代码';
      return;
    }
    submitting = true;
    try {
      const prepared = await api.deviceAuthorization.prepare(userCode);
      sessionStorage.setItem('nya_device_verification_pending', '1');
      window.location.href = prepared.consent_url;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '设备代码验证失败';
      submitting = false;
    }
  }
</script>

<svelte:head><title>设备授权 - Nya</title></svelte:head>

<div class="flex min-h-screen items-center justify-center bg-nya-page px-4 py-10">
  <div class="w-full max-w-[440px]">
    <div class="mb-6 text-center">
      <span class="mb-3 inline-flex h-12 w-12 items-center justify-center rounded-nya-lg bg-nya-primary-soft text-nya-primary">
        <MonitorCheck size={24} />
      </span>
      <h1 class="text-section-title text-nya-text-primary">连接您的设备</h1>
      <p class="mt-2 text-small text-nya-text-secondary">输入电视、终端或其他设备上显示的代码。</p>
    </div>

    <Card>
      {#if loading}
        <p class="py-8 text-center text-small text-nya-text-tertiary" role="status">正在检查登录状态…</p>
      {:else if result === 'approved'}
        <div class="py-4 text-center">
          <CheckCircle size={36} class="mx-auto mb-3 text-nya-success" />
          <h2 class="text-card-title text-nya-text-primary">设备已获授权</h2>
          <p class="mt-2 text-small text-nya-text-secondary">您可以返回设备继续操作，此页面可以安全关闭。</p>
        </div>
      {:else if result === 'denied'}
        <div class="py-4 text-center">
          <XCircle size={36} class="mx-auto mb-3 text-nya-danger" />
          <h2 class="text-card-title text-nya-text-primary">已拒绝设备访问</h2>
          <p class="mt-2 text-small text-nya-text-secondary">设备不会获得您的账户 Token。需要时可由设备重新发起请求。</p>
        </div>
      {:else}
        <form class="space-y-5" onsubmit={submit}>
          <Input
            id="device-user-code"
            label="设备代码"
            placeholder="ABCD-EFGH"
            bind:value={userCode}
            oninput={handleCodeInput}
            autocomplete="one-time-code"
            inputmode="text"
            maxlength={9}
            mono
            required
            ignorePasswordManagers
            error={error}
            hint="代码不区分大小写，连字符可以省略。"
          />
          <Button type="submit" size="lg" fullWidth loading={submitting} requiredCapability="auth_issuance">
            <KeyRound size={16} /> 验证代码
          </Button>
        </form>

        <div class="mt-5 flex items-start gap-2 rounded-nya-sm bg-nya-info-soft px-3 py-2 text-small text-nya-info">
          <ShieldCheck size={16} class="mt-0.5 shrink-0" />
          <p>下一步会显示应用身份和具体权限。只有在您刚刚主动操作该设备时才应继续授权。</p>
        </div>
      {/if}
    </Card>
  </div>
</div>
