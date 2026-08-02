<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { api } from '$lib/api';
  import { brandingStore, sessionStore } from '$lib/stores';
  import AuthorizationShell from '$lib/components/oauth/AuthorizationShell.svelte';
  import BrandLogo from '$lib/components/layout/BrandLogo.svelte';
  import OAuthClientLogo from '$lib/components/oauth/OAuthClientLogo.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import { CheckCircle2, KeyRound, ShieldCheck, XCircle } from 'lucide-svelte';

  type ResultState = 'approved' | 'denied' | '';
  type DeviceResult = { approved: boolean; client_name: string; logo_url?: string | null; permission_count: number };
  const resultStorageKey = 'nyauth:device-authorization-result';

  let userCode = $state('');
  let loading = $state(true);
  let submitting = $state(false);
  let error = $state('');
  let result = $state<ResultState>('');
  let resultDetail = $state<DeviceResult | null>(null);

  function formatUserCode(value: string): string {
    const normalized = value.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
    return normalized.length > 4 ? `${normalized.slice(0, 4)}-${normalized.slice(4)}` : normalized;
  }

  function handleCodeInput(event: Event) {
    userCode = formatUserCode((event.currentTarget as HTMLInputElement).value);
    error = '';
  }

  function consumeResultDetail(): DeviceResult | null {
    const raw = sessionStorage.getItem(resultStorageKey);
    sessionStorage.removeItem(resultStorageKey);
    if (!raw) return null;
    try {
      const value: unknown = JSON.parse(raw);
      if (!value || typeof value !== 'object') return null;
      const detail = value as Record<string, unknown>;
      if (typeof detail.approved !== 'boolean' || typeof detail.client_name !== 'string' || typeof detail.permission_count !== 'number') return null;
      return {
        approved: detail.approved,
        client_name: detail.client_name,
        logo_url: typeof detail.logo_url === 'string' ? detail.logo_url : null,
        permission_count: detail.permission_count,
      };
    } catch {
      return null;
    }
  }

  onMount(async () => {
    const status = $page.url.searchParams.get('status');
    if (status === 'approved' || status === 'denied') {
      result = status;
      resultDetail = consumeResultDetail();
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

<svelte:head><title>设备授权 - {$brandingStore.title}</title></svelte:head>

{#if result}
  <AuthorizationShell maxWidth="660px" label="设备授权结果">
    <div class="grid min-h-[340px] md:grid-cols-[0.92fr_1.08fr]">
      <div class="flex flex-col items-center justify-center p-7 text-center {result === 'approved' ? 'bg-nya-success-soft' : 'bg-nya-danger-soft'}">
        <span class="mb-4 grid h-16 w-16 place-items-center rounded-full bg-nya-surface {result === 'approved' ? 'text-nya-success' : 'text-nya-danger'}">
          {#if result === 'approved'}<CheckCircle2 size={36} />{:else}<XCircle size={36} />{/if}
        </span>
        <h1 class="text-xl font-bold text-nya-text-primary">{result === 'approved' ? '设备已获授权' : '设备访问已拒绝'}</h1>
        <p class="mt-2 text-small text-nya-text-secondary">{resultDetail?.client_name || '发起请求的设备'}{result === 'approved' ? ' 可以继续完成登录。' : ' 未获得任何访问权限。'}</p>
      </div>
      <div class="flex flex-col justify-center p-7">
        <BrandLogo size={32} showName compact />
        <h2 class="mb-3 mt-7 text-body font-semibold text-nya-text-primary">本次操作</h2>
        <div class="flex items-center gap-3 rounded-nya-md border border-nya-border bg-nya-surface-soft p-3">
          <OAuthClientLogo name={resultDetail?.client_name || '设备应用'} url={resultDetail?.logo_url} />
          <span class="min-w-0"><strong class="block truncate text-body text-nya-text-primary">{resultDetail?.client_name || '设备应用'}</strong><span class="block text-small text-nya-text-secondary">{result === 'approved' ? `已允许 ${resultDetail?.permission_count ?? 0} 项权限` : '本次请求未获得授权'}</span></span>
        </div>
        <div class="mt-3 rounded-nya-sm bg-nya-info-soft px-3 py-2.5 text-small text-nya-info"><strong class="block">{result === 'approved' ? '返回发起请求的设备' : '无需进行其他操作'}</strong>{result === 'approved' ? '设备会自动继续；本页面可以安全关闭。' : '可以关闭本页面，需要时由设备重新发起授权。'}</div>
      </div>
    </div>
  </AuthorizationShell>
{:else}
	<AuthorizationShell maxWidth="720px" label="设备代码验证">
    <div class="grid md:grid-cols-[240px_minmax(0,1fr)]">
      <aside class="bg-[#273044] p-6 text-[#F7F8FF] sm:p-8">
        <BrandLogo size={34} showName compact theme="dark" textClass="text-white" />
        <h1 class="mt-8 text-xl font-bold md:mt-[72px]">连接您的设备</h1>
        <p class="mt-2 text-small text-[#C9D0DF]">代码只用于找到设备发起的授权请求，不会直接授予任何权限。</p>
        <ul class="mt-6 hidden space-y-3 text-small text-[#DCE1EB] md:block"><li>✓ 核对应用身份</li><li>✓ 逐项确认请求权限</li><li>✓ 可随时拒绝整个请求</li></ul>
      </aside>
      <div class="p-6 sm:p-9">
        {#if loading}
          <p class="py-16 text-center text-small text-nya-text-tertiary" role="status">正在检查登录状态…</p>
        {:else}
          <form onsubmit={submit}>
            <h2 class="text-xl font-bold text-nya-text-primary">输入设备代码</h2>
            <p class="mb-7 mt-2 text-body text-nya-text-secondary">在下方输入电视、终端或其他设备显示的代码。</p>
            <label for="device-user-code" class="mb-2 block text-body font-semibold text-nya-text-primary">设备代码</label>
            <input
              id="device-user-code"
              class="h-14 w-full rounded-nya-sm border bg-nya-surface px-4 text-center font-mono text-xl font-semibold tracking-[0.08em] text-nya-text-primary outline-none transition focus:ring-2 {error ? 'border-nya-danger focus:ring-nya-danger/24' : 'border-nya-border-strong focus:border-nya-primary focus:ring-nya-primary/24'}"
              placeholder="ABCD-EFGH"
              value={userCode}
              oninput={handleCodeInput}
              autocomplete="one-time-code"
              inputmode="text"
              maxlength={9}
              required
              data-bwignore="true"
              data-1p-ignore="true"
              aria-invalid={error ? 'true' : undefined}
              aria-describedby={error ? 'device-code-error' : 'device-code-hint'}
            />
            {#if error}<p id="device-code-error" class="mt-2 text-small text-nya-danger" role="alert">{error}</p>{:else}<p id="device-code-hint" class="mt-2 text-small text-nya-text-tertiary">支持直接粘贴；字母大小写和连字符不会影响验证。</p>{/if}
            <div class="mt-6"><Button type="submit" size="lg" fullWidth loading={submitting} requiredCapability="auth_issuance"><KeyRound size={16} /> 验证并继续</Button></div>
            <div class="mt-5 flex items-start gap-2 rounded-nya-sm bg-nya-info-soft px-3 py-2.5 text-small text-nya-info"><ShieldCheck size={16} class="mt-0.5 shrink-0" /><p>下一步会显示应用身份和具体权限。只有在您刚刚主动操作该设备时才应继续。</p></div>
          </form>
        {/if}
      </div>
    </div>
  </AuthorizationShell>
{/if}
