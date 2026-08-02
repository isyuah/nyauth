<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type OAuthScopeDefinition } from '$lib/api';
  import Button from '$lib/components/ui/Button.svelte';
  import CopyButton from '$lib/components/ui/CopyButton.svelte';
  import FieldHelp from '$lib/components/ui/FieldHelp.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import { scopeHelp } from '$lib/oauth-catalog';
  import { CheckCircle, ExternalLink, RotateCw } from 'lucide-svelte';

  let { adminMode = false }: { adminMode?: boolean } = $props();

  interface DeviceResponse {
    device_code: string;
    user_code: string;
    verification_uri: string;
    verification_uri_complete: string;
    expires_in: number;
    interval: number;
  }

  type TokenResponse = Record<string, unknown> & { access_token?: string };

  let clientId = $state('nya-device-test');
  let clientSecret = $state('');
  let scopes = $state(['openid', 'profile', 'email']);
  let scopeOptions = $state(['openid', 'profile', 'email', 'offline_access']);
  let scopeDefinitions = $state<Record<string, OAuthScopeDefinition>>({});
  let device = $state<DeviceResponse | null>(null);
  let tokens = $state<TokenResponse | null>(null);
  let userInfo = $state<Record<string, unknown> | null>(null);
  let status = $state<'idle' | 'starting' | 'pending' | 'approved' | 'denied' | 'expired' | 'error'>('idle');
  let error = $state('');
  let logs = $state<string[]>([]);
  let nextPollAt = $state<Date | null>(null);
  let pollTimer: number | null = null;
  let stopped = false;

  onMount(() => {
    stopped = false;
    if (adminMode) void loadPolicy();
    return () => {
      stopped = true;
      clearPoll();
    };
  });

  async function loadPolicy() {
    try {
      const policy = await api.admin.getOAuthSettings();
      scopeOptions = [...policy.allowed_scopes];
      scopeDefinitions = policy.scope_definitions;
      scopes = scopes.filter((scope) => scopeOptions.includes(scope));
      if (scopes.length === 0 && scopeOptions.includes('openid')) scopes = ['openid'];
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '无法加载 OAuth Scope Catalog';
    }
  }

  function log(message: string) {
    logs = [...logs, `[${new Date().toLocaleTimeString()}] ${message}`];
  }

  function clearPoll() {
    if (pollTimer !== null) window.clearTimeout(pollTimer);
    pollTimer = null;
    nextPollAt = null;
  }

  function toggleScope(scope: string) {
    scopes = scopes.includes(scope) ? scopes.filter((item) => item !== scope) : [...scopes, scope];
  }

  async function start(event: SubmitEvent) {
    event.preventDefault();
    if (!clientId.trim()) {
      error = '请输入 Client ID';
      return;
    }
    clearPoll();
    device = null;
    tokens = null;
    userInfo = null;
    logs = [];
    error = '';
    status = 'starting';
    const body = new URLSearchParams({ client_id: clientId.trim(), scope: scopes.join(' ') });
    if (clientSecret) body.set('client_secret', clientSecret);
    try {
      const response = await fetch('/device_authorization', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
      });
      const payload = await response.json() as DeviceResponse & { error?: string; error_description?: string };
      if (!response.ok) throw new Error(`${payload.error || `HTTP ${response.status}`}：${payload.error_description || '设备授权初始化失败'}`);
      device = payload;
      status = 'pending';
      log(`已获得用户代码 ${payload.user_code}，等待浏览器确认`);
      schedulePoll(payload.interval);
    } catch (cause) {
      status = 'error';
      error = cause instanceof Error ? cause.message : '设备授权初始化失败';
      clientSecret = '';
    }
  }

  function schedulePoll(seconds: number) {
    if (stopped || status !== 'pending') return;
    const delay = Math.max(1, seconds) * 1_000;
    nextPollAt = new Date(Date.now() + delay);
    pollTimer = window.setTimeout(() => void poll(), delay);
  }

  async function poll() {
    if (!device || stopped || status !== 'pending') return;
    pollTimer = null;
    nextPollAt = null;
    const body = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: device.device_code,
      client_id: clientId.trim(),
    });
    if (clientSecret) body.set('client_secret', clientSecret);
    try {
      const response = await fetch('/token', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
      });
      const payload = await response.json() as TokenResponse & { error?: string; error_description?: string };
      if (response.ok) {
        tokens = payload;
        status = 'approved';
        clientSecret = '';
        log('设备授权完成并成功取得 Token');
        return;
      }
      const retry = Number.parseInt(response.headers.get('Retry-After') || '', 10);
      if (payload.error === 'authorization_pending' || payload.error === 'slow_down') {
        const delay = Number.isFinite(retry) && retry > 0 ? retry : device.interval;
        if (payload.error === 'slow_down') log(`轮询过快，服务端要求将间隔调整为 ${delay} 秒`);
        schedulePoll(delay);
        return;
      }
      if (payload.error === 'access_denied') status = 'denied';
      else if (payload.error === 'expired_token') status = 'expired';
      else status = 'error';
      error = `${payload.error || `HTTP ${response.status}`}：${payload.error_description || 'Token 请求失败'}`;
      clientSecret = '';
      log(`流程结束：${error}`);
    } catch (cause) {
      status = 'error';
      error = cause instanceof Error ? cause.message : 'Token 轮询失败';
      clientSecret = '';
    }
  }

  async function fetchUserInfo() {
    if (!tokens?.access_token) return;
    const response = await fetch('/userinfo', { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    const payload = await response.json() as Record<string, unknown> & { error?: string };
    if (!response.ok) {
      error = `UserInfo 请求失败：${payload.error || `HTTP ${response.status}`}`;
      return;
    }
    userInfo = payload;
  }

  function reset() {
    clearPoll();
    device = null;
    tokens = null;
    userInfo = null;
    clientSecret = '';
    status = 'idle';
    error = '';
    logs = [];
  }
</script>

{#if error}
  <div class="mb-4 rounded-nya-sm bg-nya-danger-soft px-4 py-3 text-small text-nya-danger" role="alert">{error}</div>
{/if}

{#if status === 'idle' || status === 'starting' || status === 'error'}
  <form onsubmit={start} class="mb-4 space-y-4 rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
    <Input id="device-test-client-id" label="Client ID" bind:value={clientId} mono required />
    <Input id="device-test-client-secret" label="Client Secret（Public Client 留空）" bind:value={clientSecret} type="password" autocomplete="off" ignorePasswordManagers mono hint="Secret 只保存在当前页面内存中，用于初始化及后续 Token 轮询。" />
    <div>
      <span class="mb-2 block text-body-medium text-nya-text-secondary">Scopes</span>
      <div class="flex flex-wrap gap-2">
        {#each scopeOptions as scope}
          <span class="inline-flex items-center gap-1">
            <button type="button" onclick={() => toggleScope(scope)} class="rounded-full border px-3 py-1 text-small {scopes.includes(scope) ? 'border-nya-primary-border bg-nya-primary-soft text-nya-primary' : 'border-nya-divider bg-nya-surface-muted text-nya-text-tertiary'}">{scope}</button>
            {#if scopeDefinitions[scope]}<FieldHelp id={`device-test-${scope}-help`} text={scopeHelp(scopeDefinitions[scope])} label={`查看 ${scope} Scope 说明`} />{/if}
          </span>
        {/each}
      </div>
    </div>
    <Button type="submit" size="lg" loading={status === 'starting'}>启动 Device Authorization</Button>
  </form>
{:else if device}
  <section class="mb-4 rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
    <div class="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <p class="text-small text-nya-text-secondary">在验证页面输入</p>
        <div class="mt-1 flex items-center gap-2"><code class="text-2xl font-bold tracking-wider text-nya-text-primary">{device.user_code}</code><CopyButton value={device.user_code} label="复制设备代码" /></div>
        <a href={device.verification_uri_complete} target="_blank" rel="noopener noreferrer" class="mt-3 inline-flex items-center gap-1 text-small text-nya-primary hover:underline"><ExternalLink size={14} /> 打开设备验证页</a>
      </div>
      <div class="rounded-nya-sm bg-nya-surface-muted px-3 py-2 text-small text-nya-text-secondary">
        {#if status === 'pending'}
          <span class="inline-flex items-center gap-2"><RotateCw size={14} class="animate-spin" /> 等待用户确认</span>
          {#if nextPollAt}<p class="mt-1 text-micro text-nya-text-tertiary">下次轮询：{nextPollAt.toLocaleTimeString()}</p>{/if}
        {:else if status === 'approved'}
          <span class="inline-flex items-center gap-2 text-nya-success"><CheckCircle size={14} /> 已取得 Token</span>
        {:else}
          <span>流程已结束：{status}</span>
        {/if}
      </div>
    </div>
    <div class="mt-4 flex flex-wrap gap-2">
      {#if status === 'approved' && tokens?.access_token}<Button variant="soft" size="sm" onclick={fetchUserInfo}>获取 UserInfo</Button>{/if}
      <Button variant="secondary" size="sm" onclick={reset}>重新测试</Button>
    </div>
  </section>
{/if}

{#if tokens}
  <section class="mb-4 rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
    <h3 class="text-card-title text-nya-text-primary">Token 响应</h3>
    <pre class="mt-3 overflow-x-auto whitespace-pre-wrap break-all rounded-nya-sm bg-nya-surface-muted p-3 text-micro">{JSON.stringify(tokens, null, 2)}</pre>
  </section>
{/if}

{#if userInfo}
  <section class="mb-4 rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
    <h3 class="text-card-title text-nya-text-primary">UserInfo</h3>
    <pre class="mt-3 overflow-x-auto whitespace-pre-wrap rounded-nya-sm bg-nya-surface-muted p-3 text-micro">{JSON.stringify(userInfo, null, 2)}</pre>
  </section>
{/if}

{#if logs.length > 0}
  <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
    <h3 class="text-card-title text-nya-text-primary">流程日志</h3>
    <div class="mt-3 max-h-64 overflow-y-auto rounded-nya-sm bg-[#1e1e2e] p-3 font-mono text-micro text-[#cdd6f4]">
      {#each logs as line}<div class="leading-7">{line}</div>{/each}
    </div>
  </section>
{/if}
