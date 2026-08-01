<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import {
    api,
    type BrowserSession,
    type LoginHistoryEntry,
    type TrustedDevice,
  } from '$lib/api';
  import { sessionStore } from '$lib/stores';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import { History, LogOut, MonitorSmartphone, ShieldCheck } from 'lucide-svelte';

  type DeviceAction =
    | { kind: 'session'; item: BrowserSession }
    | { kind: 'other_sessions' }
    | { kind: 'trusted'; item: TrustedDevice }
    | { kind: 'other_trusted' }
    | null;

  let browserSessions = $state<BrowserSession[]>([]);
  let sessionsLoading = $state(true);
  let sessionsError = $state('');

  let trustedDevices = $state<TrustedDevice[]>([]);
  let trustedDevicesEnabled = $state(true);
  let trustedLoading = $state(true);
  let trustedError = $state('');

  let loginHistory = $state<LoginHistoryEntry[]>([]);
  let historyPage = $state(1);
  let historyTotalPages = $state(1);
  let historyLoading = $state(true);
  let historyError = $state('');

  let deviceAction = $state<DeviceAction>(null);
  let confirmOpen = $state(false);
  let actionError = $state('');

  let otherSessionCount = $derived(browserSessions.filter((item) => !item.current).length);
  let otherTrustedCount = $derived(trustedDevices.filter((item) => !item.current).length);

  function deviceLabel(userAgent = ''): string {
    const browser = /Edg\//.test(userAgent) ? 'Edge' : /Firefox\//.test(userAgent) ? 'Firefox' : /Chrome\//.test(userAgent) ? 'Chrome' : /Safari\//.test(userAgent) ? 'Safari' : '未知浏览器';
    const system = /Windows/.test(userAgent) ? 'Windows' : /Android/.test(userAgent) ? 'Android' : /iPhone|iPad/.test(userAgent) ? 'iOS' : /Mac OS/.test(userAgent) ? 'macOS' : /Linux/.test(userAgent) ? 'Linux' : '未知系统';
    return `${browser} · ${system}`;
  }

  function authenticationLabel(item: LoginHistoryEntry): string {
    const method = item.authentication_method === 'password' ? '密码'
      : item.authentication_method === 'provider' ? (item.provider ? `Provider · ${item.provider}` : 'Provider')
      : item.authentication_method === 'passkey' ? 'Passkey'
      : '登录验证';
    const secondFactor = item.second_factor === 'totp' ? '动态验证码'
      : item.second_factor === 'recovery_code' ? '恢复码'
      : item.second_factor === 'passkey' ? 'Passkey MFA'
      : item.second_factor === 'trusted_device' ? '可信浏览器'
      : item.second_factor || '';
    return secondFactor ? `${method} + ${secondFactor}` : method;
  }

  async function loadSessions() {
    sessionsLoading = true;
    sessionsError = '';
    try {
      const result = await api.getMySessions();
      browserSessions = Array.isArray(result) ? result : [];
    } catch (cause) {
      sessionsError = cause instanceof Error ? cause.message : '设备会话加载失败';
    } finally {
      sessionsLoading = false;
    }
  }

  async function loadTrustedDevices() {
    trustedLoading = true;
    trustedError = '';
    try {
      const result = await api.getMyTrustedDevices();
      trustedDevicesEnabled = result.enabled !== false;
      trustedDevices = Array.isArray(result.items) ? result.items : [];
    } catch (cause) {
      trustedError = cause instanceof Error ? cause.message : '可信浏览器加载失败';
    } finally {
      trustedLoading = false;
    }
  }

  async function loadLoginHistory(page = 1) {
    historyLoading = true;
    historyError = '';
    try {
      const result = await api.getMyLoginHistory(page, 20);
      const items = Array.isArray(result.items) ? result.items : [];
      loginHistory = page === 1 ? items : [...loginHistory, ...items];
      historyPage = result.page || page;
      historyTotalPages = result.total_pages || 1;
    } catch (cause) {
      historyError = cause instanceof Error ? cause.message : '登录历史加载失败';
    } finally {
      historyLoading = false;
    }
  }

  onMount(() => {
    void Promise.all([loadSessions(), loadTrustedDevices(), loadLoginHistory()]);
  });

  function requestDeviceAction(action: DeviceAction) {
    deviceAction = action;
    actionError = '';
    confirmOpen = true;
  }

  function actionTitle(): string {
    if (deviceAction?.kind === 'other_sessions') return '退出其他设备';
    if (deviceAction?.kind === 'session') return deviceAction.item.current ? '退出当前设备' : '撤销设备会话';
    if (deviceAction?.kind === 'other_trusted') return '撤销其他可信浏览器';
    return '撤销可信浏览器';
  }

  function actionDescription(): string {
    if (deviceAction?.kind === 'other_sessions') return `将撤销其他 ${otherSessionCount} 个设备会话，当前设备保持登录。`;
    if (deviceAction?.kind === 'session') return deviceAction.item.current ? '当前会话会立即结束，你需要重新登录。' : '该设备会立即退出登录。';
    if (deviceAction?.kind === 'other_trusted') return `将撤销其他 ${otherTrustedCount} 个可信浏览器。已登录会话不受影响，这些浏览器下次登录时需要重新完成 MFA。`;
    return '该浏览器下次登录时需要重新完成 MFA；当前已登录会话不会退出。';
  }

  async function runDeviceAction() {
    const action = deviceAction;
    if (!action) return;
    actionError = '';
    try {
      if (action.kind === 'other_sessions') {
        await api.revokeOtherSessions();
        browserSessions = browserSessions.filter((item) => item.current);
      } else if (action.kind === 'session') {
        await api.revokeMySession(action.item.id);
        if (action.item.current) {
          sessionStore.clear();
          await goto('/login');
        } else {
          browserSessions = browserSessions.filter((item) => item.id !== action.item.id);
        }
      } else if (action.kind === 'other_trusted') {
        await api.revokeOtherTrustedDevices();
        trustedDevices = trustedDevices.filter((item) => item.current);
      } else {
        await api.revokeMyTrustedDevice(action.item.id);
        trustedDevices = trustedDevices.filter((item) => item.id !== action.item.id);
      }
    } catch (cause) {
      actionError = cause instanceof Error ? cause.message : '无法完成撤销操作';
      throw cause;
    }
  }
</script>

<svelte:head><title>设备与登录历史 - Nya</title></svelte:head>

<div class="space-y-5">
  <section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
    <div class="flex flex-wrap items-center justify-between gap-4 border-b border-nya-divider px-7 py-5">
      <div><h2 class="text-card-title text-nya-text-primary">设备会话</h2><p class="mt-1 text-body text-nya-text-secondary">查看已登录设备，并立即撤销不认识的会话。</p></div>
      {#if otherSessionCount > 0}<Button variant="secondary" size="sm" onclick={() => requestDeviceAction({ kind: 'other_sessions' })}><LogOut size={14} /> 退出其他设备</Button>{/if}
    </div>
    <div class="px-7 py-6">
      {#if sessionsLoading}<p class="text-body text-nya-text-tertiary" role="status">正在加载设备会话…</p>
      {:else if sessionsError}<div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2"><p class="text-small text-nya-danger">{sessionsError}</p><Button variant="ghost" size="sm" onclick={loadSessions}>重试</Button></div>
      {:else if browserSessions.length === 0}<p class="text-body text-nya-text-tertiary">暂无可显示的设备会话。</p>
      {:else}<div class="divide-y divide-nya-divider">{#each browserSessions as item}
        <article class="flex flex-col justify-between gap-3 py-4 sm:flex-row sm:items-center">
          <div class="flex min-w-0 items-start gap-3"><span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-primary-soft"><MonitorSmartphone size={19} class="text-nya-primary" /></span><div class="min-w-0">
            <p class="text-body-medium font-semibold text-nya-text-primary">{deviceLabel(item.user_agent)} {#if item.current}<Badge variant="success">当前设备</Badge>{/if}</p>
            <p class="mt-1 text-small text-nya-text-tertiary">IP {item.ip_address || '未知'} · 最后活动 {new Date(item.last_seen_at).toLocaleString()}</p>
            <p class="mt-0.5 text-micro text-nya-text-tertiary">空闲截止 {new Date(item.session_idle_expires_at).toLocaleString()} · 绝对截止 {new Date(item.session_expires_at).toLocaleString()}</p>
            <p class="mt-0.5 truncate text-micro text-nya-text-tertiary" title={item.user_agent}>{item.user_agent || '未提供 User-Agent'}</p>
          </div></div>
          <Button variant="ghost" size="sm" onclick={() => requestDeviceAction({ kind: 'session', item })}>{item.current ? '退出此设备' : '撤销会话'}</Button>
        </article>
      {/each}</div>{/if}
    </div>
  </section>

  <section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
    <div class="flex flex-wrap items-center justify-between gap-4 border-b border-nya-divider px-7 py-5">
      <div><h2 class="text-card-title text-nya-text-primary">可信浏览器</h2><p class="mt-1 text-body text-nya-text-secondary">这些浏览器完成主验证后可跳过登录 MFA，但不能跳过敏感操作的重新认证。</p></div>
      {#if otherTrustedCount > 0}<Button variant="secondary" size="sm" onclick={() => requestDeviceAction({ kind: 'other_trusted' })}><ShieldCheck size={14} /> 撤销其他浏览器</Button>{/if}
    </div>
    <div class="px-7 py-6">
      {#if trustedLoading}<p class="text-body text-nya-text-tertiary" role="status">正在加载可信浏览器…</p>
      {:else if trustedError}<div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2"><p class="text-small text-nya-danger">{trustedError}</p><Button variant="ghost" size="sm" onclick={loadTrustedDevices}>重试</Button></div>
      {:else if !trustedDevicesEnabled}<p class="rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning">管理员已关闭可信浏览器功能，现有记录已撤销。</p>
      {:else if trustedDevices.length === 0}<p class="text-body text-nya-text-tertiary">暂无可信浏览器。完成登录 MFA 时可以选择信任当前浏览器。</p>
      {:else}<div class="divide-y divide-nya-divider">{#each trustedDevices as item}
        <article class="flex flex-col justify-between gap-3 py-4 sm:flex-row sm:items-center">
          <div class="flex min-w-0 items-start gap-3"><span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-success-soft"><ShieldCheck size={19} class="text-nya-success" /></span><div class="min-w-0">
            <p class="text-body-medium font-semibold text-nya-text-primary">{deviceLabel(item.user_agent)} {#if item.current}<Badge variant="success">当前浏览器</Badge>{/if}</p>
            <p class="mt-1 text-small text-nya-text-tertiary">IP {item.ip_address || '未知'} · 最近使用 {new Date(item.last_used_at).toLocaleString()}</p>
            <p class="mt-0.5 text-micro text-nya-text-tertiary">信任于 {new Date(item.created_at).toLocaleString()} · 截止 {new Date(item.expires_at).toLocaleString()}</p>
          </div></div>
          <Button variant="ghost" size="sm" onclick={() => requestDeviceAction({ kind: 'trusted', item })}>撤销信任</Button>
        </article>
      {/each}</div>{/if}
    </div>
  </section>

  <section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
    <div class="border-b border-nya-divider px-7 py-5"><h2 class="text-card-title text-nya-text-primary">登录历史</h2><p class="mt-1 text-body text-nya-text-secondary">仅显示你的登录成功、失败和登录 MFA 失败记录，不包含其他管理审计详情。</p></div>
    <div class="px-7 py-6">
      {#if historyLoading && loginHistory.length === 0}<p class="text-body text-nya-text-tertiary" role="status">正在加载登录历史…</p>
      {:else if historyError && loginHistory.length === 0}<div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2"><p class="text-small text-nya-danger">{historyError}</p><Button variant="ghost" size="sm" onclick={() => loadLoginHistory(1)}>重试</Button></div>
      {:else if loginHistory.length === 0}<p class="text-body text-nya-text-tertiary">暂无登录历史。</p>
      {:else}<div class="divide-y divide-nya-divider">{#each loginHistory as item}
        <article class="flex items-start gap-3 py-4">
          <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full {item.result === 'success' ? 'bg-nya-success-soft text-nya-success' : 'bg-nya-danger-soft text-nya-danger'}"><History size={18} /></span>
          <div class="min-w-0 flex-1"><div class="flex flex-wrap items-center gap-2"><p class="text-body-medium font-semibold text-nya-text-primary">{authenticationLabel(item)}</p><Badge variant={item.result === 'success' ? 'success' : 'danger'}>{item.result === 'success' ? '成功' : '失败'}</Badge></div>
            <p class="mt-1 text-small text-nya-text-tertiary">{new Date(item.created_at).toLocaleString()} · IP {item.ip_address || '未知'}</p>
            <p class="mt-0.5 truncate text-micro text-nya-text-tertiary" title={item.user_agent}>{item.user_agent || '未提供 User-Agent'}</p>
          </div>
        </article>
      {/each}</div>
      {#if historyError}<p class="mt-3 text-small text-nya-danger" role="alert">{historyError}</p>{/if}
      {#if historyPage < historyTotalPages}<div class="mt-4 flex justify-center"><Button variant="secondary" size="sm" loading={historyLoading} onclick={() => loadLoginHistory(historyPage + 1)}>加载更多</Button></div>{/if}
      {/if}
    </div>
  </section>
</div>

<ConfirmDialog
  bind:open={confirmOpen}
  title={actionTitle()}
  description={actionDescription()}
  confirmLabel={actionTitle()}
  error={actionError}
  onconfirm={runDeviceAction}
/>
