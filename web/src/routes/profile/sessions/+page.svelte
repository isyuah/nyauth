<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { api, type BrowserSession } from '$lib/api';
  import { sessionStore } from '$lib/stores';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import { LogOut, MonitorSmartphone } from 'lucide-svelte';

  type SessionAction = { kind: 'single'; session: BrowserSession } | { kind: 'others' } | null;

  let browserSessions = $state<BrowserSession[]>([]);
  let loading = $state(true);
  let error = $state('');
  let sessionAction = $state<SessionAction>(null);
  let confirmOpen = $state(false);
  let actionError = $state('');

  let otherSessionCount = $derived(browserSessions.filter((item) => !item.current).length);

  function deviceLabel(userAgent = ''): string {
    const browser = /Edg\//.test(userAgent) ? 'Edge' : /Firefox\//.test(userAgent) ? 'Firefox' : /Chrome\//.test(userAgent) ? 'Chrome' : /Safari\//.test(userAgent) ? 'Safari' : '未知浏览器';
    const system = /Windows/.test(userAgent) ? 'Windows' : /Android/.test(userAgent) ? 'Android' : /iPhone|iPad/.test(userAgent) ? 'iOS' : /Mac OS/.test(userAgent) ? 'macOS' : /Linux/.test(userAgent) ? 'Linux' : '未知系统';
    return `${browser} · ${system}`;
  }

  async function loadSessions() {
    loading = true;
    error = '';
    try {
      browserSessions = await api.getMySessions();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '设备会话加载失败';
    } finally {
      loading = false;
    }
  }

  onMount(loadSessions);

  function requestSessionAction(action: SessionAction) {
    sessionAction = action;
    actionError = '';
    confirmOpen = true;
  }

  async function runSessionAction() {
    const action = sessionAction;
    if (!action) return;
    actionError = '';
    try {
      if (action.kind === 'others') {
        await api.revokeOtherSessions();
        browserSessions = browserSessions.filter((item) => item.current);
        return;
      }
      await api.revokeMySession(action.session.id);
      if (action.session.current) {
        sessionStore.clear();
        await goto('/login');
      } else {
        browserSessions = browserSessions.filter((item) => item.id !== action.session.id);
      }
    } catch (cause) {
      actionError = cause instanceof Error ? cause.message : '无法撤销会话';
      throw cause;
    }
  }
</script>

<svelte:head><title>设备会话 - Nya</title></svelte:head>

<section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
  <div class="flex items-center justify-between gap-4 border-b border-nya-divider px-7 py-5">
    <div>
      <h2 class="text-card-title text-nya-text-primary">设备会话</h2>
      <p class="mt-1 text-body text-nya-text-secondary">查看已登录设备，并立即撤销不认识的会话。</p>
    </div>
    {#if otherSessionCount > 0}<Button variant="secondary" size="sm" onclick={() => requestSessionAction({ kind: 'others' })}><LogOut size={14} /> 退出其他设备</Button>{/if}
  </div>
  <div class="px-7 py-6">
    {#if loading}
      <p class="text-body text-nya-text-tertiary" role="status">正在加载设备会话…</p>
    {:else if error}
      <div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2"><p class="text-small text-nya-danger">{error}</p><Button variant="ghost" size="sm" onclick={loadSessions}>重试</Button></div>
    {:else if browserSessions.length === 0}
      <p class="text-body text-nya-text-tertiary">暂无可显示的设备会话。</p>
    {:else}
      <div class="divide-y divide-nya-divider">
        {#each browserSessions as item}
          <div class="flex flex-col justify-between gap-3 py-4 sm:flex-row sm:items-center">
            <div class="flex min-w-0 items-start gap-3">
              <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-primary-soft"><MonitorSmartphone size={19} class="text-nya-primary" /></span>
              <div class="min-w-0">
                <p class="text-body-medium font-semibold text-nya-text-primary">{deviceLabel(item.user_agent)} {#if item.current}<Badge variant="success">当前设备</Badge>{/if}</p>
                <p class="mt-1 text-small text-nya-text-tertiary">IP {item.ip_address || '未知'} · 最后活动 {new Date(item.last_seen_at).toLocaleString()}</p>
                <p class="mt-0.5 text-micro text-nya-text-tertiary">空闲截止 {new Date(item.session_idle_expires_at).toLocaleString()} · 绝对截止 {new Date(item.session_expires_at).toLocaleString()}</p>
                <p class="mt-0.5 truncate text-micro text-nya-text-tertiary" title={item.user_agent}>{item.user_agent || '未提供 User-Agent'}</p>
              </div>
            </div>
            <Button variant="ghost" size="sm" onclick={() => requestSessionAction({ kind: 'single', session: item })}>{item.current ? '退出此设备' : '撤销会话'}</Button>
          </div>
        {/each}
      </div>
    {/if}
  </div>
</section>

<ConfirmDialog
  bind:open={confirmOpen}
  title={sessionAction?.kind === 'others' ? '退出其他设备' : sessionAction?.session.current ? '退出当前设备' : '撤销设备会话'}
  description={sessionAction?.kind === 'others' ? `将撤销其他 ${otherSessionCount} 个设备会话，当前设备保持登录。` : sessionAction?.session.current ? '当前会话会立即结束，你需要重新登录。' : '该设备会立即退出登录。'}
  confirmLabel={sessionAction?.kind === 'others' ? '退出其他设备' : '撤销会话'}
  error={actionError}
  onconfirm={runSessionAction}
/>
