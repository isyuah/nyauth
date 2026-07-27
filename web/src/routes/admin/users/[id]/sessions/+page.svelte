<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type BrowserSession } from '$lib/api';
  import { useAdminUserDetailContext } from '$lib/admin-user-detail';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import { LogOut, MonitorSmartphone } from 'lucide-svelte';

  const detail = useAdminUserDetailContext();
  let sessions = $state<BrowserSession[]>([]);
  let loading = $state(true);
  let error = $state('');
  let notice = $state('');
  let confirmOpen = $state(false);
  let confirmError = $state('');

  function deviceLabel(userAgent = ''): string {
    const browser = /Edg\//.test(userAgent) ? 'Edge' : /Firefox\//.test(userAgent) ? 'Firefox' : /Chrome\//.test(userAgent) ? 'Chrome' : /Safari\//.test(userAgent) ? 'Safari' : '未知浏览器';
    const system = /Windows/.test(userAgent) ? 'Windows' : /Android/.test(userAgent) ? 'Android' : /iPhone|iPad/.test(userAgent) ? 'iOS' : /Mac OS/.test(userAgent) ? 'macOS' : /Linux/.test(userAgent) ? 'Linux' : '未知系统';
    return `${browser} · ${system}`;
  }

  async function loadSessions() {
    loading = true;
    error = '';
    try {
      sessions = await api.admin.getUserSessions(detail.userID);
    } catch (cause) {
      sessions = [];
      error = cause instanceof Error ? cause.message : '设备会话加载失败';
    } finally {
      loading = false;
    }
  }

  async function revokeSessions() {
    confirmError = '';
    try {
      const result = await api.admin.revokeUserSessions(detail.userID);
      sessions = [];
      notice = `已撤销 ${result.revoked} 个设备会话。`;
    } catch (cause) {
      confirmError = cause instanceof Error ? cause.message : '设备会话撤销失败';
      throw cause;
    }
  }

  onMount(loadSessions);
</script>

<svelte:head><title>用户会话 - Nya</title></svelte:head>

<section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
  <div class="mb-4 flex flex-wrap items-start justify-between gap-3"><div><div class="flex items-center gap-2"><MonitorSmartphone size={18} class="text-nya-primary" /><h2 class="text-card-title text-nya-text-primary">设备会话</h2></div><p class="mt-1 text-body text-nya-text-secondary">查看该用户当前仍有效的浏览器会话。</p></div>{#if !loading && sessions.length > 0}<Button variant="secondary" onclick={() => (confirmOpen = true)}><LogOut size={15} /> 全部撤销</Button>{/if}</div>
  {#if notice}<p class="mb-3 rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">{notice}</p>{/if}
  <ResourceState {loading} {error} empty={sessions.length === 0} emptyTitle="没有活动设备会话" emptyDescription="用户需要重新登录后才会出现会话。" onretry={loadSessions}>
    {#snippet children()}
      <div class="divide-y divide-nya-divider rounded-nya-sm border border-nya-border px-4">
        {#each sessions as item}
          <article class="py-4"><div class="flex flex-wrap items-center justify-between gap-3"><p class="font-medium text-nya-text-primary">{deviceLabel(item.user_agent)}</p><span class="font-mono text-micro text-nya-text-tertiary">{item.ip_address || 'IP 未知'}</span></div><p class="mt-1 text-small text-nya-text-tertiary">最后活动 {new Date(item.last_seen_at).toLocaleString()} · 认证于 {new Date(item.authenticated_at).toLocaleString()}</p><p class="mt-1 break-all text-micro text-nya-text-tertiary">{item.user_agent || '未提供 User-Agent'}</p></article>
        {/each}
      </div>
    {/snippet}
  </ResourceState>
</section>

<ConfirmDialog bind:open={confirmOpen} title="撤销全部设备会话" description="该用户需要在所有浏览器中重新登录。" confirmLabel="全部撤销" error={confirmError} onconfirm={revokeSessions} />
