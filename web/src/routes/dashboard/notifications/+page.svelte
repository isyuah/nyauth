<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type UserNotification } from '$lib/api';
  import { notificationCenterStore } from '$lib/notification-center';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Pagination from '$lib/components/data-display/Pagination.svelte';
  import { toast } from '$lib/toast';
  import { Bell, CheckCheck, ExternalLink, ShieldAlert } from 'lucide-svelte';

  const pageSize = 20;
  let items = $state<UserNotification[]>([]);
  let loading = $state(true);
  let error = $state('');
  let unreadOnly = $state(false);
  let markingAll = $state(false);
  let currentPage = $state(1);
  let total = $state(0);

  async function load() {
    loading = true; error = '';
    try {
      const result = await api.getNotifications(currentPage, pageSize, unreadOnly);
      items = result.items || []; total = result.total;
      if (currentPage > Math.max(1, result.total_pages)) { currentPage = Math.max(1, result.total_pages); await load(); }
    }
    catch (cause) { error = cause instanceof Error ? cause.message : '站内消息加载失败'; }
    finally { loading = false; }
  }

  async function markRead(item: UserNotification) {
    try {
      if (!item.read_at) await api.markNotificationRead(item.id);
      item.read_at = item.read_at || new Date().toISOString();
      if (unreadOnly) await load(); else items = [...items];
      await notificationCenterStore.refresh().catch(() => {});
    } catch (cause) { toast.error(cause instanceof Error ? cause.message : '消息已读状态保存失败'); }
  }

  async function markAllRead() {
    markingAll = true;
    try { await api.markAllNotificationsRead(); currentPage = 1; await load(); await notificationCenterStore.refresh().catch(() => {}); }
    catch (cause) { toast.error(cause instanceof Error ? cause.message : '无法将消息全部标为已读'); }
    finally { markingAll = false; }
  }

  async function setUnreadOnly(value: boolean) { unreadOnly = value; currentPage = 1; await load(); }
  async function changePage(value: number) { currentPage = value; await load(); }

  function formatTime(value: string) { return new Intl.DateTimeFormat('zh-CN', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)); }
  onMount(load);
</script>

<div class="mx-auto max-w-4xl">
  <PageHeader title="站内消息" description="账户安全和 OAuth 应用相关的个人通知">
    {#snippet action()}
      <Button variant="secondary" size="sm" loading={markingAll} onclick={markAllRead}><CheckCheck size={15} />全部已读</Button>
    {/snippet}
  </PageHeader>
  <div class="mb-4 flex gap-2">
    <button type="button" onclick={() => void setUnreadOnly(false)} class="rounded-nya-sm px-3 py-1.5 text-small {unreadOnly ? 'text-nya-text-secondary hover:bg-nya-surface-muted' : 'bg-nya-primary-soft text-nya-primary'}">全部</button>
    <button type="button" onclick={() => void setUnreadOnly(true)} class="rounded-nya-sm px-3 py-1.5 text-small {unreadOnly ? 'bg-nya-primary-soft text-nya-primary' : 'text-nya-text-secondary hover:bg-nya-surface-muted'}">仅未读</button>
  </div>
  <ResourceState {loading} {error} empty={items.length === 0} emptyTitle="暂无站内消息" emptyDescription="重要的账户和应用事件会显示在这里" onretry={load}>
    <div class="overflow-hidden rounded-nya-card border border-nya-border bg-nya-surface">
      {#each items as item (item.id)}
        <article class="flex gap-3 border-b border-nya-divider p-4 last:border-b-0 {item.read_at ? '' : 'bg-nya-primary-softer/40'}">
          <div class="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-full {item.severity === 'critical' || item.severity === 'warning' ? 'bg-nya-warning-soft text-nya-warning' : 'bg-nya-primary-soft text-nya-primary'}">
            {#if item.severity === 'critical' || item.severity === 'warning'}<ShieldAlert size={17} />{:else}<Bell size={17} />{/if}
          </div>
          <div class="min-w-0 flex-1">
            <div class="flex flex-wrap items-start justify-between gap-2"><h2 class="font-semibold text-nya-text-primary">{item.title}</h2><time class="text-small text-nya-text-tertiary">{formatTime(item.created_at)}</time></div>
            <div class="notification-markdown mt-1 text-body text-nya-text-secondary">{@html item.body_html}</div>
            <div class="mt-3 flex items-center gap-3">
              {#if item.link_url}<a href={item.link_url} onclick={() => void markRead(item)} class="inline-flex items-center gap-1 text-small font-medium text-nya-primary hover:underline">查看详情 <ExternalLink size={13} /></a>{/if}
              {#if !item.read_at}<button type="button" onclick={() => void markRead(item)} class="text-small text-nya-text-tertiary hover:text-nya-primary">标为已读</button>{/if}
            </div>
          </div>
        </article>
      {/each}
    </div>
    <Pagination bind:page={currentPage} {pageSize} {total} onchange={changePage} />
  </ResourceState>
</div>

<style>:global(.notification-markdown p){margin:0}:global(.notification-markdown a){color:var(--nya-primary);text-decoration:underline}</style>
