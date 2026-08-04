<script lang="ts">
  import { goto, replaceState } from '$app/navigation';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import {
    api,
    type CommunicationSeverity,
    type MessageCenterItem,
    type MessageCenterKind,
    type MessageCenterReadState,
  } from '$lib/api';
  import { notificationCenterStore } from '$lib/notification-center';
  import { toast } from '$lib/toast';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Select from '$lib/components/ui/Select.svelte';
  import DateTimeRangePicker from '$lib/components/ui/DateTimeRangePicker.svelte';
  import Pagination from '$lib/components/data-display/Pagination.svelte';
  import {
    AlertCircle,
    AlertTriangle,
    Bell,
    Check,
    CheckCheck,
    ChevronRight,
    ExternalLink,
    Info,
    Megaphone,
    Pin,
    Search,
    X,
  } from 'lucide-svelte';

  type CenterTab = 'all' | 'notifications' | 'announcements';

  const pageSize = 20;
  const readOptions = [
    { value: 'all', label: '全部状态' },
    { value: 'unread', label: '仅未读' },
    { value: 'read', label: '已读' },
  ];
  const severityOptions = [
    { value: '', label: '全部级别' },
    { value: 'info', label: '信息' },
    { value: 'warning', label: '警告' },
    { value: 'critical', label: '重要' },
  ];

  let items = $state<MessageCenterItem[]>([]);
  let loading = $state(true);
  let error = $state('');
  let activeTab = $state<CenterTab>('all');
  let query = $state('');
  let readState = $state<MessageCenterReadState>('all');
  let severity = $state<'' | CommunicationSeverity>('');
  let from = $state('');
  let to = $state('');
  let currentPage = $state(1);
  let total = $state(0);
  let markingAll = $state(false);
  let counts = $derived($notificationCenterStore.value);
  let hasFilters = $derived(Boolean(query.trim() || readState !== 'all' || severity || from || to));
  let currentUnread = $derived(
    activeTab === 'notifications'
      ? counts.notification_count
      : activeTab === 'announcements'
        ? counts.announcement_count
        : counts.unread_count,
  );

  function tabKind(tab = activeTab): MessageCenterKind {
    if (tab === 'notifications') return 'notification';
    if (tab === 'announcements') return 'announcement';
    return 'all';
  }

  function validTab(value: string | null): CenterTab {
    return value === 'notifications' || value === 'announcements' ? value : 'all';
  }

  function validReadState(value: string | null): MessageCenterReadState {
    return value === 'read' || value === 'unread' ? value : 'all';
  }

  function validSeverity(value: string | null): '' | CommunicationSeverity {
    return value === 'info' || value === 'warning' || value === 'critical' ? value : '';
  }

  function localDateTime(value: string | null): string {
    if (!value) return '';
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return '';
    const local = new Date(parsed.getTime() - parsed.getTimezoneOffset() * 60_000);
    return local.toISOString().slice(0, 16);
  }

  function apiDateTime(value: string): string {
    return value ? new Date(value).toISOString() : '';
  }

  function initializeFromURL() {
    const params = $page.url.searchParams;
    activeTab = validTab(params.get('tab'));
    query = params.get('q') || '';
    readState = validReadState(params.get('read'));
    severity = validSeverity(params.get('severity'));
    from = localDateTime(params.get('from'));
    to = localDateTime(params.get('to'));
    const requestedPage = Number(params.get('page') || '1');
    currentPage = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1;
  }

  function syncURL() {
    const params = new URLSearchParams();
    if (activeTab !== 'all') params.set('tab', activeTab);
    if (query.trim()) params.set('q', query.trim());
    if (readState !== 'all') params.set('read', readState);
    if (severity) params.set('severity', severity);
    if (from) params.set('from', apiDateTime(from));
    if (to) params.set('to', apiDateTime(to));
    if (currentPage > 1) params.set('page', String(currentPage));
    const search = params.toString();
    replaceState(`${$page.url.pathname}${search ? `?${search}` : ''}`, {});
  }

  async function load() {
    loading = true;
    error = '';
    try {
      const result = await api.getMessages({
        page: currentPage,
        pageSize,
        kind: tabKind(),
        read: readState,
        severity,
        query: query.trim(),
        from: apiDateTime(from),
        to: apiDateTime(to),
      });
      items = result.items || [];
      total = result.total;
      if (currentPage > Math.max(1, result.total_pages)) {
        currentPage = Math.max(1, result.total_pages);
        syncURL();
        await load();
      }
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '消息中心加载失败';
    } finally {
      loading = false;
    }
  }

  async function selectTab(tab: CenterTab) {
    if (activeTab === tab) return;
    activeTab = tab;
    currentPage = 1;
    syncURL();
    await load();
  }

  async function applyFilters() {
    currentPage = 1;
    syncURL();
    await load();
  }

  async function clearFilters() {
    query = '';
    readState = 'all';
    severity = '';
    from = '';
    to = '';
    currentPage = 1;
    syncURL();
    await load();
  }

  async function changePage(value: number) {
    currentPage = value;
    syncURL();
    await load();
  }

  async function markRead(item: MessageCenterItem) {
    if (item.read) return;
    try {
      if (item.kind === 'announcement') await api.markAnnouncementRead(item.id);
      else await api.markNotificationRead(item.id);
      if (readState === 'unread') await load();
      else items = items.map((candidate) => candidate.kind === item.kind && candidate.id === item.id ? { ...candidate, read: true } : candidate);
      await notificationCenterStore.refresh().catch(() => {});
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : '已读状态保存失败');
    }
  }

  async function markAllRead() {
    markingAll = true;
    try {
      await api.markAllMessagesRead(tabKind());
      currentPage = 1;
      syncURL();
      await load();
      await notificationCenterStore.refresh().catch(() => {});
      toast.success('当前分类已全部标为已读');
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : '无法将当前分类标为已读');
    } finally {
      markingAll = false;
    }
  }

  async function openItem(item: MessageCenterItem) {
    await markRead(item);
    if (item.kind === 'announcement') {
      await goto(`/dashboard/announcements/${item.id}`);
    } else if (item.link_url) {
      if (item.link_url.startsWith('/')) await goto(item.link_url);
      else window.location.assign(item.link_url);
    }
  }

  function formatTime(value: string): string {
    return new Intl.DateTimeFormat('zh-CN', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
  }

  function tabCount(tab: CenterTab): number {
    if (tab === 'notifications') return counts.notification_count;
    if (tab === 'announcements') return counts.announcement_count;
    return counts.unread_count;
  }

  onMount(() => {
    const stop = notificationCenterStore.start();
    initializeFromURL();
    void load();
    return stop;
  });
</script>

<div class="mx-auto max-w-5xl">
  <PageHeader title="消息中心" description="集中查看站内消息和长期公告">
    {#snippet action()}
      <Button variant="secondary" size="sm" loading={markingAll} disabled={currentUnread === 0} onclick={markAllRead}>
        <CheckCheck size={15} />当前分类全部已读
      </Button>
    {/snippet}
  </PageHeader>

  <div class="mb-4 border-b border-nya-divider" role="tablist" aria-label="消息分类">
    <div class="flex gap-1">
      {#each [
        { value: 'all' as const, label: '全部' },
        { value: 'notifications' as const, label: '站内消息' },
        { value: 'announcements' as const, label: '公告' },
      ] as tab}
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === tab.value}
          onclick={() => void selectTab(tab.value)}
          class="relative flex min-h-11 items-center gap-2 px-3 text-body-medium transition-colors {activeTab === tab.value ? 'text-nya-primary' : 'text-nya-text-secondary hover:text-nya-text-primary'}"
        >
          {tab.label}
          {#if tabCount(tab.value) > 0}<span class="rounded-full bg-nya-primary-soft px-1.5 py-0.5 text-[10px] font-semibold leading-none text-nya-primary">{tabCount(tab.value) > 99 ? '99+' : tabCount(tab.value)}</span>{/if}
          {#if activeTab === tab.value}<span class="absolute inset-x-2 bottom-0 h-0.5 rounded-full bg-nya-primary"></span>{/if}
        </button>
      {/each}
    </div>
  </div>

  <form class="mb-5 rounded-nya-card border border-nya-border bg-nya-surface p-4" onsubmit={(event) => { event.preventDefault(); void applyFilters(); }}>
    <div class="grid gap-3 md:grid-cols-[minmax(220px,1fr)_160px_160px_auto] md:items-end">
      <Input label="搜索" bind:value={query} maxlength={200} placeholder="标题或正文内容" inputmode="search" ignorePasswordManagers />
      <Select label="阅读状态" bind:value={readState} options={readOptions} />
      <Select label="级别" bind:value={severity} options={severityOptions} />
      <Button type="submit" variant="secondary"><Search size={15} />筛选</Button>
    </div>
    <div class="mt-3 flex flex-col gap-3 lg:flex-row lg:items-end">
      <div class="min-w-0 flex-1"><DateTimeRangePicker id="message-center-time-range" label="发生时间" bind:from bind:to onconfirm={applyFilters} /></div>
      {#if hasFilters}<Button type="button" variant="ghost" onclick={clearFilters}><X size={15} />清除筛选</Button>{/if}
    </div>
  </form>

  <ResourceState {loading} {error} empty={items.length === 0} emptyTitle="没有匹配的消息" emptyDescription="调整分类或筛选条件后重试" onretry={load}>
    <div class="overflow-hidden rounded-nya-card border border-nya-border bg-nya-surface">
      {#each items as item (item.kind + ':' + item.id)}
        <article class="flex gap-3 border-b border-nya-divider p-4 last:border-b-0 {item.read ? '' : 'bg-nya-primary-softer/35'}">
          <span class="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-full {item.severity === 'critical' ? 'bg-nya-danger-soft text-nya-danger' : item.severity === 'warning' ? 'bg-nya-warning-soft text-nya-warning' : 'bg-nya-info-soft text-nya-info'}">
            {#if item.kind === 'announcement'}<Megaphone size={17} />{:else if item.severity === 'critical'}<AlertCircle size={17} />{:else if item.severity === 'warning'}<AlertTriangle size={17} />{:else}<Bell size={17} />{/if}
          </span>
          <div class="min-w-0 flex-1">
            <div class="flex flex-wrap items-start justify-between gap-2">
              <div class="flex min-w-0 items-center gap-2">
                <h2 class="truncate font-semibold text-nya-text-primary">{item.title}</h2>
                {#if item.pinned}<Pin size={13} class="shrink-0 text-nya-primary" aria-label="置顶" />{/if}
                {#if !item.read}<span class="h-2 w-2 shrink-0 rounded-full bg-nya-primary" aria-label="未读"></span>{/if}
              </div>
              <time class="shrink-0 text-small text-nya-text-tertiary">{formatTime(item.occurred_at)}</time>
            </div>
            {#if item.kind === 'notification'}
              <div class="message-markdown mt-1 line-clamp-3 text-body text-nya-text-secondary">{@html item.body_html || ''}</div>
            {:else}
              <p class="mt-1 line-clamp-3 text-body text-nya-text-secondary">{item.summary || '查看完整公告内容'}</p>
            {/if}
            <div class="mt-3 flex min-h-8 flex-wrap items-center gap-2">
              <span class="inline-flex h-6 items-center gap-1.5 rounded-full bg-nya-surface-muted px-2 text-small font-medium text-nya-text-secondary">
                {#if item.kind === 'announcement'}<Megaphone size={12} />公告{:else}<Bell size={12} />站内消息{/if}
              </span>
              {#if !item.read}
                <button type="button" onclick={() => void markRead(item)} class="inline-flex items-center gap-1 text-small text-nya-text-tertiary transition-colors hover:text-nya-primary">
                  <Check size={13} />标为已读
                </button>
              {/if}
              {#if item.kind === 'announcement' || item.link_url}
                <span class="ml-auto">
                  <Button variant="secondary" size="sm" onclick={() => void openItem(item)}>
                    查看详情
                    {#if item.kind === 'announcement' || item.link_url?.startsWith('/')}<ChevronRight size={14} />{:else}<ExternalLink size={13} />{/if}
                  </Button>
                </span>
              {/if}
            </div>
          </div>
        </article>
      {/each}
      <Pagination bind:page={currentPage} {pageSize} {total} onchange={changePage} />
    </div>
  </ResourceState>
</div>

<style>
  :global(.message-markdown p) { margin: 0; }
  :global(.message-markdown a) { color: var(--nya-primary); text-decoration: underline; }
</style>
