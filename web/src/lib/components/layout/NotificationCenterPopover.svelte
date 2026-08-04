<script lang="ts">
  import { goto } from '$app/navigation';
  import { Popover, Tabs } from 'bits-ui';
  import { onMount } from 'svelte';
  import {
    AlertTriangle,
    Bell,
    Check,
    ChevronRight,
    Inbox,
    LoaderCircle,
    Megaphone,
    RefreshCw,
    ShieldAlert,
  } from 'lucide-svelte';
  import { api, type Announcement, type CommunicationSeverity, type UserNotification } from '$lib/api';
  import { notificationCenterStore } from '$lib/notification-center';
  import { toast } from '$lib/toast';

  type CenterTab = 'all' | 'notifications' | 'announcements';
  type PreviewEntry = {
    key: string;
    kind: 'notification' | 'announcement';
    id: string;
    title: string;
    summary: string;
    severity: CommunicationSeverity;
    timestamp: string;
    unread: boolean;
    href: string;
  };

  const previewLimit = 6;
  let open = $state(false);
  let activeTab = $state<CenterTab>('all');
  let notifications = $state<UserNotification[]>([]);
  let announcements = $state<Announcement[]>([]);
  let loading = $state(false);
  let error = $state('');
  let loaded = $state(false);
  let wasOpen = false;
  let loadGeneration = 0;

  let counts = $derived($notificationCenterStore.value);
  let unreadCount = $derived(counts.unread_count);

  onMount(() => notificationCenterStore.start());

  $effect(() => {
    if (open && !wasOpen) {
      activeTab = 'all';
      void loadPreview();
    }
    wasOpen = open;
  });

  function notificationEntry(item: UserNotification): PreviewEntry {
    return {
      key: `notification:${item.id}`,
      kind: 'notification',
      id: item.id,
      title: item.title,
      summary: plainTextPreview(item.body_html),
      severity: item.severity,
      timestamp: item.created_at,
      unread: !item.read_at,
      href: item.link_url || '/dashboard/messages?tab=notifications',
    };
  }

  function announcementEntry(item: Announcement): PreviewEntry {
    return {
      key: `announcement:${item.id}`,
      kind: 'announcement',
      id: item.id,
      title: item.title,
      summary: item.summary || '查看完整公告内容',
      severity: item.severity,
      timestamp: item.published_at || item.updated_at,
      unread: !item.read,
      href: `/dashboard/announcements/${item.id}`,
    };
  }

  function visibleEntries(): PreviewEntry[] {
    const messageEntries = notifications.map(notificationEntry);
    const announcementEntries = announcements.map(announcementEntry);
    if (activeTab === 'notifications') return messageEntries.slice(0, previewLimit);
    if (activeTab === 'announcements') return announcementEntries.slice(0, previewLimit);
    return [...messageEntries, ...announcementEntries]
      .sort((left, right) => new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime())
      .slice(0, previewLimit);
  }

  async function loadPreview() {
    const generation = ++loadGeneration;
    loading = true;
    error = '';
    try {
      const [messagePage, announcementPage] = await Promise.all([
        api.getNotifications(1, previewLimit, false),
        api.getAnnouncements(1, previewLimit),
      ]);
      if (generation !== loadGeneration) return;
      notifications = messagePage.items || [];
      announcements = announcementPage.items || [];
      loaded = true;
    } catch (cause) {
      if (generation !== loadGeneration) return;
      error = cause instanceof Error ? cause.message : '消息预览加载失败';
    } finally {
      if (generation === loadGeneration) loading = false;
    }
  }

  async function markRead(entry: PreviewEntry) {
    if (!entry.unread) return;
    try {
      if (entry.kind === 'notification') {
        await api.markNotificationRead(entry.id);
        notifications = notifications.map((item) => item.id === entry.id ? { ...item, read_at: new Date().toISOString() } : item);
      } else {
        await api.markAnnouncementRead(entry.id);
        announcements = announcements.map((item) => item.id === entry.id ? { ...item, read: true } : item);
      }
      await notificationCenterStore.refresh().catch(() => {});
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : '已读状态保存失败');
      throw cause;
    }
  }

  async function openEntry(entry: PreviewEntry) {
    try {
      await markRead(entry);
    } catch {
      // Reading the content remains available when the receipt cannot be stored.
    }
    open = false;
    if (entry.href.startsWith('/')) {
      await goto(entry.href);
    } else {
      window.location.assign(entry.href);
    }
  }

  function formatTime(value: string): string {
    const date = new Date(value);
    const today = new Date();
    if (date.toDateString() === today.toDateString()) {
      return new Intl.DateTimeFormat('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false }).format(date);
    }
    return new Intl.DateTimeFormat('zh-CN', { month: 'numeric', day: 'numeric' }).format(date);
  }

  function countLabel(value: number): string {
    return value > 99 ? '99+' : String(value);
  }

  function plainTextPreview(value: string): string {
    return value
      .replace(/<br\s*\/?>/gi, ' ')
      .replace(/<\/p>/gi, ' ')
      .replace(/<[^>]+>/g, '')
      .replace(/&nbsp;/gi, ' ')
      .replace(/&amp;/gi, '&')
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/&quot;/gi, '"')
      .replace(/&#39;/gi, "'")
      .replace(/\s+/g, ' ')
      .trim();
  }
</script>

<Popover.Root bind:open>
  <Popover.Trigger
    type="button"
    class="relative flex h-9 w-9 items-center justify-center rounded-nya-md text-nya-text-tertiary transition-colors hover:bg-nya-surface-muted hover:text-nya-text-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"
    aria-label={unreadCount > 0 ? `消息中心，${unreadCount} 条未读` : '消息中心'}
  >
    <Bell size={18} />
    {#if unreadCount > 0}
      <span class="absolute -right-0.5 -top-0.5 flex min-h-4 min-w-4 items-center justify-center rounded-full bg-nya-danger px-1 text-[10px] font-semibold leading-4 text-white">{countLabel(unreadCount)}</span>
    {/if}
  </Popover.Trigger>

  <Popover.Portal>
    <Popover.Content
      sideOffset={8}
      align="end"
      role="dialog"
      aria-label="消息中心预览"
      class="z-[90] flex max-h-[min(620px,calc(100vh-5rem))] w-[min(390px,calc(100vw-1.5rem))] flex-col overflow-hidden rounded-nya-md border border-nya-border bg-nya-surface shadow-nya-popup outline-none"
    >
      <div class="flex items-center justify-between border-b border-nya-divider px-4 py-3">
        <div>
          <h2 class="font-semibold text-nya-text-primary">消息中心</h2>
          <p class="mt-0.5 text-small text-nya-text-tertiary">{unreadCount > 0 ? `${unreadCount} 条内容尚未阅读` : '没有未读内容'}</p>
        </div>
        <button type="button" onclick={loadPreview} disabled={loading} aria-label="刷新消息预览" class="flex h-8 w-8 items-center justify-center rounded-nya-sm text-nya-text-tertiary transition-colors hover:bg-nya-surface-muted hover:text-nya-primary disabled:opacity-50">
          <RefreshCw size={15} class={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      <Tabs.Root value={activeTab} onValueChange={(value) => (activeTab = value as CenterTab)}>
        <Tabs.List class="grid grid-cols-3 border-b border-nya-divider px-2" aria-label="消息中心分类">
          <Tabs.Trigger value="all" class="flex min-w-0 items-center justify-center gap-1.5 border-b-2 border-transparent px-2 py-2.5 text-small font-medium text-nya-text-secondary transition-colors hover:text-nya-text-primary data-[state=active]:border-nya-primary data-[state=active]:text-nya-primary">
            全部 <span class="rounded-full bg-nya-surface-muted px-1.5 py-0.5 text-[10px] leading-none">{countLabel(counts.unread_count)}</span>
          </Tabs.Trigger>
          <Tabs.Trigger value="notifications" class="flex min-w-0 items-center justify-center gap-1.5 border-b-2 border-transparent px-2 py-2.5 text-small font-medium text-nya-text-secondary transition-colors hover:text-nya-text-primary data-[state=active]:border-nya-primary data-[state=active]:text-nya-primary">
            站内消息 <span class="rounded-full bg-nya-surface-muted px-1.5 py-0.5 text-[10px] leading-none">{countLabel(counts.notification_count)}</span>
          </Tabs.Trigger>
          <Tabs.Trigger value="announcements" class="flex min-w-0 items-center justify-center gap-1.5 border-b-2 border-transparent px-2 py-2.5 text-small font-medium text-nya-text-secondary transition-colors hover:text-nya-text-primary data-[state=active]:border-nya-primary data-[state=active]:text-nya-primary">
            公告 <span class="rounded-full bg-nya-surface-muted px-1.5 py-0.5 text-[10px] leading-none">{countLabel(counts.announcement_count)}</span>
          </Tabs.Trigger>
        </Tabs.List>
      </Tabs.Root>

      <div class="min-h-0 flex-1 overflow-y-auto" aria-live="polite">
        {#if loading && !loaded}
          <div class="flex min-h-56 items-center justify-center text-nya-text-tertiary"><LoaderCircle size={22} class="animate-spin" /><span class="sr-only">正在加载消息预览</span></div>
        {:else if error}
          <div class="flex min-h-56 flex-col items-center justify-center px-6 text-center" role="alert">
            <AlertTriangle size={24} class="text-nya-warning" />
            <p class="mt-2 text-body text-nya-text-secondary">{error}</p>
            <button type="button" onclick={loadPreview} class="mt-3 text-small font-medium text-nya-primary hover:underline">重新加载</button>
          </div>
        {:else if visibleEntries().length === 0}
          <div class="flex min-h-56 flex-col items-center justify-center px-6 text-center">
            <Inbox size={28} class="text-nya-text-disabled" />
            <p class="mt-3 font-medium text-nya-text-primary">暂无内容</p>
            <p class="mt-1 text-small text-nya-text-tertiary">此分类中的消息会显示在这里</p>
          </div>
        {:else}
          <div class="divide-y divide-nya-divider">
            {#each visibleEntries() as entry (entry.key)}
              <article class="group flex gap-2 px-3 py-3 transition-colors hover:bg-nya-surface-muted/70 {entry.unread ? 'bg-nya-primary-softer/30' : ''}">
                <button type="button" onclick={() => openEntry(entry)} class="flex min-w-0 flex-1 gap-3 text-left focus:outline-none">
                  <span class="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full {entry.severity === 'critical' ? 'bg-nya-danger-soft text-nya-danger' : entry.severity === 'warning' ? 'bg-nya-warning-soft text-nya-warning' : 'bg-nya-primary-soft text-nya-primary'}">
                    {#if entry.kind === 'announcement'}<Megaphone size={15} />{:else if entry.severity === 'warning' || entry.severity === 'critical'}<ShieldAlert size={15} />{:else}<Bell size={15} />{/if}
                  </span>
                  <span class="min-w-0 flex-1">
                    <span class="flex items-start justify-between gap-2">
                      <span class="truncate text-body-medium text-nya-text-primary">{entry.title}</span>
                      <time class="shrink-0 text-[11px] text-nya-text-tertiary">{formatTime(entry.timestamp)}</time>
                    </span>
                    <span class="mt-1 line-clamp-2 text-small leading-5 text-nya-text-secondary">{entry.summary}</span>
                    <span class="mt-1.5 inline-flex items-center gap-1 text-[11px] text-nya-text-tertiary">{entry.kind === 'announcement' ? '公告' : '站内消息'} <ChevronRight size={11} /></span>
                  </span>
                </button>
                {#if entry.unread}
                  <button type="button" onclick={() => void markRead(entry).catch(() => {})} aria-label={`将“${entry.title}”标为已读`} title="标为已读" class="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-nya-text-tertiary opacity-70 transition-all hover:bg-nya-primary-soft hover:text-nya-primary group-hover:opacity-100 focus:opacity-100 focus:outline-none focus:ring-2 focus:ring-nya-primary/24">
                    <Check size={14} />
                  </button>
                {/if}
              </article>
            {/each}
          </div>
        {/if}
      </div>

      <div class="flex items-center justify-between gap-2 border-t border-nya-divider bg-nya-surface-soft px-3 py-2.5">
        {#if activeTab === 'notifications'}
          <a href="/dashboard/messages?tab=notifications" onclick={() => (open = false)} class="ml-auto inline-flex items-center gap-1 text-small font-medium text-nya-primary hover:underline">打开站内消息 <ChevronRight size={13} /></a>
        {:else if activeTab === 'announcements'}
          <a href="/dashboard/messages?tab=announcements" onclick={() => (open = false)} class="ml-auto inline-flex items-center gap-1 text-small font-medium text-nya-primary hover:underline">打开公告中心 <ChevronRight size={13} /></a>
        {:else}
          <a href="/dashboard/messages" onclick={() => (open = false)} class="ml-auto inline-flex items-center gap-1 text-small font-medium text-nya-primary hover:underline">打开完整消息中心 <ChevronRight size={13} /></a>
        {/if}
      </div>
    </Popover.Content>
  </Popover.Portal>
</Popover.Root>
