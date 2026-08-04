<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type Announcement } from '$lib/api';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import Pagination from '$lib/components/data-display/Pagination.svelte';
  import { AlertCircle, AlertTriangle, Info, Pin } from 'lucide-svelte';

  const pageSize = 20;
  let items = $state<Announcement[]>([]); let loading = $state(true); let error = $state(''); let currentPage = $state(1); let total = $state(0);
  async function load() { loading = true; error = ''; try { const result = await api.getAnnouncements(currentPage, pageSize); items = result.items || []; total = result.total; if (currentPage > Math.max(1, result.total_pages)) { currentPage = Math.max(1, result.total_pages); await load(); } } catch (cause) { error = cause instanceof Error ? cause.message : '公告加载失败'; } finally { loading = false; } }
  async function changePage(value: number) { currentPage = value; await load(); }
  function formatTime(value?: string) { return value ? new Intl.DateTimeFormat('zh-CN', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : ''; }
  onMount(load);
</script>

<div class="mx-auto max-w-4xl">
  <PageHeader title="公告中心" description="查看站点发布的长期通知、变更说明和重要提醒" />
  <ResourceState {loading} {error} empty={items.length === 0} emptyTitle="暂无公告" emptyDescription="已发布的公告会保留在这里" onretry={load}>
    <div>
      <div class="space-y-3">
      {#each items as item (item.id)}
        <a href={`/dashboard/announcements/${item.id}`} class="flex gap-4 rounded-nya-card border border-nya-border bg-nya-surface p-5 transition-colors hover:border-nya-primary/40 hover:bg-nya-surface-muted/50">
          <span class="mt-0.5 {item.severity === 'critical' ? 'text-nya-danger' : item.severity === 'warning' ? 'text-nya-warning' : 'text-nya-info'}">{#if item.severity === 'critical'}<AlertCircle size={20} />{:else if item.severity === 'warning'}<AlertTriangle size={20} />{:else}<Info size={20} />{/if}</span>
          <div class="min-w-0 flex-1"><div class="flex items-center gap-2"><h2 class="truncate font-semibold text-nya-text-primary">{item.title}</h2>{#if item.pinned}<Pin size={13} class="text-nya-primary" />{/if}{#if !item.read}<span class="h-2 w-2 rounded-full bg-nya-primary" aria-label="未读"></span>{/if}</div><p class="mt-1 line-clamp-2 text-body text-nya-text-secondary">{item.summary || '点击查看完整公告'}</p><time class="mt-2 block text-small text-nya-text-tertiary">{formatTime(item.published_at || item.updated_at)}</time></div>
        </a>
      {/each}
      </div>
      <Pagination bind:page={currentPage} {pageSize} {total} onchange={changePage} />
    </div>
  </ResourceState>
</div>
