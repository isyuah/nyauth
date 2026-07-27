<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type AuditLog } from '$lib/api';
  import { useAdminUserDetailContext } from '$lib/admin-user-detail';
  import Pagination from '$lib/components/data-display/Pagination.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import { Activity } from 'lucide-svelte';

  const detail = useAdminUserDetailContext();
  const pageSize = 20;
  let items = $state<AuditLog[]>([]);
  let total = $state(0);
  let page = $state(1);
  let loading = $state(true);
  let error = $state('');

  async function loadActivity() {
    loading = true;
    error = '';
    try {
      const result = await api.admin.getUserActivity(detail.userID, page, pageSize);
      items = result.items;
      total = result.total;
    } catch (cause) {
      items = [];
      total = 0;
      error = cause instanceof Error ? cause.message : '用户活动加载失败';
    } finally {
      loading = false;
    }
  }

  async function changePage(next: number) {
    page = next;
    await loadActivity();
  }

  onMount(loadActivity);
</script>

<svelte:head><title>用户活动 - Nya</title></svelte:head>

<section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
  <div class="mb-4 flex items-center gap-2"><Activity size={18} class="text-nya-primary" /><div><h2 class="text-card-title text-nya-text-primary">审计活动</h2><p class="mt-1 text-body text-nya-text-secondary">只展示该用户作为明确 actor 或明确 user target 的事件。</p></div></div>
  <ResourceState {loading} {error} empty={items.length === 0} emptyTitle="暂无用户活动" emptyDescription="没有找到与该用户直接关联的审计事件。" onretry={loadActivity}>
    {#snippet children()}
      <div class="overflow-x-auto rounded-nya-sm border border-nya-border">
        <table class="w-full">
          <thead><tr class="h-10 border-b border-nya-divider bg-nya-surface-subtle text-small text-nya-text-secondary"><th class="px-3 text-left">时间</th><th class="px-3 text-left">事件</th><th class="px-3 text-left">Actor</th><th class="px-3 text-left">Target</th><th class="px-3 text-left">结果</th><th class="px-3 text-left">来源</th></tr></thead>
          <tbody class="divide-y divide-nya-divider">
            {#each items as item}
              <tr class="align-top"><td class="whitespace-nowrap px-3 py-3 text-small text-nya-text-tertiary">{new Date(item.created_at).toLocaleString()}</td><td class="px-3 py-3 font-mono text-small text-nya-text-primary">{item.event}</td><td class="px-3 py-3 text-small"><p>{item.actor_name || '系统'}</p>{#if item.actor_id}<p class="mt-0.5 font-mono text-micro text-nya-text-tertiary">{item.actor_id}</p>{/if}</td><td class="px-3 py-3 text-small"><p>{item.target_type || '-'}</p>{#if item.target_id}<p class="mt-0.5 font-mono text-micro text-nya-text-tertiary">{item.target_id}</p>{/if}</td><td class="px-3 py-3"><Badge variant={item.result === 'success' ? 'success' : 'danger'}>{item.result}</Badge><p class="mt-1 text-micro text-nya-text-tertiary">{item.risk_level}</p></td><td class="px-3 py-3 text-small"><p class="font-mono">{item.ip_address || '-'}</p><p class="mt-0.5 max-w-xs truncate text-micro text-nya-text-tertiary" title={item.user_agent || ''}>{item.user_agent || '未提供 User-Agent'}</p></td></tr>
            {/each}
          </tbody>
        </table>
      </div>
      <Pagination bind:page {pageSize} {total} onchange={changePage} />
    {/snippet}
  </ResourceState>
</section>
