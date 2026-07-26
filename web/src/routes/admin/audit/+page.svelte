<script lang="ts">
  import { goto } from '$app/navigation';
  import { page as pageStore } from '$app/stores';
  import { onMount } from 'svelte';
  import { api, type AuditLog } from '$lib/api';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import Pagination from '$lib/components/data-display/Pagination.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import FilterBar from '$lib/components/ui/FilterBar.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import Select from '$lib/components/ui/Select.svelte';
  import { Download, Filter } from 'lucide-svelte';

  const pageSize = 20;
  let logs = $state<AuditLog[]>([]);
  let total = $state(0);
  let currentPage = $state(Math.max(1, Number($pageStore.url.searchParams.get('page')) || 1));
  let event = $state($pageStore.url.searchParams.get('event') || '');
  let result = $state($pageStore.url.searchParams.get('result') || '');
  let risk = $state($pageStore.url.searchParams.get('risk') || '');
  let actor = $state($pageStore.url.searchParams.get('actor') || '');
  let target = $state($pageStore.url.searchParams.get('target') || '');
  let ip = $state($pageStore.url.searchParams.get('ip') || '');
  let from = $state($pageStore.url.searchParams.get('from') || '');
  let to = $state($pageStore.url.searchParams.get('to') || '');
  let loading = $state(true);
  let error = $state('');
  let currentURLKey = '';
  let listRequestVersion = 0;

  function toRFC3339(value: string): string | undefined {
    if (!value) return undefined;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
  }

  async function syncURL(): Promise<boolean> {
    const url = new URL($pageStore.url);
    const values = { event, result, risk, actor, target, ip, from, to };
    for (const [key, value] of Object.entries(values)) {
      if (value) url.searchParams.set(key, value);
      else url.searchParams.delete(key);
    }
    if (currentPage > 1) url.searchParams.set('page', String(currentPage));
    else url.searchParams.delete('page');
    const destination = `${url.pathname}${url.search}${url.hash}`;
    const current = `${$pageStore.url.pathname}${$pageStore.url.search}${$pageStore.url.hash}`;
    if (destination === current) return false;
    await goto(destination, { replaceState: true, noScroll: true, keepFocus: true });
    return true;
  }

  async function loadLogs() {
    const requestVersion = ++listRequestVersion;
    loading = true;
    error = '';
    try {
      const response = await api.admin.getAuditLogs({
        page: currentPage,
        pageSize,
        event,
        result,
        risk,
        actor,
        target,
        ip,
        from: toRFC3339(from),
        to: toRFC3339(to),
      });
      if (requestVersion !== listRequestVersion) return;
      logs = response.items;
      total = response.total;
      if (currentPage > Math.max(1, response.total_pages)) {
        currentPage = Math.max(1, response.total_pages);
        await syncURL();
        return;
      }
    } catch (cause) {
      if (requestVersion === listRequestVersion) error = cause instanceof Error ? cause.message : '审计日志加载失败';
    } finally {
      if (requestVersion === listRequestVersion) loading = false;
    }
  }

  function applyURLState(url: URL) {
    const key = `${url.pathname}${url.search}${url.hash}`;
    if (key === currentURLKey) return;
    currentURLKey = key;
    currentPage = Math.max(1, Number(url.searchParams.get('page')) || 1);
    event = url.searchParams.get('event') || '';
    result = url.searchParams.get('result') || '';
    risk = url.searchParams.get('risk') || '';
    actor = url.searchParams.get('actor') || '';
    target = url.searchParams.get('target') || '';
    ip = url.searchParams.get('ip') || '';
    from = url.searchParams.get('from') || '';
    to = url.searchParams.get('to') || '';
    void loadLogs();
  }

  async function applyFilters() {
    currentPage = 1;
    if (!(await syncURL())) await loadLogs();
  }

  async function changePage(nextPage: number) {
    currentPage = nextPage;
    await syncURL();
  }

  function exportLogs(format: 'ndjson' | 'cef') {
    const params = new URLSearchParams({ format, limit: '50000' });
    const values: Record<string, string | undefined> = {
      event,
      result,
      risk,
      actor,
      target,
      ip,
      from: toRFC3339(from),
      to: toRFC3339(to),
    };
    for (const [key, value] of Object.entries(values)) {
      if (value) params.set(key, value);
    }
    window.location.assign(`/api/admin/audit-logs/export?${params}`);
  }

  function resultVariant(value: string): 'success' | 'danger' | 'default' {
    return value === 'success' ? 'success' : value === 'failure' ? 'danger' : 'default';
  }

  function riskVariant(value: string): 'danger' | 'warning' | 'info' | 'default' {
    return value === 'high' || value === 'critical' ? 'danger' : value === 'medium' ? 'warning' : value === 'low' ? 'info' : 'default';
  }

  onMount(() => pageStore.subscribe(({ url }) => applyURLState(url)));
</script>

<svelte:head><title>审计日志 - Nya</title></svelte:head>

<PageHeader title="审计日志" description="按事件、结果、风险、操作者和目标追踪安全活动" />

<FilterBar label="审计日志筛选">
  {#snippet children()}
  <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
    <Input id="audit-event" label="事件" bind:value={event} placeholder="例如 user.login" />
    <Select id="audit-result" label="结果" bind:value={result} options={[{ value: '', label: '全部结果' }, { value: 'success', label: '成功' }, { value: 'failure', label: '失败' }]} />
    <Select id="audit-risk" label="风险" bind:value={risk} options={[{ value: '', label: '全部风险' }, { value: 'low', label: '低' }, { value: 'medium', label: '中' }, { value: 'high', label: '高' }, { value: 'critical', label: '严重' }]} />
    <Input id="audit-actor" label="操作者" bind:value={actor} placeholder="名称或 ID" />
    <Input id="audit-target" label="目标" bind:value={target} placeholder="类型或 ID" />
    <Input id="audit-ip" label="IP 地址" bind:value={ip} placeholder="例如 203.0.113.10" />
    <Input id="audit-from" label="开始时间" type="datetime-local" bind:value={from} />
    <Input id="audit-to" label="结束时间" type="datetime-local" bind:value={to} />
  </div>
  <div class="mt-3 flex flex-wrap items-center justify-between gap-2">
    <p class="text-small text-nya-text-tertiary">导出默认覆盖最近 24 小时，单次时间范围最多 31 天、最多 50,000 条。</p>
    <div class="flex flex-wrap justify-end gap-2">
      <Button variant="ghost" onclick={() => exportLogs('ndjson')}><Download size={15} /> NDJSON</Button>
      <Button variant="ghost" onclick={() => exportLogs('cef')}><Download size={15} /> CEF / SIEM</Button>
      <Button variant="secondary" onclick={applyFilters}><Filter size={15} /> 应用筛选</Button>
    </div>
  </div>
  {/snippet}
</FilterBar>

<ResourceState {loading} {error} empty={logs.length === 0} emptyTitle="没有匹配的审计记录" emptyDescription="调整筛选条件后重试。" onretry={loadLogs}>
  {#snippet children()}
    <div class="overflow-hidden rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
      <div class="overflow-x-auto">
        <table class="w-full">
          <thead><tr class="h-11 border-b border-nya-divider bg-nya-surface-subtle text-small font-semibold text-nya-text-secondary"><th scope="col" class="px-4 text-left">时间</th><th scope="col" class="px-4 text-left">事件</th><th scope="col" class="px-4 text-left">操作者</th><th scope="col" class="px-4 text-left">目标</th><th scope="col" class="px-4 text-left">结果</th><th scope="col" class="px-4 text-left">风险</th><th scope="col" class="px-4 text-left">IP</th></tr></thead>
          <tbody class="divide-y divide-nya-divider">
            {#each logs as log}
              <tr class="h-[52px] text-body hover:bg-nya-surface-muted"><td class="whitespace-nowrap px-4 text-small text-nya-text-tertiary">{new Date(log.created_at).toLocaleString()}</td><td class="px-4 font-mono text-small text-nya-text-primary">{log.event}</td><td class="px-4 text-nya-text-secondary">{log.actor_name || log.actor_id || '系统'}</td><td class="px-4 text-nya-text-secondary">{log.target_type && log.target_id ? `${log.target_type}:${log.target_id}` : log.target_id || '-'}</td><td class="px-4"><Badge variant={resultVariant(log.result)}>{log.result}</Badge></td><td class="px-4"><Badge variant={riskVariant(log.risk_level)}>{log.risk_level}</Badge></td><td class="px-4 font-mono text-small text-nya-text-tertiary">{log.ip_address || '-'}</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
      <Pagination bind:page={currentPage} {pageSize} {total} onchange={changePage} />
    </div>
  {/snippet}
</ResourceState>
