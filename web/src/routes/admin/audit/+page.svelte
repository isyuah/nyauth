<script lang="ts">
  import { goto } from '$app/navigation';
  import { page as pageStore } from '$app/stores';
  import { onMount } from 'svelte';
  import {
    api,
    buildAuditLogExportURL,
    type AuditLog,
    type AuditLogFilters,
    type AuditLogOptions,
  } from '$lib/api';
  import AuditDetailsDrawer from '$lib/components/admin/AuditDetailsDrawer.svelte';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import Pagination from '$lib/components/data-display/Pagination.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import FilterBar from '$lib/components/ui/FilterBar.svelte';
  import FormField from '$lib/components/ui/FormField.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import Select from '$lib/components/ui/Select.svelte';
  import { Download, Eye, Filter, X } from 'lucide-svelte';

  type FilterKey = 'event' | 'result' | 'risk' | 'actor' | 'target' | 'subjectUserId' | 'targetType' | 'targetId' | 'ip' | 'from' | 'to';
  type ActiveFilter = { key: FilterKey; label: string; value: string };

  const pageSize = 20;
  const quickRanges = [
    { label: '最近 1 小时', hours: 1 },
    { label: '最近 24 小时', hours: 24 },
    { label: '最近 7 天', hours: 24 * 7 },
    { label: '最近 30 天', hours: 24 * 30 },
  ];
  const resultLabels: Record<string, string> = { success: '成功', failure: '失败' };
  const riskLabels: Record<string, string> = { low: '低', medium: '中', high: '高', critical: '严重' };
  const targetTypeLabels: Record<string, string> = {
    client: '客户端',
    identity: '外部身份',
    invite: '邀请',
    mail_config: '邮件配置',
    mail_runtime: '邮件运行状态',
    oauth_consent: 'OAuth 授权确认',
    oauth_endpoint: 'OAuth 端点',
    oauth_grant: 'OAuth 授权类型',
    passkey: 'Passkey',
    provider: 'Provider',
    registration: '注册',
    session: '会话',
    settings: '设置',
    user: '用户',
  };

  let logs = $state<AuditLog[]>([]);
  let total = $state(0);
  let currentPage = $state(Math.max(1, Number($pageStore.url.searchParams.get('page')) || 1));
  let event = $state($pageStore.url.searchParams.get('event') || '');
  let result = $state($pageStore.url.searchParams.get('result') || '');
  let risk = $state($pageStore.url.searchParams.get('risk') || '');
  let actor = $state($pageStore.url.searchParams.get('actor') || '');
  let target = $state($pageStore.url.searchParams.get('target') || '');
  let subjectUserId = $state($pageStore.url.searchParams.get('subject_user_id') || '');
  let targetType = $state($pageStore.url.searchParams.get('target_type') || '');
  let targetId = $state($pageStore.url.searchParams.get('target_id') || '');
  let ip = $state($pageStore.url.searchParams.get('ip') || '');
  let from = $state(toLocalDateTimeInput($pageStore.url.searchParams.get('from') || ''));
  let to = $state(toLocalDateTimeInput($pageStore.url.searchParams.get('to') || ''));
  let filterOptions = $state<AuditLogOptions>({ events: [], results: [], risks: [], target_types: [] });
  let optionsError = $state('');
  let loading = $state(true);
  let error = $state('');
  let selectedLog = $state<AuditLog | null>(null);
  let detailsOpen = $state(false);
  let currentURLKey = '';
  let listRequestVersion = 0;

  let resultOptions = $derived(selectOptions(filterOptions.results, result, '全部结果', resultLabels));
  let riskOptions = $derived(selectOptions(filterOptions.risks, risk, '全部风险', riskLabels));
  let targetTypeOptions = $derived(selectOptions(filterOptions.target_types, targetType, '全部目标类型', targetTypeLabels));
  let activeFilters = $derived(([
    { key: 'event', label: '事件', value: event.trim() },
    { key: 'result', label: '结果', value: result.trim() },
    { key: 'risk', label: '风险', value: risk.trim() },
    { key: 'actor', label: '操作者（模糊）', value: actor.trim() },
    { key: 'target', label: '目标（模糊）', value: target.trim() },
    { key: 'subjectUserId', label: '主体用户 ID', value: subjectUserId.trim() },
    { key: 'targetType', label: '目标类型', value: targetType.trim() },
    { key: 'targetId', label: '目标 ID', value: targetId.trim() },
    { key: 'ip', label: 'IP 地址', value: ip.trim() },
    { key: 'from', label: '开始时间', value: from ? formatFilterDate(from) : '' },
    { key: 'to', label: '结束时间', value: to ? formatFilterDate(to) : '' },
  ] as ActiveFilter[]).filter((item) => item.value));

  function selectOptions(values: string[], current: string, emptyLabel: string, labels: Record<string, string>) {
    const uniqueValues = Array.from(new Set([...(current ? [current] : []), ...values]));
    return [{ value: '', label: emptyLabel }, ...uniqueValues.map((value) => ({ value, label: labels[value] || value }))];
  }

  function toRFC3339(value: string): string | undefined {
    if (!value) return undefined;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
  }

  function toLocalDateTimeInput(value: string): string {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '';
    const pad = (part: number) => String(part).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function formatFilterDate(value: string): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN');
  }

  function currentFilters(): AuditLogFilters {
    return {
      page: currentPage,
      pageSize,
      event: event.trim() || undefined,
      result: result.trim() || undefined,
      risk: risk.trim() || undefined,
      actor: actor.trim() || undefined,
      target: target.trim() || undefined,
      subjectUserId: subjectUserId.trim() || undefined,
      targetType: targetType.trim() || undefined,
      targetId: targetId.trim() || undefined,
      ip: ip.trim() || undefined,
      from: toRFC3339(from),
      to: toRFC3339(to),
    };
  }

  async function syncURL(): Promise<boolean> {
    const url = new URL($pageStore.url);
    const values: Record<string, string | undefined> = {
      event: event.trim() || undefined,
      result: result.trim() || undefined,
      risk: risk.trim() || undefined,
      actor: actor.trim() || undefined,
      target: target.trim() || undefined,
      subject_user_id: subjectUserId.trim() || undefined,
      target_type: targetType.trim() || undefined,
      target_id: targetId.trim() || undefined,
      ip: ip.trim() || undefined,
      from: toRFC3339(from),
      to: toRFC3339(to),
    };
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
      const response = await api.admin.getAuditLogs(currentFilters());
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

  async function loadOptions() {
    optionsError = '';
    try {
      filterOptions = await api.admin.getAuditLogOptions();
    } catch (cause) {
      optionsError = cause instanceof Error ? cause.message : '筛选选项加载失败';
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
    subjectUserId = url.searchParams.get('subject_user_id') || '';
    targetType = url.searchParams.get('target_type') || '';
    targetId = url.searchParams.get('target_id') || '';
    ip = url.searchParams.get('ip') || '';
    from = toLocalDateTimeInput(url.searchParams.get('from') || '');
    to = toLocalDateTimeInput(url.searchParams.get('to') || '');
    void loadLogs();
  }

  async function applyFilters() {
    currentPage = 1;
    if (!(await syncURL())) await loadLogs();
  }

  async function setQuickRange(hours: number) {
    const end = new Date();
    const start = new Date(end.getTime() - hours * 60 * 60 * 1000);
    from = toLocalDateTimeInput(start.toISOString());
    to = toLocalDateTimeInput(end.toISOString());
    await applyFilters();
  }

  async function removeFilter(key: FilterKey) {
    if (key === 'event') event = '';
    else if (key === 'result') result = '';
    else if (key === 'risk') risk = '';
    else if (key === 'actor') actor = '';
    else if (key === 'target') target = '';
    else if (key === 'subjectUserId') subjectUserId = '';
    else if (key === 'targetType') targetType = '';
    else if (key === 'targetId') targetId = '';
    else if (key === 'ip') ip = '';
    else if (key === 'from') from = '';
    else if (key === 'to') to = '';
    await applyFilters();
  }

  async function clearFilters() {
    event = '';
    result = '';
    risk = '';
    actor = '';
    target = '';
    subjectUserId = '';
    targetType = '';
    targetId = '';
    ip = '';
    from = '';
    to = '';
    await applyFilters();
  }

  async function changePage(nextPage: number) {
    currentPage = nextPage;
    await syncURL();
  }

  function exportLogs(format: 'ndjson' | 'cef') {
    window.location.assign(buildAuditLogExportURL(currentFilters(), format));
  }

  function openDetails(log: AuditLog) {
    selectedLog = log;
    detailsOpen = true;
  }

  function resultVariant(value: string): 'success' | 'danger' | 'default' {
    return value === 'success' ? 'success' : value === 'failure' ? 'danger' : 'default';
  }

  function riskVariant(value: string): 'danger' | 'warning' | 'info' | 'default' {
    return value === 'high' || value === 'critical' ? 'danger' : value === 'medium' ? 'warning' : value === 'low' ? 'info' : 'default';
  }

  onMount(() => {
    const unsubscribe = pageStore.subscribe(({ url }) => applyURLState(url));
    void loadOptions();
    return unsubscribe;
  });
</script>

<svelte:head><title>审计日志 - Nya</title></svelte:head>

<PageHeader title="审计日志" description="按事件、结果、风险、操作者和目标追踪安全活动" />

<FilterBar label="审计日志筛选">
  {#snippet children()}
    <div class="mb-3 flex flex-wrap items-center gap-2" aria-label="快捷时间范围">
      <span class="text-small font-medium text-nya-text-secondary">快捷范围</span>
      {#each quickRanges as range}
        <Button size="sm" variant="ghost" onclick={() => setQuickRange(range.hours)}>{range.label}</Button>
      {/each}
    </div>

    <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
      <FormField id="audit-event" label="事件">
        {#snippet children()}
          <input id="audit-event" list="audit-event-options" bind:value={event} placeholder="例如 user.login" autocomplete="off" class="h-[38px] w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 text-body text-nya-text-primary placeholder-nya-text-tertiary transition-all hover:border-nya-border-strong focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24" />
          <datalist id="audit-event-options">{#each filterOptions.events as option}<option value={option}></option>{/each}</datalist>
        {/snippet}
      </FormField>
      <Select id="audit-result" label="结果" bind:value={result} options={resultOptions} />
      <Select id="audit-risk" label="风险" bind:value={risk} options={riskOptions} />
      <Input id="audit-actor" label="操作者（模糊）" bind:value={actor} placeholder="名称或 ID" />
      <Input id="audit-target" label="目标（模糊）" bind:value={target} placeholder="类型或 ID" />
      <Input id="audit-subject-user-id" label="主体用户 ID（精确）" bind:value={subjectUserId} placeholder="用户 UUID" mono />
      <Select id="audit-target-type" label="目标类型（精确）" bind:value={targetType} options={targetTypeOptions} />
      <Input id="audit-target-id" label="目标 ID（精确）" bind:value={targetId} placeholder="完整目标 ID" mono />
      <Input id="audit-ip" label="IP 地址" bind:value={ip} placeholder="例如 203.0.113.10" mono />
      <Input id="audit-from" label="开始时间" type="datetime-local" bind:value={from} />
      <Input id="audit-to" label="结束时间" type="datetime-local" bind:value={to} />
    </div>

    {#if optionsError}
      <p class="mt-3 text-small text-nya-warning" role="alert">筛选选项暂时不可用：{optionsError}。仍可手动输入筛选条件。</p>
    {/if}

    {#if activeFilters.length > 0}
      <div class="mt-3 flex flex-wrap items-center gap-2" aria-label="已启用筛选">
        {#each activeFilters as filter}
          <button type="button" onclick={() => removeFilter(filter.key)} aria-label={`移除筛选：${filter.label}：${filter.value}`} class="inline-flex max-w-full items-center gap-1.5 rounded-nya-full border border-nya-border bg-nya-surface px-2.5 py-1 text-small text-nya-text-secondary hover:border-nya-primary hover:text-nya-primary">
            <span class="truncate">{filter.label}：{filter.value}</span><X size={13} aria-hidden="true" />
          </button>
        {/each}
        <button type="button" onclick={clearFilters} class="px-2 py-1 text-small font-medium text-nya-primary hover:underline">清除全部筛选</button>
      </div>
    {/if}

    <div class="mt-3 flex flex-wrap items-center justify-between gap-2">
      <p class="text-small text-nya-text-tertiary">导出单次时间范围最多 31 天、最多 50,000 条，并复用当前全部筛选条件。</p>
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
          <thead><tr class="h-11 border-b border-nya-divider bg-nya-surface-subtle text-small font-semibold text-nya-text-secondary"><th scope="col" class="px-4 text-left">时间</th><th scope="col" class="px-4 text-left">事件</th><th scope="col" class="px-4 text-left">操作者</th><th scope="col" class="px-4 text-left">目标</th><th scope="col" class="px-4 text-left">结果</th><th scope="col" class="px-4 text-left">风险</th><th scope="col" class="px-4 text-left">IP</th><th scope="col" class="px-4 text-right">详情</th></tr></thead>
          <tbody class="divide-y divide-nya-divider">
            {#each logs as log}
              <tr class="h-[52px] text-body hover:bg-nya-surface-muted"><td class="whitespace-nowrap px-4 text-small text-nya-text-tertiary">{new Date(log.created_at).toLocaleString()}</td><td class="px-4 font-mono text-small text-nya-text-primary">{log.event}</td><td class="px-4 text-nya-text-secondary">{log.actor_name || log.actor_id || '系统'}</td><td class="px-4 text-nya-text-secondary">{log.target_type && log.target_id ? `${log.target_type}:${log.target_id}` : log.target_id || '-'}</td><td class="px-4"><Badge variant={resultVariant(log.result)}>{log.result}</Badge></td><td class="px-4"><Badge variant={riskVariant(log.risk_level)}>{log.risk_level}</Badge></td><td class="px-4 font-mono text-small text-nya-text-tertiary">{log.ip_address || '-'}</td><td class="px-4 text-right"><button type="button" onclick={() => openDetails(log)} aria-label={`查看审计详情：${log.event}`} class="inline-flex rounded-lg p-2 text-nya-text-tertiary hover:bg-nya-primary-soft hover:text-nya-primary"><Eye size={16} aria-hidden="true" /></button></td></tr>
            {/each}
          </tbody>
        </table>
      </div>
      <Pagination bind:page={currentPage} {pageSize} {total} onchange={changePage} />
    </div>
  {/snippet}
</ResourceState>

<AuditDetailsDrawer bind:open={detailsOpen} log={selectedLog} />
