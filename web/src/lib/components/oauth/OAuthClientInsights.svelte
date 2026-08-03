<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type OAuthClient, type OAuthClientDiagnostic, type OAuthClientInsights as Insights } from '$lib/api';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import OAuthClientLogo from './OAuthClientLogo.svelte';
  import TrendChart from '$lib/components/data-display/TrendChart.svelte';
  import Pagination from '$lib/components/data-display/Pagination.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Select from '$lib/components/ui/Select.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import { Activity, ArrowLeft, CircleCheck, CircleX, ShieldCheck, Users } from 'lucide-svelte';

  let { clientID, administrator = false }: { clientID: string; administrator?: boolean } = $props();
  let client = $state<OAuthClient | null>(null);
  let insights = $state<Insights | null>(null);
  let diagnostics = $state<OAuthClientDiagnostic[]>([]);
  let days = $state(30);
  let page = $state(1);
  const pageSize = 15;
  let total = $state(0);
  let flow = $state('');
  let stage = $state('');
  let reason = $state('');
  let loading = $state(true);
  let diagnosticLoading = $state(false);
  let error = $state('');
  let diagnosticError = $state('');

  const flowOptions = [
    { value: '', label: '全部流程' }, { value: 'authorization_code', label: '授权码' },
    { value: 'client_credentials', label: 'Client Credentials' }, { value: 'refresh_token', label: 'Refresh Token' },
    { value: 'device_authorization', label: '设备授权' },
  ];
  const stageOptions = [
    { value: '', label: '全部阶段' }, { value: 'authorization', label: '授权请求' }, { value: 'consent', label: '用户确认' },
    { value: 'token', label: 'Token 签发' }, { value: 'device_authorization', label: '设备代码申请' },
    { value: 'device_verification', label: '设备确认' },
  ];
  const reasonLabels: Record<string, string> = {
    invalid_request: '请求参数无效', invalid_client: '客户端认证失败', redirect_uri_mismatch: '回调地址不匹配',
    invalid_state: 'State 无效', grant_not_allowed: '未允许此 Grant', invalid_scope: 'Scope 无效', invalid_pkce: 'PKCE 无效',
    invalid_nonce: 'Nonce 无效', access_denied: '应用访问被拒绝', client_changed: '应用配置已变化',
    invalid_scope_selection: '可选权限选择无效', invalid_or_expired_code: '授权码无效或过期',
    code_binding_validation: '授权码绑定校验失败', scope_no_longer_allowed: 'Scope 已不再允许',
    claim_no_longer_allowed: 'Claim 已不再允许', invalid_subject: '用户主体无效', inactive_subject: '用户已不可用',
    authorization_inactive: '授权已失效', token_issuance_failed: 'Token 签发失败', id_token_issuance_failed: 'ID Token 签发失败',
    code_reuse: '授权码重复使用', code_reuse_revocation_failed: '授权码重用处置失败', invalid_refresh: 'Refresh Token 无效',
    refresh_reuse: 'Refresh Token 重用', expired_token: '设备代码已过期', user_denied: '用户拒绝授权',
    service_paused: '服务能力已暂停', rate_limited: '请求过于频繁', temporarily_unavailable: '依赖暂时不可用', server_error: '服务内部错误',
  };
  let reasonOptions = $derived([{ value: '', label: '全部原因' }, ...Object.entries(reasonLabels).map(([value, label]) => ({ value, label }))]);
  let backHref = $derived(administrator ? '/admin/clients' : '/dashboard/apps');
  let labels = $derived((insights?.trend || []).map((point) => point.day.slice(5)));
  let trendSeries = $derived([
    { key: 'success', label: '成功', values: (insights?.trend || []).map((point) => point.success), color: 'mint' as const },
    { key: 'failure', label: '失败', values: (insights?.trend || []).map((point) => point.failure), color: 'danger' as const },
  ]);

  function clientAPI() {
    return administrator ? api.admin : api.my;
  }

  async function loadSummary() {
    loading = true;
    error = '';
    try {
      [client, insights] = await Promise.all([clientAPI().getClient(clientID), clientAPI().getClientInsights(clientID, days)]);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '应用数据加载失败';
    } finally { loading = false; }
  }

  async function loadDiagnostics() {
    diagnosticLoading = true;
    diagnosticError = '';
    try {
      const result = await clientAPI().getClientDiagnostics(clientID, { flow, stage, reason, page, pageSize });
      diagnostics = Array.isArray(result.items) ? result.items.map((item) => ({ ...item, scopes: Array.isArray(item.scopes) ? item.scopes : [] })) : [];
      total = result.total;
    } catch (cause) {
      diagnosticError = cause instanceof Error ? cause.message : '失败诊断加载失败';
    } finally { diagnosticLoading = false; }
  }

  async function changeDays(value: number) { days = value; await loadSummary(); }
  async function applyDiagnosticFilters() { page = 1; await loadDiagnostics(); }
  async function changePage(value: number) { page = value; await loadDiagnostics(); }

  onMount(async () => { await Promise.all([loadSummary(), loadDiagnostics()]); });
</script>

<svelte:head><title>{client?.name || '应用数据'} - Nya</title></svelte:head>

<a href={backHref} class="mb-4 inline-flex items-center gap-1 text-small text-nya-text-secondary transition-colors hover:text-nya-primary"><ArrowLeft size={15} /> 返回应用列表</a>
<PageHeader title="应用数据与诊断" description="查看 OAuth 流程结果、活动授权和经过脱敏的失败原因">
  {#snippet action()}
    {#if client}<div class="flex min-w-0 items-center gap-3"><OAuthClientLogo name={client.name} url={client.logo_url} size="sm" /><div class="min-w-0 text-right"><p class="truncate text-body-medium font-semibold text-nya-text-primary">{client.name}</p><code class="block max-w-52 truncate text-micro text-nya-text-tertiary">{client.id}</code></div></div>{/if}
  {/snippet}
</PageHeader>

<ResourceState {loading} {error} onretry={loadSummary}>
  {#snippet children()}
    {#if insights}
      <div class="mb-5 flex justify-end gap-1" aria-label="统计时间范围">
        {#each [7, 30, 90] as option}<Button variant={days === option ? 'primary' : 'ghost'} size="sm" onclick={() => changeDays(option)}>{option} 天</Button>{/each}
      </div>
      <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div class="flex h-[104px] items-center gap-4 rounded-nya-md border border-nya-border bg-nya-surface p-5"><span class="flex h-10 w-10 items-center justify-center rounded-nya-sm bg-nya-success-soft text-nya-success"><CircleCheck size={20} /></span><div><p class="text-small text-nya-text-tertiary">成功操作</p><p class="text-stat-value tabular-nums text-nya-text-primary">{insights.totals.success}</p></div></div>
        <div class="flex h-[104px] items-center gap-4 rounded-nya-md border border-nya-border bg-nya-surface p-5"><span class="flex h-10 w-10 items-center justify-center rounded-nya-sm bg-nya-danger-soft text-nya-danger"><CircleX size={20} /></span><div><p class="text-small text-nya-text-tertiary">失败操作</p><p class="text-stat-value tabular-nums text-nya-text-primary">{insights.totals.failure}</p></div></div>
        <div class="flex h-[104px] items-center gap-4 rounded-nya-md border border-nya-border bg-nya-surface p-5"><span class="flex h-10 w-10 items-center justify-center rounded-nya-sm bg-nya-blue-soft text-nya-blue"><Activity size={20} /></span><div><p class="text-small text-nya-text-tertiary">成功率</p><p class="text-stat-value tabular-nums text-nya-text-primary">{insights.totals.success_rate === null ? '—' : `${insights.totals.success_rate}%`}</p></div></div>
        <div class="flex h-[104px] items-center gap-4 rounded-nya-md border border-nya-border bg-nya-surface p-5"><span class="flex h-10 w-10 items-center justify-center rounded-nya-sm bg-nya-primary-soft text-nya-primary"><Users size={20} /></span><div><p class="text-small text-nya-text-tertiary">活动授权</p><p class="text-stat-value tabular-nums text-nya-text-primary">{insights.active_authorizations}</p></div></div>
      </div>
      <section class="mt-5 border-y border-nya-border py-5">
        <div class="mb-4 flex flex-wrap items-end justify-between gap-3"><div><h2 class="text-card-title text-nya-text-primary">流程趋势</h2><p class="mt-1 text-small text-nya-text-secondary">按 UTC 日期聚合；设备轮询中的 authorization_pending 不计为失败。</p></div><Badge variant="info">UTC</Badge></div>
        <TrendChart {labels} series={trendSeries} ariaLabel={`${client?.name || '应用'} OAuth 成功与失败趋势`} emptyText="所选时间范围内暂无 OAuth 操作" />
      </section>
    {/if}
  {/snippet}
</ResourceState>

<section class="mt-6">
  <div class="mb-3"><h2 class="text-card-title text-nya-text-primary">失败诊断</h2><p class="mt-1 text-small text-nya-text-secondary">保留 90 天。不会记录授权码、Token、Secret、PKCE verifier 或原始用户信息。</p></div>
  <div class="grid gap-3 border-y border-nya-border bg-nya-surface-muted/40 py-4 sm:grid-cols-3 xl:grid-cols-[1fr_1fr_1fr_auto]">
    <Select label="流程" bind:value={flow} options={flowOptions} />
    <Select label="阶段" bind:value={stage} options={stageOptions} />
    <Select label="原因" bind:value={reason} options={reasonOptions} />
    <div class="flex items-end"><Button variant="secondary" onclick={applyDiagnosticFilters} loading={diagnosticLoading}>应用筛选</Button></div>
  </div>
  {#if diagnosticError}<div class="mt-3 flex items-center justify-between gap-3 bg-nya-danger-soft px-3 py-2 text-small text-nya-danger"><span>{diagnosticError}</span><Button variant="ghost" size="sm" onclick={loadDiagnostics}>重试</Button></div>
  {:else if diagnosticLoading && diagnostics.length === 0}<p class="py-8 text-center text-body text-nya-text-tertiary" role="status">正在加载失败诊断…</p>
  {:else if diagnostics.length === 0}<p class="py-8 text-center text-body text-nya-text-tertiary">没有符合条件的失败记录。</p>
  {:else}
    <div class="divide-y divide-nya-divider">
      {#each diagnostics as item (item.id)}
        <article class="grid gap-3 py-4 lg:grid-cols-[190px_1fr_auto] lg:items-start">
          <div><p class="text-small text-nya-text-primary">{new Date(item.occurred_at).toLocaleString()}</p><p class="mt-1 font-mono text-micro text-nya-text-tertiary">{item.request_id || '无 Request ID'}</p></div>
          <div class="min-w-0"><div class="flex flex-wrap items-center gap-2"><Badge variant="danger">{reasonLabels[item.reason] || item.reason}</Badge><Badge variant="default">{flowOptions.find((entry) => entry.value === item.flow)?.label || item.flow}</Badge><span class="text-small text-nya-text-secondary">{stageOptions.find((entry) => entry.value === item.stage)?.label || item.stage}</span></div>{#if item.redirect_uri}<p class="mt-2 truncate font-mono text-micro text-nya-text-tertiary" title={item.redirect_uri}>{item.redirect_uri}</p>{/if}</div>
          <div class="flex max-w-72 flex-wrap gap-1">{#each item.scopes as scope}<Badge variant="info">{scope}</Badge>{/each}</div>
        </article>
      {/each}
    </div>
    <Pagination bind:page {pageSize} {total} onchange={changePage} />
  {/if}
</section>
