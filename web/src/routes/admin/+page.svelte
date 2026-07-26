<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type DashboardStats, type OIDCDiscoveryDocument, type RecentLogin, type SystemStatus } from '$lib/api';
  import { sessionStore } from '$lib/stores';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import StatusBadge from '$lib/components/data-display/StatusBadge.svelte';
  import TrendChart from '$lib/components/data-display/TrendChart.svelte';
  import RegistrationMailStats from '$lib/components/admin/RegistrationMailStats.svelte';
  import { Activity, AlertTriangle, AppWindow, Database, KeyRound, LogIn, Server, Users } from 'lucide-svelte';

  let stats = $state<DashboardStats | null>(null);
  let recentLogins = $state<RecentLogin[]>([]);
  let trendData = $state<number[]>([]);
  let trendLabels = $state<string[]>([]);
  let systemStatus = $state<SystemStatus | null>(null);
  let discovery = $state<OIDCDiscoveryDocument | null>(null);
  let loading = $state(true);
  let error = $state('');
  let systemError = $state('');

  let currentUser = $derived($sessionStore.session?.user);
  let loginSeries = $derived([{
    key: 'successful_logins',
    label: '登录次数',
    values: trendData,
    color: 'primary' as const,
    fill: true,
  }]);
  let statCards = $derived(stats ? [
    { label: '用户总数', value: stats.user_count, icon: Users, bg: 'var(--nya-primary-soft)', fg: 'var(--nya-primary)' },
    { label: '应用总数', value: stats.app_count, icon: AppWindow, bg: 'var(--nya-blue-soft)', fg: 'var(--nya-blue)' },
    { label: '7 日登录次数', value: stats.login_count_7d, icon: LogIn, bg: 'var(--nya-mint-soft)', fg: 'var(--nya-mint)' },
    { label: '活跃会话', value: stats.active_sessions, icon: Activity, bg: 'var(--nya-orange-soft)', fg: 'var(--nya-orange)' },
    { label: '7 日失败登录', value: stats.failed_logins_7d, icon: AlertTriangle, bg: 'var(--nya-pink-soft)', fg: 'var(--nya-pink)' },
  ] : []);

  async function loadDashboard() {
    loading = true;
    error = '';
    systemError = '';
    try {
      const [statsResult, trend, logins] = await Promise.all([
        api.admin.getStats(),
        api.admin.getLoginTrend(7),
        api.admin.getRecentLogins(5),
      ]);
      stats = statsResult;
      trendData = trend.values;
      trendLabels = trend.labels;
      recentLogins = logins;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '仪表盘加载失败';
    }

    const [statusResult, discoveryResult] = await Promise.allSettled([
      api.admin.getSystemStatus(),
      api.discovery(),
    ]);
    if (statusResult.status === 'fulfilled') systemStatus = statusResult.value;
    else {
      systemStatus = null;
      systemError = statusResult.reason instanceof Error ? statusResult.reason.message : '系统状态不可用';
    }
    if (discoveryResult.status === 'fulfilled') discovery = discoveryResult.value;
    else discovery = null;
    loading = false;
  }

  onMount(loadDashboard);
</script>

<svelte:head><title>仪表盘 - Nya</title></svelte:head>

<PageHeader
  title="仪表盘"
  description={currentUser ? `欢迎回来，${currentUser.display_name || currentUser.username}` : '查看认证服务的真实运行数据'}
/>

<ResourceState {loading} {error} empty={!stats} emptyTitle="暂无统计数据" onretry={loadDashboard}>
  {#snippet children()}
    {#if stats}
      <div class="grid gap-4 [grid-template-columns:repeat(auto-fit,minmax(180px,1fr))]">
        {#each statCards as card}
          <section class="grid min-h-28 grid-cols-[48px_1fr] items-center gap-3.5 rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
            <span class="flex h-[46px] w-[46px] items-center justify-center rounded-full" style="background: {card.bg};"><card.icon size={22} color={card.fg} /></span>
            <div><p class="text-body text-nya-text-tertiary">{card.label}</p><p class="text-[28px] font-bold tabular-nums text-nya-text-primary">{card.value.toLocaleString()}</p></div>
          </section>
        {/each}
      </div>

      <div class="mt-4 grid gap-4 xl:grid-cols-2">
        <section class="min-h-[310px] rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="mb-4 flex items-center justify-between"><h2 class="text-card-title text-nya-text-primary">登录趋势</h2><span class="rounded-nya-pill bg-nya-surface-muted px-2 py-0.5 text-small text-nya-text-tertiary">7 天</span></div>
          <TrendChart
            labels={trendLabels}
            series={loginSeries}
            height="220px"
            ariaLabel="过去 7 天登录趋势"
            emptyText="暂无登录趋势数据"
          />
        </section>

        <section class="min-h-[310px] rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="mb-4 flex items-center justify-between"><h2 class="text-card-title text-nya-text-primary">最近登录</h2><span class="text-small text-nya-text-tertiary">最近 {recentLogins.length} 条</span></div>
          {#if recentLogins.length > 0}
            <div class="divide-y divide-nya-divider">
              {#each recentLogins as entry}
                <div class="grid min-h-[52px] grid-cols-[minmax(100px,1fr)_auto_auto] items-center gap-3 text-small">
                  <div class="flex min-w-0 items-center gap-2.5"><span class="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-nya-primary-soft font-semibold text-nya-primary">{entry.username.slice(0, 1).toUpperCase()}</span><span class="truncate font-medium text-nya-text-primary">{entry.username}</span></div>
                  <span class={entry.result === 'success' ? 'text-nya-success' : 'text-nya-danger'}>{entry.result === 'success' ? '成功' : '失败'}</span>
                  <span class="text-nya-text-tertiary">{entry.time}</span>
                </div>
              {/each}
            </div>
          {:else}
            <div class="flex h-56 flex-col items-center justify-center text-nya-text-tertiary"><Users size={30} class="mb-2 opacity-50" /><p class="text-body">尚无登录记录</p></div>
          {/if}
        </section>
      </div>

      <RegistrationMailStats {stats} />

      <div class="mt-4 grid gap-4 lg:grid-cols-2">
        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="mb-4 flex items-center gap-2"><KeyRound size={18} class="text-nya-primary" /><h2 class="text-card-title text-nya-text-primary">OIDC 配置</h2></div>
          {#if discovery}
            <dl class="space-y-3 text-small">
              <div class="grid grid-cols-[90px_1fr] gap-3"><dt class="text-nya-text-tertiary">Issuer</dt><dd class="break-all font-mono text-nya-text-primary">{discovery.issuer}</dd></div>
              <div class="grid grid-cols-[90px_1fr] gap-3"><dt class="text-nya-text-tertiary">Discovery</dt><dd><a href="/.well-known/openid-configuration" target="_blank" rel="noreferrer" class="text-nya-primary hover:underline">查看配置文档</a></dd></div>
              <div class="grid grid-cols-[90px_1fr] gap-3"><dt class="text-nya-text-tertiary">JWKS</dt><dd><a href={discovery.jwks_uri} target="_blank" rel="noreferrer" class="break-all text-nya-primary hover:underline">{discovery.jwks_uri}</a></dd></div>
            </dl>
          {:else}
            <p class="text-body text-nya-text-tertiary">Discovery 文档当前不可用。</p>
          {/if}
        </section>

        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="mb-4 flex items-center gap-2"><Server size={18} class="text-nya-primary" /><h2 class="text-card-title text-nya-text-primary">系统状态</h2></div>
          {#if systemStatus}
            <dl class="space-y-3 text-small">
              <div class="flex items-center justify-between gap-3"><dt class="text-nya-text-tertiary">版本 / 总体状态</dt><dd class="flex items-center gap-2"><span class="font-mono text-nya-text-primary">{systemStatus.version}</span><StatusBadge status={systemStatus.status} /></dd></div>
              <div class="flex items-center justify-between gap-3"><dt class="text-nya-text-tertiary">Schema</dt><dd class="flex items-center gap-2"><span class="font-mono">{systemStatus.schema.version} / {systemStatus.schema.required_version}</span><StatusBadge status={systemStatus.schema.status} /></dd></div>
              <div class="flex items-center justify-between gap-3"><dt class="flex items-center gap-1.5 text-nya-text-tertiary"><Database size={14} /> PostgreSQL</dt><dd class="flex items-center gap-2"><span>{systemStatus.services.postgresql.latency_ms} ms</span><StatusBadge status={systemStatus.services.postgresql.status} /></dd></div>
              <div class="flex items-center justify-between gap-3"><dt class="text-nya-text-tertiary">Redis</dt><dd class="flex items-center gap-2"><span>{systemStatus.services.redis.latency_ms} ms</span><StatusBadge status={systemStatus.services.redis.status} /></dd></div>
              <div class="flex items-center justify-between gap-3"><dt class="text-nya-text-tertiary">JWK</dt><dd class="flex items-center gap-2"><span>{systemStatus.services.jwk.latency_ms} ms</span><StatusBadge status={systemStatus.services.jwk.status} /></dd></div>
              <div class="flex items-center justify-between gap-3"><dt class="text-nya-text-tertiary">活动签名密钥</dt>{#if systemStatus.active_signing_key}<dd class="flex min-w-0 items-center gap-2"><span class="max-w-[160px] truncate font-mono" title={systemStatus.active_signing_key.kid}>{systemStatus.active_signing_key.kid}</span><StatusBadge status={systemStatus.active_signing_key.status} /></dd>{:else}<dd class="text-nya-text-tertiary">无</dd>{/if}</div>
              <div class="flex items-center justify-between gap-3"><dt class="text-nya-text-tertiary">Provider 快照</dt><dd class="flex items-center gap-2"><span>revision {systemStatus.services.providers.snapshot_revision}</span><StatusBadge status={systemStatus.services.providers.status} /></dd></div>
            </dl>
          {:else}
            <div class="rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning" role="status">系统状态不可用{systemError ? `：${systemError}` : ''}</div>
          {/if}
        </section>
      </div>

      <section class="mt-4 rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
        <div class="flex items-start gap-3">
          <AlertTriangle size={18} class={stats.failed_logins_7d > 0 ? 'mt-0.5 text-nya-warning' : 'mt-0.5 text-nya-success'} />
          <div><h2 class="text-card-title text-nya-text-primary">安全摘要</h2><p class="mt-1 text-body text-nya-text-secondary">{stats.failed_logins_7d > 0 ? `过去 7 天记录到 ${stats.failed_logins_7d} 次失败登录，请结合审计日志核查。` : '过去 7 天没有记录到失败登录。'}</p></div>
        </div>
      </section>
    {/if}
  {/snippet}
</ResourceState>
