<script lang="ts">
  import { api } from '$lib/api';
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { Users, AppWindow, LogIn, Activity, AlertTriangle } from 'lucide-svelte';
  import TrendChart from '$lib/components/data-display/TrendChart.svelte';

  let stats = $state({
    userCount: 0,
    appCount: 0,
    loginCount7d: 0,
    activeSessions: 0,
    failedLogins7d: 0,
  });
  let recentLogins = $state<Array<{user: string; role: string; result: string; ip: string; time: string; avatar: string}>>([]);
  let trendData = $state<number[]>([]);
  let trendLabels = $state<string[]>([]);
  let loading = $state(true);
  let error = $state('');

  onMount(async () => {
    try {
      const [s, trend, logins] = await Promise.all([
        api.admin.getStats(),
        api.admin.getLoginTrend(7),
        api.admin.getRecentLogins(5),
      ]);
      stats = {
        userCount: Number(s?.user_count) || 0,
        appCount: Number(s?.app_count) || 0,
        loginCount7d: Number(s?.login_count_7d) || 0,
        activeSessions: Number(s?.active_sessions) || 0,
        failedLogins7d: Number(s?.failed_logins_7d) || 0,
      };
      trendData = (trend?.values || []).map(Number);
      trendLabels = trend?.labels || [];
      recentLogins = (logins || []).map((l: any) => ({
        user: l.username || '-',
        role: '用户',
        result: l.result === 'success' ? '成功' : '失败',
        ip: l.ip || '-',
        time: l.time || '-',
        avatar: (l.username || '?')[0].toUpperCase(),
      }));
    } catch (e: any) {
      if (e?.message?.includes('401') || e?.message?.includes('invalid token')) {
        goto('/login');
        return;
      }
      error = e?.message || '加载失败';
    } finally { loading = false; }
  });

  const statCards = $derived([
    { label: '用户总数', value: stats.userCount, icon: Users, bg: 'var(--nya-primary-soft)', fg: 'var(--nya-primary)', trend: '' },
    { label: '应用总数', value: stats.appCount, icon: AppWindow, bg: 'var(--nya-blue-soft)', fg: 'var(--nya-blue)', trend: '' },
    { label: '7 日登录次数', value: stats.loginCount7d, icon: LogIn, bg: 'var(--nya-mint-soft)', fg: 'var(--nya-mint)', trend: '' },
    { label: '活跃会话', value: stats.activeSessions, icon: Activity, bg: 'var(--nya-orange-soft)', fg: 'var(--nya-orange)', trend: '' },
    { label: '7 日失败登录', value: stats.failedLogins7d, icon: AlertTriangle, bg: 'var(--nya-pink-soft)', fg: 'var(--nya-pink)', trend: '' },
  ]);
</script>

<svelte:head><title>仪表盘 - Nya</title></svelte:head>

<!-- 页面头部 §7.1 -->
<div style="margin-bottom: 20px;">
  <h1 style="font-size: 24px; line-height: 32px; font-weight: 700; color: var(--nya-text-primary); margin: 0;">仪表盘</h1>
  <p style="font-size: 14px; line-height: 21px; color: var(--nya-text-secondary); margin-top: 4px;">欢迎回来，Nya Admin！今天也要元气满满喵～</p>
</div>

<!-- 统计卡 §0.6: 5 列 → 响应式降列 -->
<div class="grid" style="gap: 16px; margin-bottom: 16px; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));">
  {#each statCards as card}
    <div
      class="bg-[var(--nya-surface)] border border-[var(--nya-border)]"
      style="min-height: 112px; padding: 20px; border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card); display: grid; grid-template-columns: 48px 1fr; column-gap: 14px; align-items: center;"
    >
      <div
        class="flex items-center justify-center rounded-full"
        style="width: 46px; height: 46px; background: {card.bg};"
      >
        <card.icon size={22} color={card.fg} />
      </div>
      <div>
        <p style="font-size: 13px; color: var(--nya-text-tertiary); line-height: 19px;">{card.label}</p>
        <p style="font-size: 28px; font-weight: 720; line-height: 34px; color: var(--nya-text-primary); font-variant-numeric: tabular-nums;">
          {(card.value ?? 0).toLocaleString()}
        </p>
        {#if card.trend}
          <p style="font-size: 12px; color: var(--nya-text-tertiary); line-height: 18px;">{card.trend}</p>
        {/if}
      </div>
    </div>
  {/each}
</div>

<!-- 主内容区 §0.6: 5:5:2 网格 → 移动端单列 -->
<div class="grid" style="gap: 16px; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));">

  <!-- 登录趋势 §7.3 -->
  <div class="bg-[var(--nya-surface)] border border-[var(--nya-border)]" style="min-height: 310px; padding: 20px; border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card);">
    <div class="flex items-center justify-between" style="margin-bottom: 16px;">
      <h3 style="font-size: 16px; font-weight: 650; color: var(--nya-text-primary);">登录趋势</h3>
      <span style="font-size: 12px; color: var(--nya-text-tertiary); background: var(--nya-surface-muted); padding: 2px 8px; border-radius: var(--nya-radius-pill);">7 天</span>
    </div>
    {#if trendData.length > 0 && trendData.some(v => v > 0)}
      <TrendChart labels={trendLabels} values={trendData} height="220px" />
    {:else}
      <div class="flex flex-col items-center justify-center" style="height: 220px; color: var(--nya-text-tertiary);">
        <LogIn size={32} style="margin-bottom: 8px; opacity: 0.4;" />
        <p style="font-size: 13px;">暂无登录数据</p>
      </div>
    {/if}
  </div>

  <!-- 最近登录 §7.4 -->
  <div class="bg-[var(--nya-surface)] border border-[var(--nya-border)]" style="min-height: 310px; padding: 20px; border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card);">
    <div class="flex items-center justify-between" style="margin-bottom: 16px;">
      <h3 style="font-size: 16px; font-weight: 650; color: var(--nya-text-primary);">最近登录</h3>
      <a href="/admin" style="font-size: 12px; color: var(--nya-primary); text-decoration: none;">查看全部</a>
    </div>
    {#if recentLogins.length > 0}
      <div>
        {#each recentLogins as entry}
          <div class="flex items-center" style="height: 52px; border-bottom: 1px solid var(--nya-divider); gap: 10px;">
            <div class="shrink-0 flex items-center justify-center rounded-full" style="width: 30px; height: 30px; background: var(--nya-primary-soft); font-size: 12px; font-weight: 600; color: var(--nya-primary);">
              {entry.avatar}
            </div>
            <div class="flex-1 min-w-0">
              <p style="font-size: 13px; font-weight: 500; color: var(--nya-text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{entry.user}</p>
            </div>
            <span style="font-size: 11px; padding: 1px 6px; border-radius: var(--nya-radius-pill); background: {entry.role === '管理员' ? 'var(--nya-pink-soft)' : 'var(--nya-surface-muted)'}; color: {entry.role === '管理员' ? 'var(--nya-pink)' : 'var(--nya-text-tertiary)'}; font-weight: 550;">
              {entry.role}
            </span>
            <span style="font-size: 12px; color: {entry.result === '成功' ? 'var(--nya-success)' : 'var(--nya-danger)'};">{entry.result}</span>
            <span style="font-size: 12px; color: var(--nya-text-tertiary); font-family: monospace; min-width: 90px;">{entry.ip}</span>
            <span style="font-size: 12px; color: var(--nya-text-tertiary); white-space: nowrap;">{entry.time}</span>
          </div>
        {/each}
      </div>
    {:else}
      <div class="flex flex-col items-center justify-center" style="height: 240px; color: var(--nya-text-tertiary);">
        <Users size={32} style="margin-bottom: 8px; opacity: 0.4;" />
        <p style="font-size: 13px;">尚无登录记录</p>
      </div>
    {/if}
  </div>

  <!-- Nya 提示卡 §7.5 -->
  <div
    class="border border-[var(--nya-primary-border)]"
    style="min-height: 310px; padding: 20px; border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card); background: linear-gradient(135deg, #f8f5ff 0%, #fff0f6 100%); display: flex; flex-direction: column; align-items: center;"
  >
    <!-- 猫系占位插画 §2.3: 占 55%-65% -->
    <svg width="100" height="100" viewBox="0 0 112 100" fill="none" style="margin-top: 10px; margin-bottom: 8px;">
      <path d="M28 58 L38 18 L50 52" stroke="#8b6cff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" opacity="0.7" fill="#f1edff"/>
      <path d="M62 52 L74 18 L84 58" stroke="#8b6cff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" opacity="0.7" fill="#f1edff"/>
      <ellipse cx="56" cy="64" rx="30" ry="24" fill="#f8f5ff" stroke="#8b6cff" stroke-width="2" opacity="0.6"/>
      <circle cx="46" cy="62" r="3.5" fill="#8b6cff" opacity="0.7"/>
      <circle cx="66" cy="62" r="3.5" fill="#8b6cff" opacity="0.7"/>
      <path d="M52 68 Q56 73 60 68" stroke="#8b6cff" stroke-width="1.5" stroke-linecap="round" fill="none" opacity="0.5"/>
      <circle cx="16" cy="38" r="2.5" fill="#c28bff" opacity="0.5"/>
      <circle cx="96" cy="32" r="2" fill="#ff9bcb" opacity="0.5"/>
      <circle cx="56" cy="12" r="2" fill="#c28bff" opacity="0.4"/>
      <text x="56" y="95" text-anchor="middle" fill="#8b6cff" font-size="10" opacity="0.5">🐾</text>
    </svg>

    <p style="font-size: 15px; font-weight: 650; color: var(--nya-primary); margin-bottom: 6px;">Nya 提示</p>
    {#if stats.userCount === 0 && stats.appCount === 0}
      <p style="font-size: 13px; color: var(--nya-text-secondary); text-align: center; line-height: 1.5;">
        还没有用户和应用<br/>创建第一个用户或应用开始使用吧！
      </p>
    {:else}
      <p style="font-size: 13px; color: var(--nya-text-secondary); text-align: center; line-height: 1.5;">
        系统运行良好！<br/>所有服务正常，最近未发现异常登录。
      </p>
    {/if}
  </div>
</div>

<!-- OIDC 配置（次级信息 §7.6 后） -->
<div class="grid" style="gap: 16px; margin-top: 16px; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));">
  <div class="bg-[var(--nya-surface)] border border-[var(--nya-border)]" style="padding: 20px; border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card);">
    <h3 style="font-size: 16px; font-weight: 650; color: var(--nya-text-primary); margin-bottom: 12px;">OIDC 配置</h3>
    <div class="space-y-2">
      <div class="flex items-center gap-2">
        <span style="font-size: 12px; color: var(--nya-text-tertiary); min-width: 80px;">Issuer</span>
        <code style="font-size: 12px; padding: 2px 8px; background: var(--nya-surface-muted); border-radius: 6px; color: var(--nya-text-primary);">http://localhost:8080</code>
      </div>
      <div class="flex items-center gap-2">
        <span style="font-size: 12px; color: var(--nya-text-tertiary); min-width: 80px;">Discovery</span>
        <a href="/.well-known/openid-configuration" target="_blank" style="font-size: 12px; color: var(--nya-primary); text-decoration: none;">/.well-known/openid-configuration</a>
      </div>
      <div class="flex items-center gap-2">
        <span style="font-size: 12px; color: var(--nya-text-tertiary); min-width: 80px;">JWKS</span>
        <a href="/.well-known/jwks.json" target="_blank" style="font-size: 12px; color: var(--nya-primary); text-decoration: none;">/.well-known/jwks.json</a>
      </div>
    </div>
  </div>
  <div class="bg-[var(--nya-surface)] border border-[var(--nya-border)]" style="padding: 20px; border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card);">
    <h3 style="font-size: 16px; font-weight: 650; color: var(--nya-text-primary); margin-bottom: 12px;">系统信息</h3>
    <div class="space-y-2">
      <div class="flex items-center gap-2">
        <span style="font-size: 12px; color: var(--nya-text-tertiary); min-width: 80px;">版本</span>
        <span style="font-size: 12px; color: var(--nya-text-primary);">0.2.0</span>
      </div>
      <div class="flex items-center gap-2">
        <span style="font-size: 12px; color: var(--nya-text-tertiary); min-width: 80px;">数据库</span>
        <span style="font-size: 12px; color: var(--nya-success);">PostgreSQL 已连接</span>
      </div>
      <div class="flex items-center gap-2">
        <span style="font-size: 12px; color: var(--nya-text-tertiary); min-width: 80px;">缓存</span>
        <span style="font-size: 12px; color: var(--nya-success);">Redis 已连接</span>
      </div>
    </div>
  </div>
</div>
