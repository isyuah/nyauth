<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type DashboardStats,
    type MailTrend,
    type RegistrationTrend,
    type StatsTrendDays,
  } from '$lib/api';
  import {
    buildMailTrendChart,
    buildRegistrationTrendCharts,
    formatCompletionRate,
    formatLocalDateTime,
  } from '$lib/admin-stats';
  import TrendChart from '$lib/components/data-display/TrendChart.svelte';
  import { Activity, AlertTriangle, Mail, ShieldCheck, Ticket, UserPlus } from 'lucide-svelte';

  let { stats }: { stats: DashboardStats } = $props();

  const trendDayOptions = [7, 30, 90] as const satisfies readonly StatsTrendDays[];

  let days = $state<StatsTrendDays>(30);
  let registrationTrend = $state<RegistrationTrend | null>(null);
  let mailTrend = $state<MailTrend | null>(null);
  let registrationLoading = $state(true);
  let mailLoading = $state(true);
  let registrationError = $state('');
  let mailError = $state('');
  let registrationRequest = 0;
  let mailRequest = 0;

  let registrationCharts = $derived(
    registrationTrend ? buildRegistrationTrendCharts(registrationTrend) : null,
  );
  let mailChart = $derived(mailTrend ? buildMailTrendChart(mailTrend) : null);
  let mailStatsAvailableFrom = $derived(mailTrend?.available_from ?? stats.mail_stats_available_from);
  let summaryCards = $derived([
    {
      label: '待验证注册',
      value: stats.pending_registrations.toLocaleString('zh-CN'),
      icon: UserPlus,
      bg: 'var(--nya-primary-soft)',
      fg: 'var(--nya-primary)',
    },
    {
      label: '7 日完成注册',
      value: stats.completed_registrations_7d.toLocaleString('zh-CN'),
      icon: Activity,
      bg: 'var(--nya-mint-soft)',
      fg: 'var(--nya-mint)',
    },
    {
      label: '30 日完成率',
      value: formatCompletionRate(stats.registration_completion_rate_30d),
      icon: Ticket,
      bg: 'var(--nya-blue-soft)',
      fg: 'var(--nya-blue)',
    },
    {
      label: '邮件待发送',
      value: stats.mail_backlog.toLocaleString('zh-CN'),
      icon: Mail,
      bg: 'var(--nya-orange-soft)',
      fg: 'var(--nya-orange)',
    },
    {
      label: '24 小时邮件失败',
      value: stats.mail_failures_24h.toLocaleString('zh-CN'),
      icon: AlertTriangle,
      bg: stats.mail_failures_24h > 0 ? 'var(--nya-danger-soft)' : 'var(--nya-surface-muted)',
      fg: stats.mail_failures_24h > 0 ? 'var(--nya-danger)' : 'var(--nya-text-tertiary)',
    },
    {
      label: 'SMTP 熔断',
      value: stats.smtp_circuit_state === 'open' ? '已熔断' : '未熔断',
      icon: ShieldCheck,
      bg: stats.smtp_circuit_state === 'open' ? 'var(--nya-danger-soft)' : 'var(--nya-mint-soft)',
      fg: stats.smtp_circuit_state === 'open' ? 'var(--nya-danger)' : 'var(--nya-mint)',
    },
  ]);

  async function loadRegistrationTrend(targetDays: StatsTrendDays = days) {
    const request = ++registrationRequest;
    registrationLoading = true;
    registrationError = '';
    try {
      const result = await api.admin.getRegistrationTrend(targetDays);
      if (request !== registrationRequest) return;
      registrationTrend = result;
    } catch (cause) {
      if (request !== registrationRequest) return;
      registrationTrend = null;
      registrationError = cause instanceof Error ? cause.message : '注册与邀请趋势加载失败';
    } finally {
      if (request === registrationRequest) registrationLoading = false;
    }
  }

  async function loadMailTrend(targetDays: StatsTrendDays = days) {
    const request = ++mailRequest;
    mailLoading = true;
    mailError = '';
    try {
      const result = await api.admin.getMailTrend(targetDays);
      if (request !== mailRequest) return;
      mailTrend = result;
    } catch (cause) {
      if (request !== mailRequest) return;
      mailTrend = null;
      mailError = cause instanceof Error ? cause.message : '邮件趋势加载失败';
    } finally {
      if (request === mailRequest) mailLoading = false;
    }
  }

  function selectDays(next: StatsTrendDays) {
    if (next === days) return;
    days = next;
    void loadRegistrationTrend(next);
    void loadMailTrend(next);
  }

  onMount(() => {
    void loadRegistrationTrend();
    void loadMailTrend();
  });
</script>

<section id="registration-mail-stats" class="mt-4" aria-labelledby="registration-mail-stats-title">
  <div class="mb-4 flex flex-wrap items-end justify-between gap-3">
    <div>
      <h2 id="registration-mail-stats-title" class="text-card-title text-nya-text-primary">注册与邮件</h2>
      <p class="mt-1 text-small text-nya-text-tertiary">趋势数据按 UTC 自然日聚合</p>
      <p class="mt-1 text-micro text-nya-text-tertiary">
        邮件统计自 {formatLocalDateTime(mailStatsAvailableFrom)} 起可用，早于该时间的数据可能不完整。
      </p>
    </div>
    <div class="flex rounded-nya-md border border-nya-border bg-nya-surface p-1" role="group" aria-label="趋势时间范围">
      {#each trendDayOptions as option}
        <button
          type="button"
          aria-pressed={days === option}
          class="rounded-nya-sm px-3 py-1.5 text-small font-medium transition-colors {days === option ? 'bg-nya-primary text-white' : 'text-nya-text-secondary hover:bg-nya-surface-muted'}"
          onclick={() => selectDays(option)}
        >
          {option} 天
        </button>
      {/each}
    </div>
  </div>

  <div class="grid gap-4 [grid-template-columns:repeat(auto-fit,minmax(170px,1fr))]">
    {#each summaryCards as card}
      <section class="grid min-h-24 grid-cols-[42px_1fr] items-center gap-3 rounded-nya-card border border-nya-border bg-nya-surface p-4 shadow-nya-card">
        <span class="flex h-10 w-10 items-center justify-center rounded-full" style="background: {card.bg};">
          <card.icon size={19} color={card.fg} />
        </span>
        <div class="min-w-0">
          <p class="text-small text-nya-text-tertiary">{card.label}</p>
          <p class="truncate text-xl font-bold tabular-nums text-nya-text-primary">{card.value}</p>
        </div>
      </section>
    {/each}
  </div>

  <div class="mt-4 grid gap-4 xl:grid-cols-2">
    {#if registrationLoading}
      <section class="flex min-h-[310px] items-center justify-center rounded-nya-card border border-nya-border bg-nya-surface p-5 text-body text-nya-text-tertiary shadow-nya-card xl:col-span-2" aria-busy="true">
        正在加载注册与邀请趋势…
      </section>
    {:else if registrationError}
      <section class="min-h-[160px] rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card xl:col-span-2">
        <p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">注册与邀请趋势加载失败：{registrationError}</p>
        <button type="button" class="mt-3 text-small font-medium text-nya-primary hover:underline" onclick={() => loadRegistrationTrend()}>重试注册与邀请趋势</button>
      </section>
    {:else if registrationCharts}
      <section class="min-h-[310px] rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
        <h3 class="mb-4 text-card-title text-nya-text-primary">注册趋势</h3>
        <TrendChart
          labels={registrationCharts.labels}
          series={registrationCharts.registrationSeries}
          ariaLabel={`注册趋势（${days} 天）`}
          emptyText="暂无注册趋势数据"
        />
      </section>

      <section class="min-h-[310px] rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
        <h3 class="mb-4 text-card-title text-nya-text-primary">邀请趋势</h3>
        <TrendChart
          labels={registrationCharts.labels}
          series={registrationCharts.invitationSeries}
          ariaLabel={`邀请趋势（${days} 天）`}
          emptyText="暂无邀请趋势数据"
        />
      </section>
    {/if}

    <section class="min-h-[310px] rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card xl:col-span-2">
      <h3 class="mb-4 text-card-title text-nya-text-primary">邮件趋势</h3>
      {#if mailLoading}
        <div class="flex h-[220px] items-center justify-center text-body text-nya-text-tertiary" aria-busy="true">正在加载邮件趋势…</div>
      {:else if mailError}
        <div>
          <p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">邮件趋势加载失败：{mailError}</p>
          <button type="button" class="mt-3 text-small font-medium text-nya-primary hover:underline" onclick={() => loadMailTrend()}>重试邮件趋势</button>
        </div>
      {:else if mailChart}
        <TrendChart
          labels={mailChart.labels}
          series={mailChart.series}
          ariaLabel={`邮件趋势（${days} 天）`}
          emptyText="暂无邮件趋势数据"
        />
      {/if}
    </section>
  </div>
</section>
