import type { MailTrend, RegistrationTrend } from './api';

export type TrendColor = 'primary' | 'blue' | 'mint' | 'orange' | 'pink' | 'danger';

export interface TrendSeries {
  key: string;
  label: string;
  values: number[];
  color: TrendColor;
  fill?: boolean;
}

export interface RegistrationTrendCharts {
  labels: string[];
  registrationSeries: TrendSeries[];
  invitationSeries: TrendSeries[];
}

export interface MailTrendChart {
  labels: string[];
  series: TrendSeries[];
}

const percentageFormatter = new Intl.NumberFormat('zh-CN', {
  style: 'percent',
  maximumFractionDigits: 1,
});

const localDateTimeFormatter = new Intl.DateTimeFormat('zh-CN', {
  dateStyle: 'medium',
  timeStyle: 'short',
});

export function formatCompletionRate(value: number | null): string {
  return value === null ? '—' : percentageFormatter.format(value);
}

export function formatLocalDateTime(value: string): string {
  return localDateTimeFormatter.format(new Date(value));
}

function formatDay(day: string): string {
  return day.slice(5);
}

export function buildRegistrationTrendCharts(trend: RegistrationTrend): RegistrationTrendCharts {
  return {
    labels: trend.points.map((point) => formatDay(point.day)),
    registrationSeries: [
      {
        key: 'registrations_started',
        label: '开始注册',
        values: trend.points.map((point) => point.registrations_started),
        color: 'primary',
      },
      {
        key: 'registrations_completed',
        label: '完成验证',
        values: trend.points.map((point) => point.registrations_completed),
        color: 'mint',
      },
      {
        key: 'registrations_expired',
        label: '注册过期',
        values: trend.points.map((point) => point.registrations_expired),
        color: 'orange',
      },
    ],
    invitationSeries: [
      {
        key: 'invites_reserved',
        label: '邀请预占',
        values: trend.points.map((point) => point.invites_reserved),
        color: 'primary',
      },
      {
        key: 'invites_consumed',
        label: '邀请消费',
        values: trend.points.map((point) => point.invites_consumed),
        color: 'mint',
      },
      {
        key: 'invites_released',
        label: '预占释放',
        values: trend.points.map((point) => point.invites_released),
        color: 'orange',
      },
    ],
  };
}

export function buildMailTrendChart(trend: MailTrend): MailTrendChart {
  return {
    labels: trend.points.map((point) => formatDay(point.day)),
    series: [
      {
        key: 'enqueued',
        label: '邮件入队',
        values: trend.points.map((point) => point.enqueued),
        color: 'primary',
      },
      {
        key: 'sent',
        label: '发送成功',
        values: trend.points.map((point) => point.sent),
        color: 'mint',
      },
      {
        key: 'other_failures',
        label: '其他失败尝试',
        values: trend.points.map((point) => point.other_failures),
        color: 'pink',
      },
      {
        key: 'rejected',
        label: '永久拒收',
        values: trend.points.map((point) => point.rejected),
        color: 'danger',
      },
      {
        key: 'expired',
        label: '邮件过期',
        values: trend.points.map((point) => point.expired),
        color: 'orange',
      },
    ],
  };
}
