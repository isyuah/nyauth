import { describe, expect, it } from 'vitest';
import type { MailTrend, RegistrationTrend } from './api';
import {
  buildMailTrendChart,
  buildRegistrationTrendCharts,
  formatCompletionRate,
  formatLocalDateTime,
} from './admin-stats';

const registrationTrend = {
  timezone: 'UTC',
  points: [
    {
      day: '2026-07-25',
      registrations_started: 4,
      registrations_completed: 3,
      registrations_expired: 1,
      invites_reserved: 2,
      invites_consumed: 1,
      invites_released: 1,
    },
    {
      day: '2026-07-26',
      registrations_started: 0,
      registrations_completed: 0,
      registrations_expired: 0,
      invites_reserved: 0,
      invites_consumed: 0,
      invites_released: 0,
    },
  ],
} satisfies RegistrationTrend;

const mailTrend = {
  timezone: 'UTC',
  available_from: '2026-07-27T00:00:00Z',
  points: [
    {
      day: '2026-07-25',
      enqueued: 8,
      sent: 6,
      other_failures: 2,
      rejected: 1,
      expired: 0,
    },
    {
      day: '2026-07-26',
      enqueued: 0,
      sent: 0,
      other_failures: 0,
      rejected: 0,
      expired: 1,
    },
  ],
} satisfies MailTrend;

describe('admin statistics formatting', () => {
  it('formats nullable completion rates without turning an empty sample into zero percent', () => {
    expect(formatCompletionRate(null)).toBe('—');
    expect(formatCompletionRate(0)).toBe('0%');
    expect(formatCompletionRate(0.825)).toBe('82.5%');
  });

  it('formats the mail history boundary in the local timezone', () => {
    const value = '2026-07-27T00:00:00Z';
    const expected = new Intl.DateTimeFormat('zh-CN', {
      dateStyle: 'medium',
      timeStyle: 'short',
    }).format(new Date(value));

    expect(formatLocalDateTime(value)).toBe(expected);
  });

  it('maps registration and invitation points into independent chart series', () => {
    const charts = buildRegistrationTrendCharts(registrationTrend);

    expect(charts.labels).toEqual(['07-25', '07-26']);
    expect(charts.registrationSeries.map((series) => series.values)).toEqual([
      [4, 0],
      [3, 0],
      [1, 0],
    ]);
    expect(charts.invitationSeries.map((series) => series.values)).toEqual([
      [2, 0],
      [1, 0],
      [1, 0],
    ]);
  });

  it('keeps transient failures and permanent rejection as separate mail series', () => {
    const chart = buildMailTrendChart(mailTrend);

    expect(chart.labels).toEqual(['07-25', '07-26']);
    expect(chart.series.find((series) => series.key === 'other_failures')?.values).toEqual([2, 0]);
    expect(chart.series.find((series) => series.key === 'rejected')?.values).toEqual([1, 0]);
    expect(chart.series.find((series) => series.key === 'expired')?.values).toEqual([0, 1]);
  });

  it('retains an all-zero interval so the chart can render a zero baseline', () => {
    const zeroTrend = {
      timezone: 'UTC',
      points: [{
        day: '2026-07-27',
        registrations_started: 0,
        registrations_completed: 0,
        registrations_expired: 0,
        invites_reserved: 0,
        invites_consumed: 0,
        invites_released: 0,
      }],
    } satisfies RegistrationTrend;

    const charts = buildRegistrationTrendCharts(zeroTrend);
    expect(charts.labels).toEqual(['07-27']);
    expect(charts.registrationSeries.every((series) => series.values[0] === 0)).toBe(true);
    expect(charts.invitationSeries.every((series) => series.values[0] === 0)).toBe(true);
  });
});
