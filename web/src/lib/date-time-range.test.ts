import { describe, expect, it } from 'vitest';
import {
  buildCalendarMonth,
  formatLocalDateTime,
  isWithinDateRange,
  orderedDateRange,
  parseDateKey,
  parseLocalDateTime,
  shiftCalendarMonth,
  splitLocalDateTime,
} from './date-time-range';

describe('date time range helpers', () => {
  it('builds a stable Monday-first six-week calendar', () => {
    const days = buildCalendarMonth(2026, 6, new Date(2026, 6, 15, 10, 0));
    expect(days).toHaveLength(42);
    expect(days[0]).toMatchObject({ dateKey: '2026-06-29', inCurrentMonth: false });
    expect(days[2]).toMatchObject({ dateKey: '2026-07-01', inCurrentMonth: true });
    expect(days.find((day) => day.dateKey === '2026-07-15')?.isToday).toBe(true);
    expect(days[41].dateKey).toBe('2026-08-09');
  });

  it('moves across month and year boundaries', () => {
    expect(shiftCalendarMonth(2026, 0, -1)).toEqual({ year: 2025, month: 11 });
    expect(shiftCalendarMonth(2026, 11, 1)).toEqual({ year: 2027, month: 0 });
    expect(shiftCalendarMonth(2026, 6, -12)).toEqual({ year: 2025, month: 6 });
  });

  it('validates local dates without accepting calendar rollover', () => {
    expect(parseDateKey('2028-02-29')).not.toBeNull();
    expect(parseDateKey('2026-02-29')).toBeNull();
    expect(parseLocalDateTime('2026-07-05T08:15')).not.toBeNull();
    expect(parseLocalDateTime('2026-07-05T08:15:42')).not.toBeNull();
    expect(parseLocalDateTime('2026-07-05T24:00')).toBeNull();
    expect(parseLocalDateTime('2026-07-05T08:15:60')).toBeNull();
    expect(splitLocalDateTime('invalid', '23:59')).toEqual({ date: '', time: '23:59' });
    expect(splitLocalDateTime('2026-07-05T08:15', '00:00:00', true)).toEqual({ date: '2026-07-05', time: '08:15:00' });
  });

  it('formats local date-time values at minute precision', () => {
    expect(formatLocalDateTime(new Date(2026, 6, 5, 8, 7))).toBe('2026-07-05T08:07');
    expect(formatLocalDateTime(new Date(2026, 6, 5, 8, 7, 9), true)).toBe('2026-07-05T08:07:09');
  });

  it('orders endpoints and identifies interior dates', () => {
    expect(orderedDateRange('2026-07-20', '2026-07-05')).toEqual(['2026-07-05', '2026-07-20']);
    expect(isWithinDateRange('2026-07-10', '2026-07-05', '2026-07-20')).toBe(true);
    expect(isWithinDateRange('2026-07-05', '2026-07-05', '2026-07-20')).toBe(false);
  });
});
