export type CalendarDay = {
  dateKey: string;
  day: number;
  inCurrentMonth: boolean;
  isToday: boolean;
};

const dateKeyPattern = /^(\d{4})-(\d{2})-(\d{2})$/;
const localDateTimePattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/;

function pad(value: number): string {
  return String(value).padStart(2, '0');
}

export function formatDateKey(value: Date): string {
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`;
}

export function formatLocalDateTime(value: Date, includeSeconds = false): string {
  const minutes = `${formatDateKey(value)}T${pad(value.getHours())}:${pad(value.getMinutes())}`;
  return includeSeconds ? `${minutes}:${pad(value.getSeconds())}` : minutes;
}

export function parseDateKey(value: string): Date | null {
  const match = dateKeyPattern.exec(value);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const parsed = new Date(year, month - 1, day, 12, 0, 0, 0);
  if (parsed.getFullYear() !== year || parsed.getMonth() !== month - 1 || parsed.getDate() !== day) return null;
  return parsed;
}

export function parseLocalDateTime(value: string): Date | null {
  const match = localDateTimePattern.exec(value);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6] ?? '0');
  if (hour > 23 || minute > 59 || second > 59) return null;
  const parsed = new Date(year, month - 1, day, hour, minute, second, 0);
  if (
    parsed.getFullYear() !== year
    || parsed.getMonth() !== month - 1
    || parsed.getDate() !== day
    || parsed.getHours() !== hour
    || parsed.getMinutes() !== minute
    || parsed.getSeconds() !== second
  ) return null;
  return parsed;
}

export function splitLocalDateTime(value: string, fallbackTime: string, includeSeconds = false): { date: string; time: string } {
  if (!parseLocalDateTime(value)) return { date: '', time: fallbackTime };
  const time = value.slice(11);
  return {
    date: value.slice(0, 10),
    time: includeSeconds ? (time.length === 5 ? `${time}:00` : time) : time.slice(0, 5),
  };
}

export function combineLocalDateTime(date: string, time: string): string {
  return `${date}T${time}`;
}

export function buildCalendarMonth(year: number, month: number, today = new Date()): CalendarDay[] {
  const firstDay = new Date(year, month, 1, 12, 0, 0, 0);
  const mondayOffset = (firstDay.getDay() + 6) % 7;
  const todayKey = formatDateKey(today);
  const days: CalendarDay[] = [];

  for (let index = 0; index < 42; index += 1) {
    const date = new Date(year, month, 1 - mondayOffset + index, 12, 0, 0, 0);
    const dateKey = formatDateKey(date);
    days.push({
      dateKey,
      day: date.getDate(),
      inCurrentMonth: date.getFullYear() === year && date.getMonth() === month,
      isToday: dateKey === todayKey,
    });
  }

  return days;
}

export function shiftCalendarMonth(year: number, month: number, delta: number): { year: number; month: number } {
  const shifted = new Date(year, month + delta, 1, 12, 0, 0, 0);
  return { year: shifted.getFullYear(), month: shifted.getMonth() };
}

export function orderedDateRange(first: string, second: string): [string, string] {
  return first <= second ? [first, second] : [second, first];
}

export function isWithinDateRange(value: string, start: string, end: string): boolean {
  return Boolean(start && end && value > start && value < end);
}
