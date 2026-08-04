import { writable } from 'svelte/store';
import { api, type NotificationUnreadCount } from './api';

const EMPTY: NotificationUnreadCount = { unread_count: 0, notification_count: 0, announcement_count: 0 };

export interface NotificationCenterState {
  initialized: boolean;
  value: NotificationUnreadCount;
  error: string | null;
}

export function isNotificationUnreadCount(value: unknown): value is NotificationUnreadCount {
  if (typeof value !== 'object' || value === null) return false;
  const item = value as NotificationUnreadCount;
  return [item.unread_count, item.notification_count, item.announcement_count]
    .every((count) => Number.isSafeInteger(count) && count >= 0);
}

interface NotificationEventSource {
  addEventListener(type: string, listener: EventListenerOrEventListenerObject): void;
  close(): void;
}

interface NotificationCenterOptions {
  eventSourceFactory?: (url: string) => NotificationEventSource | null;
  pollMilliseconds?: number;
  reconnectMilliseconds?: number;
}

export function createNotificationCenterStore(
  loadCount: () => Promise<NotificationUnreadCount> = api.getNotificationUnreadCount,
  options: NotificationCenterOptions = {},
) {
  const { subscribe, set, update } = writable<NotificationCenterState>({ initialized: false, value: EMPTY, error: null });
  let source: NotificationEventSource | null = null;
  let pollTimer: ReturnType<typeof setTimeout> | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let started = false;
  let consumers = 0;

  async function refresh() {
    try {
      const value = await loadCount();
      if (!isNotificationUnreadCount(value)) throw new Error('消息中心返回了无效响应');
      set({ initialized: true, value, error: null });
      return value;
    } catch (cause) {
      update((current) => ({ ...current, initialized: true, error: cause instanceof Error ? cause.message : '消息状态加载失败' }));
      throw cause;
    }
  }

  function schedulePoll(delay = 0) {
    if (!started || source !== null || pollTimer !== null) return;
    pollTimer = setTimeout(async () => {
      pollTimer = null;
      await refresh().catch(() => {});
      schedulePoll(options.pollMilliseconds ?? 30_000);
    }, delay);
  }

  function connect() {
    if (!started || source !== null) return;
    const factory = options.eventSourceFactory ?? ((url: string) => typeof EventSource === 'undefined' ? null : new EventSource(url));
    try {
      source = factory('/api/notifications/events');
      if (source === null) { schedulePoll(); return; }
      source.addEventListener('open', () => { if (pollTimer !== null) clearTimeout(pollTimer); pollTimer = null; });
      source.addEventListener('notifications', (event) => {
        try {
          const value: unknown = JSON.parse((event as MessageEvent<string>).data);
          if (isNotificationUnreadCount(value)) set({ initialized: true, value, error: null });
        } catch { /* The next database-backed refresh remains authoritative. */ }
      });
      source.addEventListener('error', () => {
        source?.close(); source = null; schedulePoll();
        if (reconnectTimer === null) reconnectTimer = setTimeout(() => { reconnectTimer = null; connect(); }, options.reconnectMilliseconds ?? 30_000);
      });
    } catch { source = null; schedulePoll(); }
  }

  return {
    subscribe,
    refresh,
    start() {
      consumers += 1;
      if (!started) {
        started = true;
        void refresh().catch(() => {});
        connect();
      }
      let released = false;
      return () => {
        if (released) return;
        released = true;
        consumers = Math.max(0, consumers - 1);
        if (consumers > 0) return;
        started = false;
        source?.close(); source = null;
        if (pollTimer !== null) clearTimeout(pollTimer); pollTimer = null;
        if (reconnectTimer !== null) clearTimeout(reconnectTimer); reconnectTimer = null;
        set({ initialized: false, value: EMPTY, error: null });
      };
    },
    clear() { set({ initialized: false, value: EMPTY, error: null }); },
  };
}

export const notificationCenterStore = createNotificationCenterStore();
