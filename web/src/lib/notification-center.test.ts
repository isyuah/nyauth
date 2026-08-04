import { get } from 'svelte/store';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { NotificationUnreadCount } from './api';
import { createNotificationCenterStore, isNotificationUnreadCount } from './notification-center';

const count: NotificationUnreadCount = { unread_count: 3, notification_count: 2, announcement_count: 1 };

afterEach(() => vi.useRealTimers());

describe('notification center payload', () => {
  it('accepts only non-negative integer counts', () => {
    expect(isNotificationUnreadCount(count)).toBe(true);
    expect(isNotificationUnreadCount({ ...count, unread_count: -1 })).toBe(false);
    expect(isNotificationUnreadCount({ ...count, announcement_count: 1.5 })).toBe(false);
    expect(isNotificationUnreadCount(null)).toBe(false);
  });
});

describe('notification center store', () => {
  it('applies SSE counts and closes the shared stream after the final consumer', async () => {
    const source = new FakeEventSource();
    const store = createNotificationCenterStore(async () => ({ unread_count: 0, notification_count: 0, announcement_count: 0 }), { eventSourceFactory: () => source });
    const stopFirst = store.start();
    const stopSecond = store.start();
    await store.refresh();
    source.emit('notifications', count);
    expect(get(store).value).toEqual(count);
    stopFirst();
    expect(source.closed).toBe(false);
    stopSecond();
    expect(source.closed).toBe(true);
    expect(get(store)).toEqual({ initialized: false, value: { unread_count: 0, notification_count: 0, announcement_count: 0 }, error: null });
  });

  it('falls back to polling after a stream error and stops timers', async () => {
    vi.useFakeTimers();
    const source = new FakeEventSource();
    const loader = vi.fn(async () => count);
    const store = createNotificationCenterStore(loader, { eventSourceFactory: () => source, pollMilliseconds: 100, reconnectMilliseconds: 1_000 });
    const stop = store.start();
    await store.refresh();
    source.emitRaw('error', {} as Event);
    await vi.advanceTimersByTimeAsync(250);
    expect(loader.mock.calls.length).toBeGreaterThanOrEqual(3);
    const calls = loader.mock.calls.length;
    stop();
    await vi.advanceTimersByTimeAsync(2_000);
    expect(loader).toHaveBeenCalledTimes(calls);
  });
});

class FakeEventSource {
  closed = false;
  private readonly listeners = new Map<string, EventListenerOrEventListenerObject[]>();
  addEventListener(type: string, listener: EventListenerOrEventListenerObject) { const values = this.listeners.get(type) ?? []; values.push(listener); this.listeners.set(type, values); }
  close() { this.closed = true; }
  emit(type: string, value: NotificationUnreadCount) { this.emitRaw(type, { data: JSON.stringify(value) } as MessageEvent<string>); }
  emitRaw(type: string, event: Event) { for (const listener of this.listeners.get(type) ?? []) { if (typeof listener === 'function') listener(event); else listener.handleEvent(event); } }
}
