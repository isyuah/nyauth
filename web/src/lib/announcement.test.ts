import { get } from 'svelte/store';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { PublicAnnouncementResponse } from './api';
import {
  DISMISSED_ANNOUNCEMENT_VERSION_KEY,
  createAnnouncementStore,
  isPublicAnnouncementResponse,
  isSafeAnnouncementLink,
} from './announcement';

const activeAnnouncement: PublicAnnouncementResponse = {
  announcement: {
    version: 7,
    severity: 'warning',
    title: '计划维护',
    message: '部分操作可能短暂不可用。',
    link_label: '查看状态',
    link_url: '/status',
    dismissible: true,
    ends_at: '2099-07-30T12:00:00Z',
  },
};

afterEach(() => {
  vi.useRealTimers();
});

describe('announcement payload validation', () => {
  it('accepts complete public payloads and rejects unsafe shapes', () => {
    expect(isPublicAnnouncementResponse(activeAnnouncement)).toBe(true);
    expect(isPublicAnnouncementResponse({ announcement: null, next_change_at: '2099-07-30T12:00:00Z' })).toBe(true);
    expect(isPublicAnnouncementResponse({ announcement: { ...activeAnnouncement.announcement, version: 0 } })).toBe(false);
    expect(isPublicAnnouncementResponse({ announcement: { ...activeAnnouncement.announcement, severity: 'urgent' } })).toBe(false);
  });

  it('rejects browser-normalized cross-origin backslash paths', () => {
    expect(isSafeAnnouncementLink('/status')).toBe(true);
    expect(isSafeAnnouncementLink('https://status.example.test/incident')).toBe(true);
    expect(isSafeAnnouncementLink('/\\attacker.example/path')).toBe(false);
    expect(isSafeAnnouncementLink('//attacker.example/path')).toBe(false);
  });
});

describe('announcement store', () => {
  it('applies live appearance and removal, and scopes dismissal to one version', async () => {
    const source = new FakeEventSource();
    const storage = new MemoryStorage();
    const store = createAnnouncementStore(async () => ({ announcement: null }), {
      eventSourceFactory: () => source,
      storage,
    });
    const stop = store.start();
    await store.refresh();

    source.emit('announcement', activeAnnouncement);
    expect(get(store).value.announcement?.version).toBe(7);
    expect(get(store).dismissed).toBe(false);

    store.dismiss();
    expect(storage.getItem(DISMISSED_ANNOUNCEMENT_VERSION_KEY)).toBe('7');
    expect(get(store).dismissed).toBe(true);
    source.emit('announcement', activeAnnouncement);
    expect(get(store).dismissed).toBe(true);

    source.emit('announcement', {
      announcement: { ...activeAnnouncement.announcement!, version: 8, title: '维护完成' },
    });
    expect(get(store).dismissed).toBe(false);
    source.emit('announcement', { announcement: null });
    expect(get(store).value.announcement).toBeNull();

    stop();
    expect(source.closed).toBe(true);
  });

  it('falls back to bounded polling after an SSE error and releases all resources', async () => {
    vi.useFakeTimers();
    const source = new FakeEventSource();
    const loader = vi.fn(async () => ({ announcement: null } satisfies PublicAnnouncementResponse));
    const store = createAnnouncementStore(loader, {
      eventSourceFactory: () => source,
      pollMinimumMilliseconds: 100,
      pollMaximumMilliseconds: 400,
      reconnectMilliseconds: 1_000,
    });
    const stop = store.start();
    await store.refresh();
    source.emitRaw('error', {} as Event);
    await vi.advanceTimersByTimeAsync(450);
    expect(loader.mock.calls.length).toBeGreaterThanOrEqual(3);

    const callsBeforeStop = loader.mock.calls.length;
    stop();
    await vi.advanceTimersByTimeAsync(2_000);
    expect(loader).toHaveBeenCalledTimes(callsBeforeStop);
  });

  it('refreshes at next_change_at even when no event arrives', async () => {
    vi.useFakeTimers();
    let currentTime = Date.parse('2026-07-29T12:00:00Z');
    const loader = vi.fn<() => Promise<PublicAnnouncementResponse>>()
      .mockResolvedValueOnce({ announcement: null, next_change_at: '2026-07-29T12:00:01Z' })
      .mockResolvedValueOnce(activeAnnouncement);
    const store = createAnnouncementStore(loader, {
      now: () => currentTime,
      eventSourceFactory: () => null,
      pollMinimumMilliseconds: 60_000,
    });
    const stop = store.start();
    await store.refresh();
    currentTime += 1_050;
    await vi.advanceTimersByTimeAsync(1_050);
    expect(get(store).value.announcement?.version).toBe(7);
    stop();
  });
});

class MemoryStorage {
  private readonly values = new Map<string, string>();

  getItem(key: string) {
    return this.values.get(key) ?? null;
  }

  setItem(key: string, value: string) {
    this.values.set(key, value);
  }
}

class FakeEventSource {
  closed = false;
  private readonly listeners = new Map<string, EventListenerOrEventListenerObject[]>();

  addEventListener(type: string, listener: EventListenerOrEventListenerObject) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  close() {
    this.closed = true;
  }

  emit(type: string, value: PublicAnnouncementResponse) {
    this.emitRaw(type, { data: JSON.stringify(value) } as MessageEvent<string>);
  }

  emitRaw(type: string, event: Event) {
    for (const listener of this.listeners.get(type) ?? []) {
      if (typeof listener === 'function') listener(event);
      else listener.handleEvent(event);
    }
  }
}
