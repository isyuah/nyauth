import { get } from 'svelte/store';
import { describe, expect, it, vi } from 'vitest';
import type { OperationsSettings, ServiceStatus } from './api';
import {
  capabilityPauseReason,
  createServiceStatusStore,
  isServiceStatus,
  isCapabilityPaused,
  matchesCapabilities,
  publicStatusFromOperations,
  sortCapabilities,
} from './service-control';

const restrictedStatus: ServiceStatus = {
  status: 'restricted',
  paused_capabilities: ['media_writes', 'self_registration'],
  public_message: '计划维护中',
  expires_at: '2099-07-28T12:00:00Z',
  retry_after_seconds: 60,
};

describe('service control helpers', () => {
  it('sorts, deduplicates, and compares capability sets in canonical order', () => {
    expect(sortCapabilities(['media_writes', 'self_registration', 'media_writes'])).toEqual([
      'self_registration',
      'media_writes',
    ]);
    expect(matchesCapabilities(
      ['admin_mutations', 'account_mutations'],
      ['account_mutations', 'admin_mutations'],
    )).toBe(true);
  });

  it('accepts only complete public service status payloads', () => {
    expect(isServiceStatus(restrictedStatus)).toBe(true);
    expect(isServiceStatus({ ...restrictedStatus, paused_capabilities: ['future_capability'] })).toBe(false);
    expect(isServiceStatus({ ...restrictedStatus, retry_after_seconds: '60' })).toBe(false);
  });

  it('provides the public maintenance reason only for a paused capability', () => {
    expect(isCapabilityPaused(restrictedStatus, 'self_registration')).toBe(true);
    expect(capabilityPauseReason(restrictedStatus, 'self_registration')).toBe('计划维护中');
    expect(capabilityPauseReason(restrictedStatus, 'auth_issuance')).toBe('');
  });

  it('strips management-only fields when updating the public store', () => {
    const settings: OperationsSettings = {
      ...restrictedStatus,
      revision: 4,
      internal_reason: 'deploy database changes',
      updated_at: '2026-07-28T11:00:00Z',
      updated_by: 'admin-id',
      application_status: 'applied',
      active_instances: 0,
      applied_instances: 0,
      instances: [],
    };
    expect(publicStatusFromOperations(settings)).toEqual({
      ...restrictedStatus,
      paused_capabilities: ['self_registration', 'media_writes'],
    });
  });
});

describe('service status store', () => {
  it('deduplicates concurrent refreshes and stores the normalized response', async () => {
    const loader = vi.fn(async () => restrictedStatus);
    const store = createServiceStatusStore(loader);

    await Promise.all([store.refresh(), store.refresh()]);

    expect(loader).toHaveBeenCalledTimes(1);
    expect(get(store)).toEqual({
      initialized: true,
      loading: false,
      value: { ...restrictedStatus, paused_capabilities: ['self_registration', 'media_writes'] },
      error: null,
    });
  });

  it('keeps the last known value when a refresh fails', async () => {
    const loader = vi.fn<() => Promise<ServiceStatus>>()
      .mockResolvedValueOnce(restrictedStatus)
      .mockRejectedValueOnce(new Error('offline'));
    const store = createServiceStatusStore(loader);
    await store.refresh();
    await expect(store.refresh(true)).rejects.toThrow('offline');

    expect(get(store).value.status).toBe('restricted');
    expect(get(store).error).toBe('offline');
  });

  it('applies valid SSE updates immediately, ignores malformed events, and closes on cleanup', async () => {
    const source = new FakeEventSource();
    const store = createServiceStatusStore(async () => restrictedStatus, {
      eventSourceFactory: () => source,
    });
    const cleanup = store.startPolling(60_000);
    await store.refresh();

    source.emit('service-status', '{not-json');
    expect(get(store).value.status).toBe('restricted');
    source.emit('service-status', JSON.stringify({ ...restrictedStatus, status: 'normal', paused_capabilities: [] }));
    expect(get(store).value.status).toBe('normal');

    cleanup();
    expect(source.closed).toBe(true);
  });

  it('refreshes at the advertised expiration time even without an SSE event', async () => {
    vi.useFakeTimers();
    let currentTime = Date.parse('2026-07-28T12:00:00Z');
    const loader = vi.fn<() => Promise<ServiceStatus>>()
      .mockResolvedValueOnce({ ...restrictedStatus, expires_at: '2026-07-28T12:00:01Z' })
      .mockResolvedValueOnce({
        status: 'normal', paused_capabilities: [], public_message: '', expires_at: null, retry_after_seconds: 0,
      });
    const store = createServiceStatusStore(loader, { now: () => currentTime });
    await store.refresh();

    currentTime += 1_050;
    await vi.advanceTimersByTimeAsync(1_050);

    expect(loader).toHaveBeenCalledTimes(2);
    expect(get(store).value.status).toBe('normal');
    vi.useRealTimers();
  });
});

class FakeEventSource {
  closed = false;
  private listeners = new Map<string, EventListenerOrEventListenerObject[]>();

  addEventListener(type: string, listener: EventListenerOrEventListenerObject) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  close() {
    this.closed = true;
  }

  emit(type: string, data: string) {
    const event = { data } as MessageEvent<string>;
    for (const listener of this.listeners.get(type) ?? []) {
      if (typeof listener === 'function') listener(event);
      else listener.handleEvent(event);
    }
  }
}
