import { writable } from 'svelte/store';
import { api, type PublicSiteBannerResponse } from './api';

export const DISMISSED_SITE_BANNER_VERSION_KEY = 'nyauth:site-banner:dismissed-version';

export interface SiteBannerState {
  initialized: boolean;
  loading: boolean;
  value: PublicSiteBannerResponse;
  dismissed: boolean;
  error: string | null;
}

interface SiteBannerEventSource {
  addEventListener(type: string, listener: EventListenerOrEventListenerObject): void;
  close(): void;
}

interface SiteBannerStoreOptions {
  eventSourceFactory?: (url: string) => SiteBannerEventSource | null;
  storage?: Pick<Storage, 'getItem' | 'setItem'> | null;
  now?: () => number;
  pollMinimumMilliseconds?: number;
  pollMaximumMilliseconds?: number;
  reconnectMilliseconds?: number;
}

const EMPTY_SITE_BANNER: PublicSiteBannerResponse = { site_banner: null };

export function isPublicSiteBannerResponse(value: unknown): value is PublicSiteBannerResponse {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<PublicSiteBannerResponse>;
  if (candidate.next_change_at !== undefined && typeof candidate.next_change_at !== 'string') return false;
  if (candidate.site_banner === null) return true;
  if (typeof candidate.site_banner !== 'object' || candidate.site_banner === null) return false;
  const siteBanner = candidate.site_banner;
  return Number.isSafeInteger(siteBanner.version)
    && siteBanner.version > 0
    && ['info', 'warning', 'critical'].includes(siteBanner.severity)
    && typeof siteBanner.title === 'string'
    && typeof siteBanner.message_html === 'string'
    && typeof siteBanner.dismissible === 'boolean'
    && (siteBanner.ends_at === undefined || typeof siteBanner.ends_at === 'string');
}

export function createSiteBannerStore(
  loadSiteBanner: () => Promise<PublicSiteBannerResponse> = api.getSiteBanner,
  options: SiteBannerStoreOptions = {},
) {
  const { subscribe, set, update } = writable<SiteBannerState>({
    initialized: false,
    loading: false,
    value: EMPTY_SITE_BANNER,
    dismissed: false,
    error: null,
  });
  const now = options.now ?? Date.now;
  const pollMinimum = options.pollMinimumMilliseconds ?? 5_000;
  const pollMaximum = Math.max(pollMinimum, options.pollMaximumMilliseconds ?? 60_000);
  const reconnectDelay = options.reconnectMilliseconds ?? 30_000;
  let pending: Promise<PublicSiteBannerResponse> | null = null;
  let source: SiteBannerEventSource | null = null;
  let pollTimer: ReturnType<typeof setTimeout> | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let changeTimer: ReturnType<typeof setTimeout> | null = null;
  let pollingDelay = pollMinimum;
  let started = false;
  let generation = 0;

  function storage(): Pick<Storage, 'getItem' | 'setItem'> | null {
    if (options.storage !== undefined) return options.storage;
    return typeof localStorage === 'undefined' ? null : localStorage;
  }

  function isDismissed(response: PublicSiteBannerResponse): boolean {
    const version = response.site_banner?.version;
    if (!version) return false;
    try {
      return storage()?.getItem(DISMISSED_SITE_BANNER_VERSION_KEY) === String(version);
    } catch {
      return false;
    }
  }

  function scheduleNextChange(nextChangeAt?: string) {
    if (changeTimer !== null) clearTimeout(changeTimer);
    changeTimer = null;
    if (!nextChangeAt) return;
    const timestamp = Date.parse(nextChangeAt);
    if (!Number.isFinite(timestamp)) return;
    const delay = Math.min(2_147_000_000, Math.max(0, timestamp - now() + 50));
    changeTimer = setTimeout(() => {
      changeTimer = null;
      void refresh(true).catch(() => {});
    }, delay);
  }

  function apply(response: PublicSiteBannerResponse, external = false) {
    if (external) generation += 1;
    set({ initialized: true, loading: false, value: response, dismissed: isDismissed(response), error: null });
    scheduleNextChange(response.next_change_at);
  }

  function refresh(force = false): Promise<PublicSiteBannerResponse> {
    if (pending && !force) return pending;
    const requestGeneration = generation;
    update((current) => ({ ...current, loading: true, error: null }));
    const request = loadSiteBanner()
      .then((response) => {
        if (!isPublicSiteBannerResponse(response)) throw new Error('全站横幅服务返回了无效响应');
        if (requestGeneration === generation) apply(response);
        return response;
      })
      .catch((cause: unknown) => {
        const message = cause instanceof Error ? cause.message : '全站横幅加载失败';
        update((current) => ({ ...current, initialized: true, loading: false, error: message }));
        throw cause;
      })
      .finally(() => {
        if (pending === request) pending = null;
      });
    pending = request;
    return request;
  }

  function clearPollTimer() {
    if (pollTimer !== null) clearTimeout(pollTimer);
    pollTimer = null;
  }

  function schedulePoll(delay = pollingDelay) {
    if (!started || pollTimer !== null) return;
    pollTimer = setTimeout(async () => {
      pollTimer = null;
      try {
        await refresh(true);
        pollingDelay = pollMinimum;
      } catch {
        pollingDelay = Math.min(pollMaximum, Math.max(pollMinimum, pollingDelay * 2));
      }
      schedulePoll(pollingDelay);
    }, delay);
  }

  function scheduleReconnect() {
    if (!started || reconnectTimer !== null) return;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connectEvents();
    }, reconnectDelay);
  }

  function handleStreamFailure() {
    source?.close();
    source = null;
    schedulePoll(0);
    scheduleReconnect();
  }

  function connectEvents() {
    if (!started || source !== null) return;
    const factory = options.eventSourceFactory ?? ((url: string) => {
      if (typeof EventSource === 'undefined') return null;
      return new EventSource(url);
    });
    try {
      source = factory('/api/site-banner/events');
      if (source === null) {
        schedulePoll(0);
        return;
      }
      source.addEventListener('open', () => {
        clearPollTimer();
        pollingDelay = pollMinimum;
      });
      source.addEventListener('error', handleStreamFailure);
      source.addEventListener('site_banner', (event) => {
        try {
          const response: unknown = JSON.parse((event as MessageEvent<string>).data);
          if (isPublicSiteBannerResponse(response)) apply(response, true);
        } catch {
          // Polling remains authoritative when a notification is malformed.
        }
      });
    } catch {
      source = null;
      schedulePoll(0);
      scheduleReconnect();
    }
  }

  function refreshWhenVisible() {
    if (document.visibilityState === 'visible') void refresh(true).catch(() => {});
  }

  function refreshAfterReconnect() {
    void refresh(true).catch(() => {});
    if (source === null) connectEvents();
  }

  return {
    subscribe,
    refresh,
    dismiss() {
      update((current) => {
        const siteBanner = current.value.site_banner;
        if (!siteBanner?.dismissible) return current;
        try {
          storage()?.setItem(DISMISSED_SITE_BANNER_VERSION_KEY, String(siteBanner.version));
        } catch {
          // Storage denial must not make the close control unusable for this page view.
        }
        return { ...current, dismissed: true };
      });
    },
    start() {
      if (started) return () => {};
      started = true;
      void refresh().catch(() => {});
      connectEvents();
      if (typeof document !== 'undefined') document.addEventListener('visibilitychange', refreshWhenVisible);
      if (typeof window !== 'undefined') window.addEventListener('online', refreshAfterReconnect);
      return () => {
        started = false;
        clearPollTimer();
        if (reconnectTimer !== null) clearTimeout(reconnectTimer);
        reconnectTimer = null;
        if (changeTimer !== null) clearTimeout(changeTimer);
        changeTimer = null;
        source?.close();
        source = null;
        if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', refreshWhenVisible);
        if (typeof window !== 'undefined') window.removeEventListener('online', refreshAfterReconnect);
      };
    },
  };
}

export const siteBannerStore = createSiteBannerStore();
