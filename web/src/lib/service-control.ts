import { writable } from 'svelte/store';
import {
  api,
  type OperationsSettings,
  type ServiceCapability,
  type ServiceOperatingState,
  type ServiceStatus,
} from './api';

export const SERVICE_CAPABILITIES: ReadonlyArray<{
  code: ServiceCapability;
  label: string;
  description: string;
}> = [
  { code: 'self_registration', label: '自助注册', description: '暂停自助注册和 Provider 首次创建账户。' },
  { code: 'account_mutations', label: '账户写入', description: '暂停资料、密码、邮箱、MFA、Passkey、身份及自助客户端写操作。' },
  { code: 'admin_mutations', label: '管理写入', description: '暂停用户、客户端、Provider、邀请及普通设置写操作。' },
  { code: 'auth_issuance', label: '认证签发', description: '暂停登录、OAuth 授权、Token 签发、刷新和授权确认。' },
  { code: 'mail_delivery', label: '邮件投递', description: '停止领取新的邮件任务；在途发送仍会完成。' },
  { code: 'media_writes', label: '媒体写入', description: '暂停头像上传、删除和 Provider 头像导入。' },
];

export const SERVICE_CONTROL_PRESETS: ReadonlyArray<{
  id: 'normal' | 'read_only' | 'authentication' | 'full_pause';
  label: string;
  capabilities: ServiceCapability[];
}> = [
  { id: 'normal', label: '正常运行', capabilities: [] },
  {
    id: 'read_only',
    label: '只读维护',
    capabilities: ['self_registration', 'account_mutations', 'admin_mutations', 'media_writes'],
  },
  {
    id: 'authentication',
    label: '认证维护',
    capabilities: ['self_registration', 'account_mutations', 'admin_mutations', 'auth_issuance', 'media_writes'],
  },
  { id: 'full_pause', label: '全面暂停', capabilities: SERVICE_CAPABILITIES.map(({ code }) => code) },
];

export interface ServiceStatusState {
  initialized: boolean;
  loading: boolean;
  value: ServiceStatus;
  error: string | null;
}

interface ServiceStatusEventSource {
  addEventListener(type: string, listener: EventListenerOrEventListenerObject): void;
  close(): void;
}

interface ServiceStatusStoreOptions {
  eventSourceFactory?: (url: string) => ServiceStatusEventSource | null;
  now?: () => number;
}

export const NORMAL_SERVICE_STATUS: ServiceStatus = {
  status: 'normal',
  paused_capabilities: [],
  public_message: '',
  expires_at: null,
  retry_after_seconds: 0,
};

export function sortCapabilities(capabilities: readonly ServiceCapability[]): ServiceCapability[] {
  const selected = new Set(capabilities);
  return SERVICE_CAPABILITIES.map(({ code }) => code).filter((code) => selected.has(code));
}

export function matchesCapabilities(left: readonly ServiceCapability[], right: readonly ServiceCapability[]): boolean {
  const normalizedLeft = sortCapabilities(left);
  const normalizedRight = sortCapabilities(right);
  return normalizedLeft.length === normalizedRight.length
    && normalizedLeft.every((capability, index) => capability === normalizedRight[index]);
}

export function isCapabilityPaused(status: ServiceStatus | null | undefined, capability: ServiceCapability): boolean {
  return status?.paused_capabilities.includes(capability) ?? false;
}

export function capabilityPauseReason(status: ServiceStatus | null | undefined, capability: ServiceCapability): string {
  if (!isCapabilityPaused(status, capability)) return '';
  const label = SERVICE_CAPABILITIES.find((item) => item.code === capability)?.label ?? capability;
  return status?.public_message.trim() || `${label}因服务维护而暂时停用，请稍后再试。`;
}

export function operatingStateLabel(status: ServiceOperatingState): string {
  switch (status) {
    case 'restricted': return '受限运行';
    case 'authentication_paused': return '认证维护';
    case 'full_pause': return '全面暂停';
    default: return '正常运行';
  }
}

export function publicStatusFromOperations(settings: OperationsSettings): ServiceStatus {
  return {
    status: settings.status,
    paused_capabilities: sortCapabilities(settings.paused_capabilities),
    public_message: settings.public_message,
    expires_at: settings.expires_at,
    retry_after_seconds: settings.retry_after_seconds,
  };
}

export function isServiceStatus(value: unknown): value is ServiceStatus {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<ServiceStatus>;
  const operatingStates: ServiceOperatingState[] = ['normal', 'restricted', 'authentication_paused', 'full_pause'];
  const capabilities = new Set<ServiceCapability>(SERVICE_CAPABILITIES.map(({ code }) => code));
  return operatingStates.includes(candidate.status as ServiceOperatingState)
    && Array.isArray(candidate.paused_capabilities)
    && candidate.paused_capabilities.every((capability) => capabilities.has(capability))
    && typeof candidate.public_message === 'string'
    && (candidate.expires_at === null || typeof candidate.expires_at === 'string')
    && typeof candidate.retry_after_seconds === 'number'
    && Number.isFinite(candidate.retry_after_seconds)
    && candidate.retry_after_seconds >= 0;
}

export function createServiceStatusStore(
  loadStatus: () => Promise<ServiceStatus> = api.getServiceStatus,
  options: ServiceStatusStoreOptions = {},
) {
  const { subscribe, set, update } = writable<ServiceStatusState>({
    initialized: false,
    loading: false,
    value: NORMAL_SERVICE_STATUS,
    error: null,
  });
  let pending: Promise<ServiceStatus> | null = null;
  let pollTimer: ReturnType<typeof setInterval> | null = null;
  let expiryTimer: ReturnType<typeof setTimeout> | null = null;
  let eventSource: ServiceStatusEventSource | null = null;
  let externalGeneration = 0;
  let expiredRefreshAttempted: string | null = null;
  const now = options.now ?? Date.now;

  function scheduleExpiry(expiresAt: string | null) {
    if (expiryTimer !== null) clearTimeout(expiryTimer);
    expiryTimer = null;
    if (expiresAt === null) {
      expiredRefreshAttempted = null;
      return;
    }
    const expires = Date.parse(expiresAt);
    if (!Number.isFinite(expires)) return;
    const maximumDelay = 2_147_000_000;
    const remaining = expires - now();
    if (remaining <= 0) {
      if (expiredRefreshAttempted === expiresAt) return;
      expiredRefreshAttempted = expiresAt;
    } else {
      expiredRefreshAttempted = null;
    }
    const delay = Math.min(maximumDelay, Math.max(0, remaining + 50));
    expiryTimer = setTimeout(() => {
      expiryTimer = null;
      void refresh(true).catch(() => {});
    }, delay);
  }

  function applyStatus(status: ServiceStatus, external = false): ServiceStatus {
    if (external) externalGeneration += 1;
    const normalized = { ...status, paused_capabilities: sortCapabilities(status.paused_capabilities) };
    set({ initialized: true, loading: false, value: normalized, error: null });
    scheduleExpiry(normalized.expires_at);
    return normalized;
  }

  function refresh(force = false): Promise<ServiceStatus> {
    if (pending && !force) return pending;
    const requestGeneration = externalGeneration;
    update((current) => ({ ...current, loading: true, error: null }));
    const request = loadStatus()
      .then((status) => {
        if (requestGeneration !== externalGeneration) return status;
        return applyStatus(status);
      })
      .catch((cause: unknown) => {
        const message = cause instanceof Error ? cause.message : '运行状态加载失败';
        update((current) => ({ ...current, initialized: true, loading: false, error: message }));
        throw cause;
      })
      .finally(() => {
        if (pending === request) pending = null;
      });
    pending = request;
    return request;
  }

  return {
    subscribe,
    refresh,
    setFromOperations(settings: OperationsSettings) {
      applyStatus(publicStatusFromOperations(settings), true);
    },
    startPolling(intervalMilliseconds = 15_000) {
      if (pollTimer === null) {
        void refresh().catch(() => {});
        pollTimer = setInterval(() => void refresh(true).catch(() => {}), intervalMilliseconds);

        const factory = options.eventSourceFactory ?? ((url: string) => {
          if (typeof EventSource === 'undefined') return null;
          return new EventSource(url);
        });
        try {
          eventSource = factory('/api/service-status/events');
          eventSource?.addEventListener('service-status', (event) => {
            try {
              const parsed: unknown = JSON.parse((event as MessageEvent<string>).data);
              if (isServiceStatus(parsed)) applyStatus(parsed, true);
            } catch {
              // A malformed notification is ignored; polling remains authoritative.
            }
          });
        } catch {
          eventSource = null;
        }

        if (typeof document !== 'undefined') document.addEventListener('visibilitychange', refreshWhenVisible);
        if (typeof window !== 'undefined') window.addEventListener('online', refreshAfterReconnect);
      }
      return () => {
        if (pollTimer !== null) clearInterval(pollTimer);
        pollTimer = null;
        if (expiryTimer !== null) clearTimeout(expiryTimer);
        expiryTimer = null;
        eventSource?.close();
        eventSource = null;
        if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', refreshWhenVisible);
        if (typeof window !== 'undefined') window.removeEventListener('online', refreshAfterReconnect);
      };
    },
  };

  function refreshWhenVisible() {
    if (document.visibilityState === 'visible') void refresh(true).catch(() => {});
  }

  function refreshAfterReconnect() {
    void refresh(true).catch(() => {});
  }
}

export const serviceStatusStore = createServiceStatusStore();
