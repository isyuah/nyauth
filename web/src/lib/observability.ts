import type {
  ObservabilityPolicy,
  SaveOTLPCandidateInput,
} from './api';
import { parseDurationMilliseconds } from './policy-settings';

export interface ObservabilityValidationError {
  field: string;
  message: string;
}

const MIN_ALERT_COUNT = 1;
const MAX_ALERT_COUNT = 1_000_000;
const MIN_ALERT_AGE = 60_000;
const MAX_ALERT_AGE = 7 * 24 * 60 * 60 * 1000;

export function cloneObservabilityPolicy(value: ObservabilityPolicy): ObservabilityPolicy {
  return {
    log_level: value.log_level,
    debug_until: value.debug_until ?? null,
    alerts: { ...value.alerts },
  };
}

export function validateObservabilityPolicy(value: ObservabilityPolicy, now = Date.now()): ObservabilityValidationError | null {
  if (!['info', 'warn', 'error'].includes(value.log_level)) {
    return { field: 'observability-log-level', message: '请选择有效的日志基线级别。' };
  }
  if (value.debug_until) {
    const until = Date.parse(value.debug_until);
    const remaining = until - now;
    if (!Number.isFinite(until) || remaining < 60_000 || remaining > 24 * 60 * 60 * 1000 + 5_000) {
      return { field: 'observability-debug', message: '临时 Debug 的结束时间须在 1 分钟至 24 小时内。' };
    }
  }
  const countFields: Array<[keyof ObservabilityPolicy['alerts'], string, string]> = [
    ['mail_backlog_count', 'observability-mail-backlog', '邮件积压数量'],
    ['audit_outbox_backlog_count', 'observability-audit-backlog', '审计投递积压数量'],
    ['avatar_cleanup_pending_count', 'observability-avatar-cleanup', '头像清理积压数量'],
  ];
  for (const [key, field, label] of countFields) {
    const count = value.alerts[key];
    if (typeof count !== 'number' || !Number.isInteger(count) || count < MIN_ALERT_COUNT || count > MAX_ALERT_COUNT) {
      return { field, message: `${label}须为 1 至 1,000,000 的整数。` };
    }
  }
  const ageFields: Array<[keyof ObservabilityPolicy['alerts'], string, string]> = [
    ['mail_oldest_pending_age', 'observability-mail-age', '最老待发邮件时长'],
    ['audit_oldest_pending_age', 'observability-audit-age', '最老待投递审计时长'],
  ];
  for (const [key, field, label] of ageFields) {
    const encoded = value.alerts[key];
    const duration = typeof encoded === 'string' ? parseDurationMilliseconds(encoded.trim()) : null;
    if (duration === null || duration < MIN_ALERT_AGE || duration > MAX_ALERT_AGE) {
      return { field, message: `${label}须为 1 分钟至 7 天的时长，例如 15m、2h。` };
    }
  }
  return null;
}

export function buildOTLPCandidateInput(
  expectedRevision: number,
  values: { endpoint: string; authorization: string; export_interval: string; timeout: string },
  clearAuthorization: boolean,
): SaveOTLPCandidateInput {
  const authorization = values.authorization.trim();
  return {
    expected_revision: expectedRevision,
    endpoint: values.endpoint.trim(),
    export_interval: values.export_interval.trim(),
    timeout: values.timeout.trim(),
    ...(clearAuthorization ? { authorization: '' } : authorization ? { authorization } : {}),
  };
}

export function validateOTLPCandidate(values: { endpoint: string; export_interval: string; timeout: string }): ObservabilityValidationError | null {
  let endpoint: URL;
  try {
    endpoint = new URL(values.endpoint.trim());
  } catch {
    return { field: 'observability-otlp-endpoint', message: '请输入完整的 HTTP(S) OTLP Metrics 地址。' };
  }
  if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    return { field: 'observability-otlp-endpoint', message: 'OTLP 地址只能使用 HTTP(S)，且不能包含凭据、查询参数或片段。' };
  }
  const interval = parseDurationMilliseconds(values.export_interval.trim());
  if (interval === null || interval < 10_000 || interval > 60 * 60 * 1000) {
    return { field: 'observability-otlp-interval', message: '导出间隔须为 10 秒至 1 小时，例如 30s、5m。' };
  }
  const timeout = parseDurationMilliseconds(values.timeout.trim());
  if (timeout === null || timeout < 1_000 || timeout > 30_000 || timeout > interval) {
    return { field: 'observability-otlp-timeout', message: '超时时间须为 1 至 30 秒，且不能超过导出间隔。' };
  }
  return null;
}
