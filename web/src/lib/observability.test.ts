import { describe, expect, it } from 'vitest';
import type { ObservabilityPolicy } from './api';
import {
  buildOTLPCandidateInput,
  cloneObservabilityPolicy,
  validateObservabilityPolicy,
  validateOTLPCandidate,
} from './observability';

const policy: ObservabilityPolicy = {
  log_level: 'info',
  debug_until: null,
  alerts: {
    mail_backlog_count: 100,
    mail_oldest_pending_age: '15m',
    audit_outbox_backlog_count: 1000,
    audit_oldest_pending_age: '10m',
    avatar_cleanup_pending_count: 100,
  },
};

describe('observability policy form helpers', () => {
  it('clones nested alert thresholds and validates supported values', () => {
    const cloned = cloneObservabilityPolicy(policy);
    cloned.alerts.mail_backlog_count = 10;
    expect(policy.alerts.mail_backlog_count).toBe(100);
    expect(validateObservabilityPolicy(cloned)).toBeNull();
  });

  it('rejects invalid alert thresholds and expired temporary debug', () => {
    expect(validateObservabilityPolicy({ ...policy, alerts: { ...policy.alerts, mail_backlog_count: 0 } })?.field)
      .toBe('observability-mail-backlog');
    expect(validateObservabilityPolicy({ ...policy, alerts: { ...policy.alerts, audit_oldest_pending_age: '8d' } })?.field)
      .toBe('observability-audit-age');
    expect(validateObservabilityPolicy({ ...policy, debug_until: '2026-07-30T08:00:00Z' }, Date.parse('2026-07-30T09:00:00Z'))?.field)
      .toBe('observability-debug');
  });
});

describe('OTLP candidate form helpers', () => {
  const values = { endpoint: ' https://collector.example/v1/metrics ', authorization: '', export_interval: '30s', timeout: '5s' };

  it('omits an empty authorization so the server can inherit the active secret', () => {
    expect(buildOTLPCandidateInput(4, values, false)).toEqual({
      expected_revision: 4,
      endpoint: 'https://collector.example/v1/metrics',
      export_interval: '30s',
      timeout: '5s',
    });
  });

  it('sends an explicit empty authorization only when clearing was requested', () => {
    expect(buildOTLPCandidateInput(4, values, true)).toHaveProperty('authorization', '');
    expect(buildOTLPCandidateInput(4, { ...values, authorization: 'Bearer secret' }, false)).toHaveProperty('authorization', 'Bearer secret');
  });

  it('validates endpoint, interval, and timeout bounds', () => {
    expect(validateOTLPCandidate(values)).toBeNull();
    expect(validateOTLPCandidate({ ...values, endpoint: 'ftp://collector.example' })?.field).toBe('observability-otlp-endpoint');
    expect(validateOTLPCandidate({ ...values, export_interval: '5s' })?.field).toBe('observability-otlp-interval');
    expect(validateOTLPCandidate({ ...values, timeout: '31s' })?.field).toBe('observability-otlp-timeout');
  });
});
