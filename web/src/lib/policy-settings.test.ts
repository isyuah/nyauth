import { describe, expect, it } from 'vitest';
import type { UpdateLifecycleSettingsInput, UpdateOAuthSettingsInput, UpdateProtectionSettingsInput } from './api';
import {
  DEFAULT_OAUTH_SETTINGS,
  DEFAULT_PROTECTION_SETTINGS,
  applyProtectionPreset,
  disabledProtectionGroups,
  matchingProtectionPreset,
  parseDurationMilliseconds,
  protectionValidationError,
  retentionConfirmation,
  lifecycleValidationError,
  oauthPolicyValidationError,
  validateLifecycleSettings,
  validateProtectionSettings,
} from './policy-settings';

describe('protection policy presets', () => {
  it('uses the existing code defaults as the stable template baseline', () => {
    expect(DEFAULT_PROTECTION_SETTINGS).toMatchObject({
      login: { window: '5m', identity_limit: 5, ip_limit: 30, passkey_ceremony_ip_limit: 120 },
      account: { window: '15m', subject_limit: 5, ip_limit: 20 },
      avatar: { window: '15m', user_limit: 30, ip_limit: 200 },
      mail: { window: '15m', save_limit: 60, test_limit: 30, ip_limit: 200 },
      owned_client_default_limit: 10,
    });
  });

  it('rounds strict limits up, scales relaxed limits, and preserves the independent client quota', () => {
    const current = { ...DEFAULT_PROTECTION_SETTINGS, owned_client_default_limit: 37, revision: 8 };
    const strict = applyProtectionPreset(current, 'strict');
    const relaxed = applyProtectionPreset(current, 'relaxed');

    expect(strict.login.identity_limit).toBe(3);
    expect(strict.account.subject_limit).toBe(3);
    expect(strict.mail.save_limit).toBe(30);
    expect(relaxed.login.identity_limit).toBe(20);
    expect(relaxed.mail.ip_limit).toBe(800);
    expect(strict.owned_client_default_limit).toBe(37);
    expect(relaxed.owned_client_default_limit).toBe(37);
    expect(matchingProtectionPreset(strict)).toBe('strict');
  });

  it('requires confirmation only for enabled groups that become disabled', () => {
    const preset = applyProtectionPreset(DEFAULT_PROTECTION_SETTINGS, 'default');
    const next: UpdateProtectionSettingsInput = {
      expected_revision: preset.revision,
      login: { ...preset.login },
      account: { ...preset.account },
      avatar: { ...preset.avatar },
      mail: { ...preset.mail },
      owned_client_default_limit: preset.owned_client_default_limit,
    };
    next.login.enabled = false;
    next.avatar.enabled = false;
    expect(disabledProtectionGroups(DEFAULT_PROTECTION_SETTINGS, next)).toEqual(['login', 'avatar']);
  });
});

describe('runtime policy validation', () => {
  const validProtection: UpdateProtectionSettingsInput = {
    expected_revision: 1,
    ...applyProtectionPreset(DEFAULT_PROTECTION_SETTINGS, 'default'),
  };

  it('accepts composite Go-style hour/minute durations and rejects trailing input', () => {
    expect(parseDurationMilliseconds('1h30m')).toBe(5_400_000);
    expect(parseDurationMilliseconds('10s')).toBe(10_000);
    expect(parseDurationMilliseconds('15m later')).toBeNull();
  });

  it('enforces hard rate and client quota ranges', () => {
    expect(validateProtectionSettings(validProtection)).toBe('');
    expect(validateProtectionSettings({
      ...validProtection,
      login: { ...validProtection.login, window: '9s' },
    })).toContain('10 秒');
    expect(protectionValidationError({
      ...validProtection,
      login: { ...validProtection.login, window: '9s' },
    })?.field).toBe('protection-login-window');
    expect(validateProtectionSettings({ ...validProtection, owned_client_default_limit: 1_001 })).toContain('0 至 1000');
  });

  it('builds and validates the exact retention confirmation contract', () => {
    const lifecycle: UpdateLifecycleSettingsInput = {
      expected_revision: 2,
      session_absolute_ttl: '24h',
      session_idle_ttl: '12h',
      max_concurrent_sessions: 5,
      recent_authentication_ttl: '10m',
      access_token_ttl: '1h',
      refresh_token_ttl: '720h',
      authorization_code_ttl: '5m',
      audit_retention_days: 90,
    };
    expect(validateLifecycleSettings(lifecycle)).toBe('');
    expect(retentionConfirmation(90)).toBe('RETENTION 90 DAYS');
    expect(validateLifecycleSettings({ ...lifecycle, recent_authentication_ttl: '61m' })).toContain('1 小时');
    expect(lifecycleValidationError({ ...lifecycle, recent_authentication_ttl: '61m' })?.field)
      .toBe('lifecycle-recent-auth-ttl');
    expect(lifecycleValidationError({ ...lifecycle, session_idle_ttl: '25h' })?.field)
      .toBe('lifecycle-session-idle-ttl');
    expect(lifecycleValidationError({ ...lifecycle, access_token_ttl: '25h' })?.field)
      .toBe('lifecycle-access-token-ttl');
  });

  it('enforces OAuth grant, scope, public-client, and URI dependencies', () => {
    const valid: UpdateOAuthSettingsInput = {
      expected_revision: 3,
      self_service_client_creation_enabled: DEFAULT_OAUTH_SETTINGS.self_service_client_creation_enabled,
      public_clients_enabled: DEFAULT_OAUTH_SETTINGS.public_clients_enabled,
      allowed_grant_types: [...DEFAULT_OAUTH_SETTINGS.allowed_grant_types],
      allowed_scopes: [...DEFAULT_OAUTH_SETTINGS.allowed_scopes],
      max_redirect_uris: DEFAULT_OAUTH_SETTINGS.max_redirect_uris,
      max_post_logout_redirect_uris: DEFAULT_OAUTH_SETTINGS.max_post_logout_redirect_uris,
    };
    expect(oauthPolicyValidationError(valid)).toBeNull();
    expect(oauthPolicyValidationError({ ...valid, allowed_scopes: ['openid', 'tenant.read'] })).toBeNull();
    expect(oauthPolicyValidationError({ ...valid, allowed_scopes: [] })).toBeNull();
    expect(oauthPolicyValidationError({ ...valid, allowed_scopes: ['tenant read'] })?.field).toBe('oauth-scopes');
    expect(oauthPolicyValidationError({
      ...valid,
      public_clients_enabled: false,
      allowed_grant_types: ['refresh_token'],
      allowed_scopes: ['openid'],
    })?.message).toContain('Authorization Code');
    expect(oauthPolicyValidationError({
      ...valid,
      public_clients_enabled: false,
      allowed_grant_types: ['authorization_code'],
      allowed_scopes: ['openid', 'offline_access'],
    })?.message).toContain('Refresh Token');
    expect(oauthPolicyValidationError({
      ...valid,
      allowed_grant_types: ['client_credentials'],
      allowed_scopes: ['openid'],
    })?.field).toBe('oauth-public-clients');
    expect(oauthPolicyValidationError({ ...valid, max_redirect_uris: 101 })?.field).toBe('oauth-max-redirects');
    expect(oauthPolicyValidationError({ ...valid, max_post_logout_redirect_uris: -1 })?.field).toBe('oauth-max-logouts');
  });
});
