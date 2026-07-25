import { describe, expect, it } from 'vitest';
import { cleanProviderAuthError, safeReturnPath } from './navigation';

describe('safeReturnPath', () => {
  it('accepts same-origin relative paths and preserves query/hash', () => {
    expect(safeReturnPath('/authorize?client_id=app#consent')).toBe('/authorize?client_id=app#consent');
  });

  it.each([
    'https://evil.example/callback',
    '//evil.example/callback',
    '/\\evil.example/callback',
    'dashboard',
  ])('rejects unsafe return path %s', (value) => {
    expect(safeReturnPath(value, '/safe')).toBe('/safe');
  });
});

describe('cleanProviderAuthError', () => {
  it('consumes a direct auth_error without dropping unrelated URL state', () => {
    expect(cleanProviderAuthError('https://auth.example/login?auth_error=provider_denied&return_to=%2Fdashboard#top')).toEqual({
      message: '你取消了外部身份提供商的授权。',
      cleanPath: '/login?return_to=%2Fdashboard#top',
    });
  });

  it('consumes auth_error nested in a safe return_to value', () => {
    expect(cleanProviderAuthError('https://auth.example/login?return_to=%2Fdashboard%3Fauth_error%3Dinvalid_state%26tab%3Dsecurity')).toEqual({
      message: '登录状态无效或已过期，请重新发起登录。',
      cleanPath: '/login?return_to=%2Fdashboard%3Ftab%3Dsecurity',
    });
  });

  it('does not inspect an unsafe nested return_to URL', () => {
    expect(cleanProviderAuthError('https://auth.example/login?return_to=https%3A%2F%2Fevil.example%2F%3Fauth_error%3Dinvalid_state')).toBeNull();
  });

  it('uses a generic message for unknown server codes', () => {
    expect(cleanProviderAuthError('https://auth.example/profile?auth_error=unknown_code')).toEqual({
      message: '外部身份验证失败，请重新尝试。',
      cleanPath: '/profile',
    });
  });
});
