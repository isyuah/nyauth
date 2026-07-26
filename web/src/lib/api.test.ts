import { describe, expect, it } from 'vitest';
import { localizeAPIErrorMessage } from './api';
import { PASSWORD_REQUIREMENT } from './password-policy';

describe('localizeAPIErrorMessage', () => {
  it.each([
    'invalid input: password must be valid UTF-8 and 12 to 1024 bytes',
    'invalid account request: password must be valid UTF-8 and 12 to 1024 bytes',
  ])('maps the backend password policy error to the shared Chinese requirement', (message) => {
    expect(localizeAPIErrorMessage(message)).toBe(PASSWORD_REQUIREMENT);
  });

  it.each([
    ['invalid credentials', '认证凭据不正确'],
    ['current password is incorrect', '当前密码不正确'],
    ['recent authentication is required', '请先完成近期身份验证'],
    ['password reauthentication is unavailable', '此账户无法使用密码重新认证'],
    ['a local password is already configured', '此账户已设置本地密码'],
    ['csrf_validation_failed', '安全校验失败，请刷新页面后重试'],
  ])('maps stable authentication error %s', (message, expected) => {
    expect(localizeAPIErrorMessage(message)).toBe(expected);
  });

  it('preserves unrelated API errors', () => {
    expect(localizeAPIErrorMessage('provider temporarily unavailable')).toBe('provider temporarily unavailable');
  });
});
