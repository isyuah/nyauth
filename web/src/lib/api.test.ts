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
    ['registration is temporarily unavailable', '注册功能暂时不可用，请稍后重试'],
    ['mail settings changed; reload and try again', '邮件设置已被其他管理员修改，请重新加载后再试'],
    ['a successful candidate test is required', '激活前必须先成功发送候选配置的测试邮件'],
    ['close self-registration before disabling mail', '禁用邮件服务前必须先关闭自助注册'],
  ])('maps stable authentication error %s', (message, expected) => {
    expect(localizeAPIErrorMessage(message)).toBe(expected);
  });

  it('preserves unrelated API errors', () => {
    expect(localizeAPIErrorMessage('provider temporarily unavailable')).toBe('provider temporarily unavailable');
  });
});
