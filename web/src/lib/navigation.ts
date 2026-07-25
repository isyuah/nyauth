const providerAuthErrors: Record<string, string> = {
  invalid_state: '登录状态无效或已过期，请重新发起登录。',
  provider_denied: '你取消了外部身份提供商的授权。',
  missing_code: '身份提供商未返回授权码，请重试。',
  provider_unavailable: '该身份提供商当前不可用。',
  provider_authentication_failed: '身份提供商验证失败，请稍后重试。',
  session_changed: '当前会话已变化，请重新发起身份绑定。',
  identity_already_bound: '该外部身份已绑定到其他账户。',
  binding_failed: '外部身份绑定失败，请稍后重试。',
  account_unavailable: '该账户当前不可用，请联系管理员。',
  session_failed: '登录会话创建失败，请稍后重试。',
};

export interface ProviderAuthErrorResult {
  message: string;
  cleanPath: string;
}

export function safeReturnPath(value: string | null | undefined, fallback = '/dashboard'): string {
  if (!value || !value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return fallback;
  try {
    const parsed = new URL(value, 'https://local.invalid');
    return parsed.origin === 'https://local.invalid' ? `${parsed.pathname}${parsed.search}${parsed.hash}` : fallback;
  } catch {
    return fallback;
  }
}

export function cleanProviderAuthError(href: string): ProviderAuthErrorResult | null {
  const url = new URL(href);
  let code = url.searchParams.get('auth_error');
  if (code) {
    url.searchParams.delete('auth_error');
  } else {
    const nestedReturnTo = safeReturnPath(url.searchParams.get('return_to'), '');
    if (nestedReturnTo) {
      const nestedURL = new URL(nestedReturnTo, 'https://local.invalid');
      code = nestedURL.searchParams.get('auth_error');
      if (code) {
        nestedURL.searchParams.delete('auth_error');
        url.searchParams.set('return_to', `${nestedURL.pathname}${nestedURL.search}${nestedURL.hash}`);
      }
    }
  }
  if (!code) return null;

  return {
    message: providerAuthErrors[code] || '外部身份验证失败，请重新尝试。',
    cleanPath: `${url.pathname}${url.search}${url.hash}`,
  };
}
