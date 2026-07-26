export const PASSWORD_MIN_BYTES = 12;
export const PASSWORD_MAX_BYTES = 1024;
export const PASSWORD_REQUIREMENT = '密码长度需为 12–1024 字节（按 UTF-8 编码）。';

const utf8Encoder = new TextEncoder();

export function passwordByteLength(password: string): number {
  return utf8Encoder.encode(password).byteLength;
}

export function passwordPolicyError(password: string): string | null {
  const length = passwordByteLength(password);
  if (length < PASSWORD_MIN_BYTES || length > PASSWORD_MAX_BYTES) {
    return PASSWORD_REQUIREMENT;
  }
  return null;
}
