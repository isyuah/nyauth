import { describe, expect, it } from 'vitest';
import {
  PASSWORD_MAX_BYTES,
  PASSWORD_MIN_BYTES,
  passwordByteLength,
  passwordPolicyError,
} from './password-policy';

describe('password policy', () => {
  it('counts UTF-8 bytes rather than JavaScript code units', () => {
    expect(passwordByteLength('密码密码密码')).toBe(18);
    expect(passwordByteLength('🔐🔐🔐')).toBe(12);
  });

  it('accepts both byte boundaries', () => {
    expect(passwordPolicyError('a'.repeat(PASSWORD_MIN_BYTES))).toBeNull();
    expect(passwordPolicyError('a'.repeat(PASSWORD_MAX_BYTES))).toBeNull();
  });

  it('rejects passwords below the byte minimum', () => {
    expect(passwordPolicyError('a'.repeat(PASSWORD_MIN_BYTES - 1))).not.toBeNull();
  });

  it('rejects passwords above the byte maximum', () => {
    expect(passwordPolicyError('a'.repeat(PASSWORD_MAX_BYTES + 1))).not.toBeNull();
  });
});
