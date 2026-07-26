import { describe, expect, it } from 'vitest';
import {
  buildMailCandidateInput,
  parseMailReauthenticationSnapshot,
  serializeMailReauthenticationSnapshot,
  type MailCandidateDraft,
} from './mail-settings';

const draft: MailCandidateDraft = {
  host: ' smtp.example.com ',
  port: '587',
  username: ' operator ',
  tls_mode: 'starttls',
  from_address: ' noreply@example.com ',
  from_name: ' Nyauth ',
  public_base_url: ' https://auth.example.com ',
  connect_timeout: '10s',
  send_timeout: '30s',
};

describe('mail candidate payload', () => {
  it('omits an empty password so the backend can inherit the active secret', () => {
    expect(buildMailCandidateInput(7, draft, '', false)).toEqual({
      expected_revision: 7,
      host: 'smtp.example.com',
      port: 587,
      username: 'operator',
      tls_mode: 'starttls',
      from_address: 'noreply@example.com',
      from_name: 'Nyauth',
      public_base_url: 'https://auth.example.com',
      connect_timeout: '10s',
      send_timeout: '30s',
    });
  });

  it('uses an explicit empty password only for passwordless SMTP', () => {
    expect(buildMailCandidateInput(7, draft, 'must-not-be-used', true).password).toBe('');
  });
});

describe('provider reauthentication snapshot', () => {
  it('allowlists non-secret fields and never serializes the SMTP password', () => {
    const raw = serializeMailReauthenticationSnapshot({
      action: 'save',
      expected_revision: 7,
      draft: { ...draft, password: 'smtp-secret' } as MailCandidateDraft,
      password_was_provided: true,
    });

    expect(raw).not.toContain('smtp-secret');
    expect(raw).not.toContain('"password"');
    expect(parseMailReauthenticationSnapshot(raw)).toMatchObject({
      action: 'save',
      expected_revision: 7,
      password_was_provided: true,
      draft: { host: ' smtp.example.com ', port: '587' },
    });
  });

  it('rejects unknown actions instead of replaying them', () => {
    expect(parseMailReauthenticationSnapshot('{"action":"delete_everything"}')).toBeNull();
  });
});
