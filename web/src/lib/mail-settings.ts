import type { MailTLSMode, SaveMailCandidateInput } from './api';

export interface MailCandidateDraft {
  host: string;
  port: string;
  username: string;
  tls_mode: MailTLSMode;
  from_address: string;
  from_name: string;
  public_base_url: string;
  connect_timeout: string;
  send_timeout: string;
}

export type MailReauthenticationAction = 'load' | 'save' | 'test' | 'activate' | 'rollback' | 'disable';

export interface MailReauthenticationSnapshot {
  action: MailReauthenticationAction;
  expected_revision?: number;
  version_id?: string;
  draft?: MailCandidateDraft;
  password_was_provided?: boolean;
  passwordless?: boolean;
}

const mailReauthenticationActions = new Set<MailReauthenticationAction>([
  'load',
  'save',
  'test',
  'activate',
  'rollback',
  'disable',
]);

function cleanDraft(value: MailCandidateDraft): MailCandidateDraft {
  return {
    host: String(value.host || ''),
    port: String(value.port || ''),
    username: String(value.username || ''),
    tls_mode: value.tls_mode,
    from_address: String(value.from_address || ''),
    from_name: String(value.from_name || ''),
    public_base_url: String(value.public_base_url || ''),
    connect_timeout: String(value.connect_timeout || ''),
    send_timeout: String(value.send_timeout || ''),
  };
}

export function buildMailCandidateInput(
  expectedRevision: number,
  draft: MailCandidateDraft,
  password: string,
  passwordless: boolean,
): SaveMailCandidateInput {
  const port = Number(String(draft.port ?? '').trim());
  const payload: SaveMailCandidateInput = {
    expected_revision: expectedRevision,
    host: draft.host.trim(),
    port,
    username: draft.username.trim(),
    tls_mode: draft.tls_mode,
    from_address: draft.from_address.trim(),
    from_name: draft.from_name.trim(),
    public_base_url: draft.public_base_url.trim(),
    connect_timeout: draft.connect_timeout.trim(),
    send_timeout: draft.send_timeout.trim(),
  };
  if (passwordless) payload.password = '';
  else if (password !== '') payload.password = password;
  return payload;
}

export function serializeMailReauthenticationSnapshot(value: MailReauthenticationSnapshot): string {
  const snapshot: MailReauthenticationSnapshot = { action: value.action };
  if (Number.isSafeInteger(value.expected_revision) && (value.expected_revision ?? -1) >= 0) {
    snapshot.expected_revision = value.expected_revision;
  }
  if (value.version_id) snapshot.version_id = value.version_id;
  if (value.action === 'save' && value.draft) snapshot.draft = cleanDraft(value.draft);
  if (value.password_was_provided) snapshot.password_was_provided = true;
  if (value.passwordless) snapshot.passwordless = true;
  return JSON.stringify(snapshot);
}

export function parseMailReauthenticationSnapshot(raw: string): MailReauthenticationSnapshot | null {
  try {
    const value = JSON.parse(raw) as Partial<MailReauthenticationSnapshot>;
    if (!value || typeof value.action !== 'string' || !mailReauthenticationActions.has(value.action as MailReauthenticationAction)) {
      return null;
    }
    const snapshot: MailReauthenticationSnapshot = { action: value.action as MailReauthenticationAction };
    if (Number.isSafeInteger(value.expected_revision) && (value.expected_revision ?? -1) >= 0) {
      snapshot.expected_revision = value.expected_revision;
    }
    if (typeof value.version_id === 'string' && value.version_id) snapshot.version_id = value.version_id;
    if (snapshot.action === 'save' && value.draft && typeof value.draft === 'object') {
      snapshot.draft = cleanDraft(value.draft as MailCandidateDraft);
    }
    if (value.password_was_provided === true) snapshot.password_was_provided = true;
    if (value.passwordless === true) snapshot.passwordless = true;
    return snapshot;
  } catch {
    return null;
  }
}
