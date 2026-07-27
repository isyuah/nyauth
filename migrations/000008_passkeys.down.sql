-- Version 7 does not understand the Passkey enrollment switch. Remove only
-- that JSON member while preserving the TOTP and administrator MFA policy.
UPDATE runtime_settings
SET value = value - 'passkeys_enabled', updated_at = NOW()
WHERE key = 'security';

DROP TABLE IF EXISTS user_passkey_credentials;
DROP TABLE IF EXISTS user_passkey_handles;
