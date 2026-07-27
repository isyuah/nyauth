-- Security policy storage is introduced by Phase T even though it lives in
-- the shared runtime_settings table. Version 6 must not retain a policy that
-- depends on MFA tables which no longer exist.
DELETE FROM runtime_settings WHERE key = 'security';

DROP TABLE IF EXISTS user_recovery_codes;
DROP TABLE IF EXISTS user_totp_credentials;
