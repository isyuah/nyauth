DROP TABLE IF EXISTS client_access_users;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS access_policy;
