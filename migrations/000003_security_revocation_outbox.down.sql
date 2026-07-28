DROP TRIGGER IF EXISTS users_security_revocation_outbox ON users;
DROP FUNCTION IF EXISTS nyauth_enqueue_security_revocation();
DROP TABLE IF EXISTS security_revocation_outbox;
