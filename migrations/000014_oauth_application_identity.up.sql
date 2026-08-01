ALTER TABLE oauth_clients
    ADD COLUMN homepage_uri TEXT NOT NULL DEFAULT '',
    ADD COLUMN privacy_policy_uri TEXT NOT NULL DEFAULT '',
    ADD COLUMN terms_of_service_uri TEXT NOT NULL DEFAULT '',
    ADD COLUMN identity_revision BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN authorization_revision BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT oauth_clients_identity_revision_positive CHECK (identity_revision > 0),
    ADD CONSTRAINT oauth_clients_authorization_revision_positive CHECK (authorization_revision > 0);

ALTER TABLE user_avatars
    DROP CONSTRAINT user_avatars_source_valid,
    ADD COLUMN media_purpose TEXT NOT NULL DEFAULT 'user_avatar',
    ADD COLUMN client_id VARCHAR(64) REFERENCES oauth_clients(id) ON DELETE SET NULL,
    ADD CONSTRAINT user_avatars_source_valid
        CHECK (source IN ('user_upload', 'admin_upload', 'provider_import', 'client_upload')),
    ADD CONSTRAINT user_avatars_media_purpose_valid
        CHECK (media_purpose IN ('user_avatar', 'client_logo')),
    ADD CONSTRAINT user_avatars_media_source_consistent CHECK (
        (media_purpose = 'user_avatar' AND source <> 'client_upload')
        OR (media_purpose = 'client_logo' AND source = 'client_upload')
    ),
    ADD CONSTRAINT user_avatars_media_owner_consistent CHECK (
        (media_purpose = 'user_avatar' AND client_id IS NULL)
        OR (media_purpose = 'client_logo' AND user_id IS NULL)
    );

CREATE INDEX idx_user_avatars_client_created
    ON user_avatars (client_id, created_at DESC, id)
    WHERE media_purpose = 'client_logo';

CREATE UNIQUE INDEX idx_user_avatars_one_active_client_logo
    ON user_avatars (client_id)
    WHERE media_purpose = 'client_logo' AND status = 'active';

ALTER TABLE oauth_clients ADD COLUMN current_logo_id UUID;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_current_logo_fk
    FOREIGN KEY (current_logo_id)
    REFERENCES user_avatars(id)
    ON DELETE SET NULL
    DEFERRABLE INITIALLY IMMEDIATE;

ALTER TABLE oauth_authorizations
    ADD COLUMN client_name_snapshot TEXT NOT NULL DEFAULT '',
    ADD COLUMN homepage_uri_snapshot TEXT NOT NULL DEFAULT '',
    ADD COLUMN privacy_policy_uri_snapshot TEXT NOT NULL DEFAULT '',
    ADD COLUMN terms_of_service_uri_snapshot TEXT NOT NULL DEFAULT '',
    ADD COLUMN client_identity_revision BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN client_authorization_revision BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT oauth_authorizations_identity_revision_positive CHECK (client_identity_revision > 0),
    ADD CONSTRAINT oauth_authorizations_client_authorization_revision_positive CHECK (client_authorization_revision > 0);

UPDATE oauth_authorizations AS grant_record
SET client_name_snapshot = client.name,
    homepage_uri_snapshot = client.homepage_uri,
    privacy_policy_uri_snapshot = client.privacy_policy_uri,
    terms_of_service_uri_snapshot = client.terms_of_service_uri,
    client_identity_revision = client.identity_revision,
    client_authorization_revision = client.authorization_revision
FROM oauth_clients AS client
WHERE client.id = grant_record.client_id;

-- Before schema 14 this column was initialized at consent time and never
-- tracked actual use. Reset that misleading legacy value; new token issuance
-- updates it after a user grant is really exercised.
UPDATE oauth_authorizations SET last_used_at = NULL;
