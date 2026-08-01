ALTER TABLE oauth_authorizations
    DROP CONSTRAINT oauth_authorizations_client_authorization_revision_positive,
    DROP CONSTRAINT oauth_authorizations_identity_revision_positive,
    DROP COLUMN client_authorization_revision,
    DROP COLUMN client_identity_revision,
    DROP COLUMN terms_of_service_uri_snapshot,
    DROP COLUMN privacy_policy_uri_snapshot,
    DROP COLUMN homepage_uri_snapshot,
    DROP COLUMN client_name_snapshot;

ALTER TABLE oauth_clients
    DROP CONSTRAINT oauth_clients_current_logo_fk,
    DROP COLUMN current_logo_id;

DROP INDEX idx_user_avatars_one_active_client_logo;
DROP INDEX idx_user_avatars_client_created;

ALTER TABLE user_avatars
    DROP CONSTRAINT user_avatars_media_owner_consistent,
    DROP CONSTRAINT user_avatars_media_source_consistent,
    DROP CONSTRAINT user_avatars_media_purpose_valid,
    DROP CONSTRAINT user_avatars_source_valid,
    DROP COLUMN client_id,
    DROP COLUMN media_purpose,
    ADD CONSTRAINT user_avatars_source_valid
        CHECK (source IN ('user_upload', 'admin_upload', 'provider_import'));

ALTER TABLE oauth_clients
    DROP CONSTRAINT oauth_clients_authorization_revision_positive,
    DROP CONSTRAINT oauth_clients_identity_revision_positive,
    DROP COLUMN authorization_revision,
    DROP COLUMN identity_revision,
    DROP COLUMN terms_of_service_uri,
    DROP COLUMN privacy_policy_uri,
    DROP COLUMN homepage_uri;
