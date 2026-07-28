DROP TRIGGER IF EXISTS oauth_providers_presentation_defaults ON oauth_providers;
DROP FUNCTION IF EXISTS nyauth_provider_presentation_defaults();

ALTER TABLE oauth_providers
    DROP CONSTRAINT IF EXISTS oauth_providers_icon_key_valid,
    DROP CONSTRAINT IF EXISTS oauth_providers_display_name_valid,
    DROP COLUMN IF EXISTS icon_key,
    DROP COLUMN IF EXISTS display_name;
