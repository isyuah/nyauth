-- Add mutable presentation fields without changing the provider identifier
-- used by callback URLs, identities, and encrypted-secret AAD.

ALTER TABLE oauth_providers
    ADD COLUMN display_name VARCHAR(100),
    ADD COLUMN icon_key VARCHAR(32) NOT NULL DEFAULT 'auto';

UPDATE oauth_providers
SET display_name = name
WHERE display_name IS NULL;

ALTER TABLE oauth_providers
    ALTER COLUMN display_name SET NOT NULL,
    ADD CONSTRAINT oauth_providers_display_name_valid
        CHECK (char_length(btrim(display_name)) BETWEEN 1 AND 100),
    ADD CONSTRAINT oauth_providers_icon_key_valid
        CHECK (icon_key IN ('auto', 'github', 'google', 'key', 'link', 'globe'));

CREATE FUNCTION nyauth_provider_presentation_defaults() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.display_name IS NULL OR btrim(NEW.display_name) = '' THEN
        NEW.display_name := NEW.name;
    END IF;
    IF NEW.icon_key IS NULL OR btrim(NEW.icon_key) = '' THEN
        NEW.icon_key := 'auto';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER oauth_providers_presentation_defaults
BEFORE INSERT OR UPDATE OF name, display_name, icon_key ON oauth_providers
FOR EACH ROW EXECUTE FUNCTION nyauth_provider_presentation_defaults();
