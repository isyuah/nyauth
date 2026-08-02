ALTER TABLE users
    ADD COLUMN theme_preference VARCHAR(16) NOT NULL DEFAULT 'default',
    ADD CONSTRAINT users_theme_preference_valid
        CHECK (theme_preference IN ('default', 'light', 'dark', 'system'));

UPDATE runtime_settings
SET value = (value - 'logo_url') || jsonb_build_object(
    'default_theme', 'system',
    'primary_color', '#704DE8',
    'light_logo_url', COALESCE(value->>'logo_url', ''),
    'dark_logo_url', COALESCE(value->>'logo_url', ''),
    'favicon_url', ''
)
WHERE key = 'branding';
