UPDATE runtime_settings
SET value = (value - 'default_theme' - 'primary_color' - 'light_logo_url' - 'dark_logo_url' - 'favicon_url')
    || jsonb_build_object('logo_url', COALESCE(value->>'light_logo_url', value->>'dark_logo_url', ''))
WHERE key = 'branding';

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_theme_preference_valid,
    DROP COLUMN IF EXISTS theme_preference;
