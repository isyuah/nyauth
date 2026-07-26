-- Operational settings editable at runtime from the admin UI. Deployment-shape
-- configuration (issuer, keys, connections) stays in the config file on purpose.
-- NOTE: fold into the 000001 baseline when cutting the 0.3.0 release.
CREATE TABLE runtime_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
