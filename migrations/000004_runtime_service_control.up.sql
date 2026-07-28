CREATE TABLE service_control_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    revision BIGINT NOT NULL,
    public_message VARCHAR(240) NOT NULL DEFAULT '',
    internal_reason VARCHAR(500) NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by_name VARCHAR(255),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT service_control_state_singleton CHECK (singleton),
    CONSTRAINT service_control_state_revision_positive CHECK (revision > 0),
    CONSTRAINT service_control_state_updater_name_not_blank CHECK (
        updated_by_name IS NULL OR btrim(updated_by_name) <> ''
    )
);

CREATE TABLE service_control_pauses (
    capability VARCHAR(64) PRIMARY KEY,
    singleton BOOLEAN NOT NULL DEFAULT TRUE REFERENCES service_control_state(singleton) ON DELETE CASCADE,
    CONSTRAINT service_control_pauses_singleton CHECK (singleton),
    CONSTRAINT service_control_pauses_capability_valid CHECK (capability IN (
        'self_registration',
        'account_mutations',
        'admin_mutations',
        'auth_issuance',
        'mail_delivery',
        'media_writes'
    ))
);

CREATE TABLE service_control_instances (
    instance_id UUID PRIMARY KEY,
    version VARCHAR(128) NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    loaded_revision BIGINT NOT NULL,
    applied_revision BIGINT NOT NULL,
    CONSTRAINT service_control_instances_version_not_blank CHECK (btrim(version) <> ''),
    CONSTRAINT service_control_instances_revisions_positive CHECK (
        loaded_revision > 0 AND applied_revision > 0
    ),
    CONSTRAINT service_control_instances_revision_order CHECK (applied_revision <= loaded_revision)
);

CREATE INDEX idx_service_control_instances_heartbeat
    ON service_control_instances (heartbeat_at);

INSERT INTO service_control_state (singleton, revision)
VALUES (TRUE, 1);
