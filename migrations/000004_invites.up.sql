-- Invitation codes and durable self-registration lifecycle state.
-- NOTE: fold into the 000001 baseline when cutting the 0.3.0 release.
CREATE TABLE invites (
    id UUID PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    note TEXT NOT NULL DEFAULT '',
    max_uses INT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT invites_max_uses_positive CHECK (max_uses >= 1),
    CONSTRAINT invites_expiry_valid CHECK (expires_at > created_at)
);
CREATE INDEX idx_invites_created_at ON invites (created_at DESC);

CREATE TABLE self_registrations (
    id UUID PRIMARY KEY,
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE SET NULL,
    invite_id UUID REFERENCES invites(id) ON DELETE RESTRICT,
    status VARCHAR(16) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    release_reason VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT self_registrations_status_valid CHECK (status IN ('pending', 'completed', 'released')),
    CONSTRAINT self_registrations_expiry_valid CHECK (expires_at > created_at),
    CONSTRAINT self_registrations_terminal_state_valid CHECK (
        (status = 'pending' AND user_id IS NOT NULL AND completed_at IS NULL AND released_at IS NULL AND release_reason IS NULL)
        OR (status = 'completed' AND completed_at IS NOT NULL AND released_at IS NULL AND release_reason IS NULL)
        OR (status = 'released' AND completed_at IS NULL AND released_at IS NOT NULL AND release_reason IS NOT NULL)
    )
);
CREATE INDEX idx_self_registrations_invite_status ON self_registrations (invite_id, status)
    WHERE invite_id IS NOT NULL;
CREATE INDEX idx_self_registrations_pending_expiry ON self_registrations (expires_at, id)
    WHERE status = 'pending';
