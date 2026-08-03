CREATE TABLE oauth_client_stats_daily (
    client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    day DATE NOT NULL,
    flow VARCHAR(32) NOT NULL,
    stage VARCHAR(32) NOT NULL,
    success_count BIGINT NOT NULL DEFAULT 0,
    failure_count BIGINT NOT NULL DEFAULT 0,
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,
    PRIMARY KEY (client_id, day, flow, stage),
    CONSTRAINT oauth_client_stats_flow_valid CHECK (flow IN ('authorization_code','client_credentials','refresh_token','device_authorization')),
    CONSTRAINT oauth_client_stats_stage_valid CHECK (stage IN ('authorization','consent','token','device_authorization','device_verification')),
    CONSTRAINT oauth_client_stats_counts_nonnegative CHECK (success_count >= 0 AND failure_count >= 0)
);

CREATE INDEX idx_oauth_client_stats_day ON oauth_client_stats_daily (day DESC, client_id);

CREATE TABLE oauth_client_diagnostics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    request_id VARCHAR(128),
    flow VARCHAR(32) NOT NULL,
    stage VARCHAR(32) NOT NULL,
    reason VARCHAR(64) NOT NULL,
    redirect_uri TEXT,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    CONSTRAINT oauth_client_diagnostics_flow_valid CHECK (flow IN ('authorization_code','client_credentials','refresh_token','device_authorization')),
    CONSTRAINT oauth_client_diagnostics_stage_valid CHECK (stage IN ('authorization','consent','token','device_authorization','device_verification')),
    CONSTRAINT oauth_client_diagnostics_reason_valid CHECK (reason IN (
        'invalid_request','invalid_client','redirect_uri_mismatch','invalid_state','grant_not_allowed',
        'invalid_scope','invalid_pkce','invalid_nonce','access_denied','client_changed',
        'invalid_scope_selection','invalid_or_expired_code','code_binding_validation',
        'scope_no_longer_allowed','claim_no_longer_allowed','invalid_subject','inactive_subject',
        'authorization_inactive','token_issuance_failed','id_token_issuance_failed',
        'code_reuse','code_reuse_revocation_failed','invalid_refresh','refresh_reuse',
        'authorization_pending','slow_down','expired_token','user_denied','service_paused','rate_limited',
        'temporarily_unavailable','server_error'
    )),
    CONSTRAINT oauth_client_diagnostics_request_id_not_blank CHECK (request_id IS NULL OR btrim(request_id) <> ''),
    CONSTRAINT oauth_client_diagnostics_redirect_uri_not_blank CHECK (redirect_uri IS NULL OR btrim(redirect_uri) <> ''),
    CONSTRAINT oauth_client_diagnostics_scopes_no_null CHECK (array_position(scopes, NULL) IS NULL)
);

CREATE INDEX idx_oauth_client_diagnostics_client_time ON oauth_client_diagnostics (client_id, occurred_at DESC, id DESC);
CREATE INDEX idx_oauth_client_diagnostics_reason_time ON oauth_client_diagnostics (client_id, reason, occurred_at DESC);

CREATE TABLE provider_diagnostic_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES oauth_providers(id) ON DELETE CASCADE,
    provider_revision BIGINT NOT NULL,
    mode VARCHAR(16) NOT NULL,
    result VARCHAR(16) NOT NULL,
    checks JSONB NOT NULL DEFAULT '[]'::JSONB,
    initiated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT provider_diagnostic_runs_mode_valid CHECK (mode IN ('preflight','interactive')),
    CONSTRAINT provider_diagnostic_runs_result_valid CHECK (result IN ('success','failure')),
    CONSTRAINT provider_diagnostic_runs_revision_positive CHECK (provider_revision > 0),
    CONSTRAINT provider_diagnostic_runs_checks_array CHECK (jsonb_typeof(checks) = 'array')
);

CREATE INDEX idx_provider_diagnostic_runs_provider_time ON provider_diagnostic_runs (provider_id, created_at DESC, id DESC);
