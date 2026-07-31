package server

import (
	"context"
	"net/http"
	"time"

	"github.com/nyasharp/nyauth/internal/avatar"
	"github.com/nyasharp/nyauth/internal/buildinfo"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/humanverification"
	"github.com/nyasharp/nyauth/internal/mailruntime"
	"github.com/nyasharp/nyauth/pkg/models"
)

type systemDependencyStatus struct {
	Status    string `json:"status"`
	LatencyMS int64  `json:"latency_ms"`
}

type systemProviderStatus struct {
	Status           string `json:"status"`
	LatencyMS        int64  `json:"latency_ms"`
	SnapshotRevision uint64 `json:"snapshot_revision"`
}

type systemMailStatus struct {
	Status       string `json:"status"`
	Mode         string `json:"mode"`
	Configured   bool   `json:"configured"`
	Available    bool   `json:"available"`
	CircuitState string `json:"circuit_state"`
}

type systemMediaStatus struct {
	Status      string     `json:"status"`
	Backend     string     `json:"backend"`
	Configured  bool       `json:"configured"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
}

type systemObservabilityStatus struct {
	Status         string     `json:"status"`
	LogLevel       string     `json:"log_level"`
	DebugUntil     *time.Time `json:"debug_until,omitempty"`
	OTLPMode       string     `json:"otlp_mode"`
	OTLPConfigured bool       `json:"otlp_configured"`
	OTLPAvailable  bool       `json:"otlp_available"`
	LastExportAt   *time.Time `json:"last_export_at,omitempty"`
	LastErrorAt    *time.Time `json:"last_error_at,omitempty"`
	LastErrorCode  string     `json:"last_error_code,omitempty"`
}

type systemHumanVerificationStatus struct {
	Status     string `json:"status"`
	Mode       string `json:"mode"`
	Configured bool   `json:"configured"`
	Available  bool   `json:"available"`
	Provider   string `json:"provider,omitempty"`
}

type systemSchemaStatus struct {
	Status          string `json:"status"`
	Version         int64  `json:"version"`
	RequiredVersion int64  `json:"required_version"`
}

type systemSigningKeyStatus struct {
	Kid              string           `json:"kid"`
	Status           models.JWKStatus `json:"status"`
	SigningStartedAt time.Time        `json:"signing_started_at"`
	NextRotationAt   time.Time        `json:"next_rotation_at"`
}

type systemStatusResponse struct {
	Status         string             `json:"status"`
	OperatingState string             `json:"operating_state"`
	Version        string             `json:"version"`
	Schema         systemSchemaStatus `json:"schema"`
	Services       struct {
		PostgreSQL        systemDependencyStatus        `json:"postgresql"`
		Redis             systemDependencyStatus        `json:"redis"`
		Providers         systemProviderStatus          `json:"providers"`
		JWK               systemDependencyStatus        `json:"jwk"`
		Mail              systemMailStatus              `json:"mail"`
		Media             systemMediaStatus             `json:"media"`
		Observability     systemObservabilityStatus     `json:"observability"`
		HumanVerification systemHumanVerificationStatus `json:"human_verification"`
	} `json:"services"`
	ActiveSigningKey        *systemSigningKeyStatus  `json:"active_signing_key,omitempty"`
	DisabledRateLimitGroups []string                 `json:"disabled_rate_limit_groups"`
	OperationalAlerts       operationalAlertSnapshot `json:"operational_alerts"`
}

type systemSchemaSnapshot struct {
	version int64
	dirty   bool
	rows    int64
}

type systemStatusSources struct {
	pingPostgreSQL   func(context.Context) error
	pingRedis        func(context.Context) error
	readSchema       func(context.Context) (systemSchemaSnapshot, error)
	readSigningKey   func(context.Context) (*models.JWK, error)
	providerState    func() (bool, uint64)
	providerDegraded func() bool
	mailState        func() mailruntime.RuntimeStatus
	mediaState       func() avatar.RuntimeStatus
	operatingState   func() string
}

func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Server.ReadinessTimeout)
	defer cancel()
	response := collectSystemStatus(ctx, s.cfg.Auth.JWK.RotationInterval, systemStatusSources{
		pingPostgreSQL: func(ctx context.Context) error { return s.db.Ping(ctx) },
		pingRedis:      func(ctx context.Context) error { return s.rdb.Ping(ctx).Err() },
		readSchema: func(ctx context.Context) (systemSchemaSnapshot, error) {
			var snapshot systemSchemaSnapshot
			err := s.db.QueryRow(ctx, `SELECT COALESCE(MAX(version),0), COALESCE(BOOL_OR(dirty),FALSE), COUNT(*) FROM schema_migrations`).Scan(&snapshot.version, &snapshot.dirty, &snapshot.rows)
			return snapshot, err
		},
		readSigningKey: func(ctx context.Context) (*models.JWK, error) {
			if _, _, err := s.jwkManager.GetPrivateKey(ctx); err != nil {
				return nil, err
			}
			return s.jwkManager.GetActiveKey(ctx)
		},
		providerState: func() (bool, uint64) {
			return s.providerMgr.Ready(), s.providerMgr.SnapshotRevision()
		},
		providerDegraded: s.providerMgr.Degraded,
		mailState:        s.mailRuntimeStatus,
		mediaState:       s.avatarService.RuntimeStatus,
		operatingState: func() string {
			if s.serviceControl == nil || s.serviceControl.FailClosed() {
				return "full_pause"
			}
			return derivedOperatingState(s.serviceControl.Snapshot().PausedCapabilities)
		},
	})
	protection := s.settingsMgr.Protection()
	response.DisabledRateLimitGroups = make([]string, 0, 4)
	for _, group := range []struct {
		name    string
		enabled bool
	}{
		{"login", protection.Login.Enabled},
		{"account", protection.Account.Enabled},
		{"avatar", protection.Avatar.Enabled},
		{"mail", protection.Mail.Enabled},
	} {
		if !group.enabled {
			response.DisabledRateLimitGroups = append(response.DisabledRateLimitGroups, group.name)
		}
	}
	observability := s.settingsMgr.Observability()
	effectiveLogLevel := observability.LogLevel
	if observability.DebugUntil != nil && observability.DebugUntil.After(time.Now()) {
		effectiveLogLevel = "debug"
	}
	otlpMode := "fallback"
	if s.observabilityManager != nil {
		otlpMode = s.observabilityManager.Effective().Mode
	}
	otlpRuntime := s.telemetry.OTLPStatus()
	componentStatus := "not_configured"
	if otlpMode == "disabled" {
		componentStatus = "disabled"
	} else if otlpRuntime.Configured && otlpRuntime.Available {
		componentStatus = "ok"
	} else if otlpRuntime.Configured {
		componentStatus = "degraded"
	} else if otlpMode == "active" {
		componentStatus = "degraded"
	}
	response.Services.Observability = systemObservabilityStatus{
		Status: componentStatus, LogLevel: effectiveLogLevel, DebugUntil: observability.DebugUntil,
		OTLPMode: otlpMode, OTLPConfigured: otlpRuntime.Configured, OTLPAvailable: otlpRuntime.Available,
		LastExportAt: otlpRuntime.LastSuccessAt, LastErrorAt: otlpRuntime.LastErrorAt, LastErrorCode: otlpRuntime.LastErrorCode,
	}
	if s.operationalAlerts != nil {
		response.OperationalAlerts = s.operationalAlerts.Snapshot()
	} else {
		response.OperationalAlerts = operationalAlertSnapshot{Status: "unavailable", Active: []operationalAlert{}}
	}
	if s.humanVerification != nil {
		humanStatus := s.humanVerification.Status()
		componentStatus := "disabled"
		if humanStatus.Mode == humanverification.ModeActive && humanStatus.Available {
			componentStatus = "ok"
		} else if humanStatus.Mode == humanverification.ModeActive {
			componentStatus = "degraded"
		}
		response.Services.HumanVerification = systemHumanVerificationStatus{
			Status: componentStatus, Mode: humanStatus.Mode, Configured: humanStatus.Configured,
			Available: humanStatus.Available, Provider: humanStatus.Provider,
		}
	} else {
		response.Services.HumanVerification = systemHumanVerificationStatus{Status: "unavailable", Mode: humanverification.ModeDisabled}
	}
	writeJSON(w, http.StatusOK, response)
}

func collectSystemStatus(ctx context.Context, rotationInterval time.Duration, sources systemStatusSources) systemStatusResponse {
	response := systemStatusResponse{Status: "ok", OperatingState: "normal", Version: buildinfo.Version}
	if sources.operatingState != nil {
		response.OperatingState = sources.operatingState()
	}
	response.Schema = systemSchemaStatus{Status: "unavailable", RequiredVersion: database.SchemaVersion}

	started := time.Now()
	if err := sources.pingPostgreSQL(ctx); err != nil {
		response.Services.PostgreSQL = systemDependencyStatus{Status: "unavailable", LatencyMS: elapsedMilliseconds(started)}
		response.Status = "degraded"
	} else {
		response.Services.PostgreSQL = systemDependencyStatus{Status: "ok", LatencyMS: elapsedMilliseconds(started)}
	}

	started = time.Now()
	if err := sources.pingRedis(ctx); err != nil {
		response.Services.Redis = systemDependencyStatus{Status: "unavailable", LatencyMS: elapsedMilliseconds(started)}
		response.Status = "degraded"
	} else {
		response.Services.Redis = systemDependencyStatus{Status: "ok", LatencyMS: elapsedMilliseconds(started)}
	}

	snapshot, err := sources.readSchema(ctx)
	if err == nil {
		response.Schema.Version = snapshot.version
		if snapshot.rows == 1 && !snapshot.dirty && snapshot.version == database.SchemaVersion {
			response.Schema.Status = "ok"
		} else {
			response.Schema.Status = "incompatible"
			response.Status = "degraded"
		}
	} else {
		response.Status = "degraded"
	}

	started = time.Now()
	if key, err := sources.readSigningKey(ctx); err != nil || key == nil {
		response.Services.JWK = systemDependencyStatus{Status: "unavailable", LatencyMS: elapsedMilliseconds(started)}
		response.Status = "degraded"
	} else {
		response.Services.JWK = systemDependencyStatus{Status: "ok", LatencyMS: elapsedMilliseconds(started)}
		response.ActiveSigningKey = &systemSigningKeyStatus{
			Kid:              key.Kid,
			Status:           key.Status,
			SigningStartedAt: key.SigningStartedAt,
			NextRotationAt:   key.SigningStartedAt.Add(rotationInterval),
		}
	}

	started = time.Now()
	providersReady, revision := sources.providerState()
	providerStatus := "ok"
	if !providersReady {
		providerStatus = "not_ready"
		response.Status = "degraded"
	} else if sources.providerDegraded != nil && sources.providerDegraded() {
		providerStatus = "degraded"
		response.Status = "degraded"
	}
	response.Services.Providers = systemProviderStatus{Status: providerStatus, LatencyMS: elapsedMilliseconds(started), SnapshotRevision: revision}

	mailStatus := mailruntime.RuntimeStatus{Mode: mailruntime.ModeFallback, CircuitState: mailruntime.CircuitClosed}
	if sources.mailState != nil {
		mailStatus = sources.mailState()
	}
	componentStatus := "not_configured"
	switch {
	case mailStatus.Mode == mailruntime.ModeDisabled:
		componentStatus = "disabled"
	case mailStatus.Available:
		componentStatus = "ok"
	case mailStatus.Configured && mailStatus.CircuitState == mailruntime.CircuitOpen:
		componentStatus = "unavailable"
		response.Status = "degraded"
	case mailStatus.Configured:
		componentStatus = "degraded"
		response.Status = "degraded"
	}
	response.Services.Mail = systemMailStatus{
		Status: componentStatus, Mode: mailStatus.Mode, Configured: mailStatus.Configured,
		Available: mailStatus.Available, CircuitState: mailStatus.CircuitState,
	}
	mediaStatus := avatar.RuntimeStatus{Status: "not_configured"}
	if sources.mediaState != nil {
		mediaStatus = sources.mediaState()
	}
	response.Services.Media = systemMediaStatus{
		Status: mediaStatus.Status, Backend: string(mediaStatus.Backend), Configured: mediaStatus.Configured,
		LastErrorAt: mediaStatus.LastErrorAt,
	}
	if mediaStatus.Status == "degraded" {
		response.Status = "degraded"
	}
	return response
}

func elapsedMilliseconds(started time.Time) int64 {
	return time.Since(started).Milliseconds()
}
