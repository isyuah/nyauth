package server

import (
	"context"
	"net/http"
	"time"

	"github.com/nyasharp/nyauth/internal/avatar"
	"github.com/nyasharp/nyauth/internal/buildinfo"
	"github.com/nyasharp/nyauth/internal/database"
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
	Status   string             `json:"status"`
	Version  string             `json:"version"`
	Schema   systemSchemaStatus `json:"schema"`
	Services struct {
		PostgreSQL systemDependencyStatus `json:"postgresql"`
		Redis      systemDependencyStatus `json:"redis"`
		Providers  systemProviderStatus   `json:"providers"`
		JWK        systemDependencyStatus `json:"jwk"`
		Mail       systemMailStatus       `json:"mail"`
		Media      systemMediaStatus      `json:"media"`
	} `json:"services"`
	ActiveSigningKey *systemSigningKeyStatus `json:"active_signing_key,omitempty"`
}

type systemSchemaSnapshot struct {
	version int64
	dirty   bool
	rows    int64
}

type systemStatusSources struct {
	pingPostgreSQL func(context.Context) error
	pingRedis      func(context.Context) error
	readSchema     func(context.Context) (systemSchemaSnapshot, error)
	readSigningKey func(context.Context) (*models.JWK, error)
	providerState  func() (bool, uint64)
	mailState      func() mailruntime.RuntimeStatus
	mediaState     func() avatar.RuntimeStatus
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
		mailState:  s.mailRuntimeStatus,
		mediaState: s.avatarService.RuntimeStatus,
	})
	writeJSON(w, http.StatusOK, response)
}

func collectSystemStatus(ctx context.Context, rotationInterval time.Duration, sources systemStatusSources) systemStatusResponse {
	response := systemStatusResponse{Status: "ok", Version: buildinfo.Version}
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
