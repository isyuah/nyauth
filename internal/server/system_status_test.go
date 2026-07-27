package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nyasharp/nyauth/internal/buildinfo"
	"github.com/nyasharp/nyauth/internal/avatar"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/mailruntime"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestCollectSystemStatusReportsHealthyRuntime(t *testing.T) {
	started := time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC)
	response := collectSystemStatus(context.Background(), 24*time.Hour, systemStatusSources{
		pingPostgreSQL: func(context.Context) error { return nil },
		pingRedis:      func(context.Context) error { return nil },
		readSchema: func(context.Context) (systemSchemaSnapshot, error) {
			return systemSchemaSnapshot{version: database.SchemaVersion, rows: 1}, nil
		},
		readSigningKey: func(context.Context) (*models.JWK, error) {
			return &models.JWK{Kid: "public-kid", Status: models.JWKStatusSigning, SigningStartedAt: started}, nil
		},
		providerState: func() (bool, uint64) { return true, 17 },
	})
	if response.Status != "ok" || response.Version != buildinfo.Version {
		t.Fatalf("status = %#v", response)
	}
	if response.Schema.Status != "ok" || response.Schema.Version != database.SchemaVersion {
		t.Fatalf("schema = %#v", response.Schema)
	}
	if response.Services.PostgreSQL.Status != "ok" || response.Services.Redis.Status != "ok" || response.Services.JWK.Status != "ok" || response.Services.Providers.Status != "ok" {
		t.Fatalf("services = %#v", response.Services)
	}
	if response.Services.Providers.SnapshotRevision != 17 {
		t.Fatalf("provider revision = %d", response.Services.Providers.SnapshotRevision)
	}
	if response.ActiveSigningKey == nil || response.ActiveSigningKey.Kid != "public-kid" || !response.ActiveSigningKey.NextRotationAt.Equal(started.Add(24*time.Hour)) {
		t.Fatalf("signing key = %#v", response.ActiveSigningKey)
	}
}

func TestCollectSystemStatusDoesNotExposeDependencyErrors(t *testing.T) {
	response := collectSystemStatus(context.Background(), time.Hour, systemStatusSources{
		pingPostgreSQL: func(context.Context) error { return errors.New("postgres://user:password@secret-host/db") },
		pingRedis:      func(context.Context) error { return errors.New("redis password secret") },
		readSchema: func(context.Context) (systemSchemaSnapshot, error) {
			return systemSchemaSnapshot{version: database.SchemaVersion, rows: 1}, errors.New("schema internal error")
		},
		readSigningKey: func(context.Context) (*models.JWK, error) {
			return nil, errors.New("encrypted private key detail")
		},
		providerState: func() (bool, uint64) { return false, 2 },
	})
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"password", "secret-host", "internal error", "private key detail"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("system status leaked %q: %s", secret, encoded)
		}
	}
	if response.Status != "degraded" || response.Schema.Status != "unavailable" || response.ActiveSigningKey != nil {
		t.Fatalf("status = %#v", response)
	}
	if response.Services.PostgreSQL.Status != "unavailable" || response.Services.Redis.Status != "unavailable" || response.Services.JWK.Status != "unavailable" || response.Services.Providers.Status != "not_ready" {
		t.Fatalf("services = %#v", response.Services)
	}
}

func TestCollectSystemStatusMarksDirtySchemaIncompatible(t *testing.T) {
	response := collectSystemStatus(context.Background(), time.Hour, systemStatusSources{
		pingPostgreSQL: func(context.Context) error { return nil },
		pingRedis:      func(context.Context) error { return nil },
		readSchema: func(context.Context) (systemSchemaSnapshot, error) {
			return systemSchemaSnapshot{version: database.SchemaVersion, dirty: true, rows: 1}, nil
		},
		readSigningKey: func(context.Context) (*models.JWK, error) {
			return &models.JWK{Kid: "kid", Status: models.JWKStatusSigning, SigningStartedAt: time.Now()}, nil
		},
		providerState: func() (bool, uint64) { return true, 1 },
	})
	if response.Status != "degraded" || response.Schema.Status != "incompatible" {
		t.Fatalf("status = %#v", response)
	}
}

func TestCollectSystemStatusReportsMailRuntimeWithoutAffectingReadinessDependencies(t *testing.T) {
	baseSources := func(mailState mailruntime.RuntimeStatus) systemStatusSources {
		return systemStatusSources{
			pingPostgreSQL: func(context.Context) error { return nil },
			pingRedis:      func(context.Context) error { return nil },
			readSchema: func(context.Context) (systemSchemaSnapshot, error) {
				return systemSchemaSnapshot{version: database.SchemaVersion, rows: 1}, nil
			},
			readSigningKey: func(context.Context) (*models.JWK, error) {
				return &models.JWK{Kid: "kid", Status: models.JWKStatusSigning, SigningStartedAt: time.Now()}, nil
			},
			providerState: func() (bool, uint64) { return true, 1 },
			mailState:     func() mailruntime.RuntimeStatus { return mailState },
		}
	}

	tests := []struct {
		name          string
		mail          mailruntime.RuntimeStatus
		wantOverall   string
		wantComponent string
	}{
		{
			name: "available",
			mail: mailruntime.RuntimeStatus{
				Mode: mailruntime.ModeActive, Configured: true, Available: true,
				CircuitState: mailruntime.CircuitClosed,
			},
			wantOverall: "ok", wantComponent: "ok",
		},
		{
			name: "open circuit",
			mail: mailruntime.RuntimeStatus{
				Mode: mailruntime.ModeActive, Configured: true, Available: false,
				CircuitState: mailruntime.CircuitOpen,
			},
			wantOverall: "degraded", wantComponent: "unavailable",
		},
		{
			name: "disabled by operator",
			mail: mailruntime.RuntimeStatus{
				Mode: mailruntime.ModeDisabled, Configured: false, Available: false,
				CircuitState: mailruntime.CircuitClosed,
			},
			wantOverall: "ok", wantComponent: "disabled",
		},
		{
			name: "not configured",
			mail: mailruntime.RuntimeStatus{
				Mode: mailruntime.ModeFallback, Configured: false, Available: false,
				CircuitState: mailruntime.CircuitClosed,
			},
			wantOverall: "ok", wantComponent: "not_configured",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := collectSystemStatus(context.Background(), time.Hour, baseSources(test.mail))
			if response.Status != test.wantOverall || response.Services.Mail.Status != test.wantComponent {
				t.Fatalf("status=%q mail=%#v", response.Status, response.Services.Mail)
			}
			if response.Services.Mail.Mode != test.mail.Mode ||
				response.Services.Mail.Configured != test.mail.Configured ||
				response.Services.Mail.Available != test.mail.Available ||
				response.Services.Mail.CircuitState != test.mail.CircuitState {
				t.Fatalf("mail response=%#v, runtime=%#v", response.Services.Mail, test.mail)
			}
			if response.Services.PostgreSQL.Status != "ok" || response.Services.Redis.Status != "ok" {
				t.Fatalf("mail state altered readiness dependencies: %#v", response.Services)
			}
		})
	}
}

func TestCollectSystemStatusReportsMediaDegradationWithoutChangingCoreDependencies(t *testing.T) {
	now := time.Now().UTC()
	response := collectSystemStatus(context.Background(), time.Hour, systemStatusSources{
		pingPostgreSQL: func(context.Context) error { return nil },
		pingRedis:      func(context.Context) error { return nil },
		readSchema: func(context.Context) (systemSchemaSnapshot, error) {
			return systemSchemaSnapshot{version: database.SchemaVersion, rows: 1}, nil
		},
		readSigningKey: func(context.Context) (*models.JWK, error) {
			return &models.JWK{Kid: "kid", Status: models.JWKStatusSigning, SigningStartedAt: now}, nil
		},
		providerState: func() (bool, uint64) { return true, 1 },
		mediaState: func() avatar.RuntimeStatus {
			return avatar.RuntimeStatus{Backend: avatar.StorageS3, Status: "degraded", Configured: true, LastErrorAt: &now}
		},
	})
	if response.Status != "degraded" || response.Services.Media.Status != "degraded" || response.Services.Media.Backend != "s3" {
		t.Fatalf("media status = %#v overall=%q", response.Services.Media, response.Status)
	}
	if response.Services.PostgreSQL.Status != "ok" || response.Services.Redis.Status != "ok" {
		t.Fatalf("media state altered core dependencies: %#v", response.Services)
	}
}
