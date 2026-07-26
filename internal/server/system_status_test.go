package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nyasharp/nyauth/internal/buildinfo"
	"github.com/nyasharp/nyauth/internal/database"
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
