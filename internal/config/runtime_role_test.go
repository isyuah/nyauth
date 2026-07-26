package config

import (
	"strings"
	"testing"
)

func TestLoadDefaultsDatabaseRuntimeRole(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
database:
  driver: postgres
  dsn: postgres://local
redis:
  addr: localhost:6379
auth:
  issuer: http://localhost:8080
  master_key: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Database.RuntimeRole != "nyauth_runtime" {
		t.Fatalf("database runtime role = %q", cfg.Database.RuntimeRole)
	}
}

func TestLoadBindsDatabaseRuntimeRoleEnvironment(t *testing.T) {
	t.Setenv("NYAUTH_DATABASE_RUNTIME_ROLE", "company_auth_runtime")
	cfg, err := Load(writeConfig(t, `
database:
  driver: postgres
  dsn: postgres://local
redis:
  addr: localhost:6379
auth:
  issuer: http://localhost:8080
  master_key: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Database.RuntimeRole != "company_auth_runtime" {
		t.Fatalf("database runtime role = %q", cfg.Database.RuntimeRole)
	}
}

func TestLoadRejectsUnsafeDatabaseRuntimeRole(t *testing.T) {
	_, err := Load(writeConfig(t, `
database:
  driver: postgres
  dsn: postgres://local
  runtime_role: "runtime; DROP SCHEMA public"
redis:
  addr: localhost:6379
auth:
  issuer: http://localhost:8080
  master_key: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
`))
	if err == nil || !strings.Contains(err.Error(), "database.runtime_role") {
		t.Fatalf("Load() error = %v", err)
	}
}
