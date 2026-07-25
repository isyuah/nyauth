package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadBindsNestedUnderscoreEnvironment(t *testing.T) {
	path := writeConfig(t, `
environment: development
database:
  driver: postgres
  dsn: postgres://local
redis:
  addr: localhost:6379
auth:
  issuer: http://localhost:8080
  master_key: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
`)
	t.Setenv("NYAUTH_SERVER_SECURE_COOKIE", "true")
	t.Setenv("NYAUTH_SERVER_TRUSTED_PROXY_CIDRS", "10.0.0.0/8,192.168.10.10/32")
	t.Setenv("NYAUTH_AUTH_ARGON2_CONCURRENCY", "7")
	t.Setenv("NYAUTH_REDIS_ADDR", "redis.internal:6379")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Server.SecureCookie {
		t.Error("secure cookie env override was not applied")
	}
	if got := cfg.Server.TrustedProxyCIDRs; len(got) != 2 || got[0] != "10.0.0.0/8" || got[1] != "192.168.10.10/32" {
		t.Fatalf("trusted proxies = %#v", got)
	}
	if cfg.Auth.Argon2Concurrency != 7 {
		t.Fatalf("argon2 concurrency = %d", cfg.Auth.Argon2Concurrency)
	}
	if cfg.Redis.Addr != "redis.internal:6379" {
		t.Fatalf("redis addr = %q", cfg.Redis.Addr)
	}
}

func TestLoadRejectsUnsafeProductionConfiguration(t *testing.T) {
	path := writeConfig(t, `
environment: production
server:
  secure_cookie: false
database:
  driver: postgres
  dsn: postgres://production
redis:
  addr: redis:6379
  password: changeme
auth:
  issuer: http://auth.example.com
  master_key: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
admin:
  password: changeme
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() unexpectedly accepted unsafe production config")
	}
	for _, want := range []string{"HTTPS", "secure_cookie", "trusted_proxy_cidrs", "redis.password", "auth.master_key", "admin.password"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestLoadAcceptsHardenedProductionConfiguration(t *testing.T) {
	encodedKey := base64.StdEncoding.EncodeToString([]byte("89abcdef0123456789abcdef01234567"))
	path := writeConfig(t, `
environment: production
server:
  secure_cookie: true
  trusted_proxy_cidrs: ["10.20.30.40/32"]
database:
  driver: postgres
  dsn: postgres://production
redis:
  addr: redis:6379
  password: a-long-random-redis-password
auth:
  issuer: https://auth.company.test
  master_key: `+encodedKey+`
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.IsProduction() {
		t.Fatal("expected production environment")
	}
	if len(cfg.Auth.MasterKey) != 32 {
		t.Fatalf("decoded master key length = %d", len(cfg.Auth.MasterKey))
	}
}

func TestLoadRejectsWrongMasterKeyLength(t *testing.T) {
	path := writeConfig(t, `
database:
  driver: postgres
  dsn: postgres://local
redis:
  addr: localhost:6379
auth:
  issuer: http://localhost:8080
  master_key: YWJj
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "exactly 32 bytes") {
		t.Fatalf("Load() error = %v", err)
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
