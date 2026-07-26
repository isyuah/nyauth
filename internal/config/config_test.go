package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	t.Setenv("NYAUTH_TELEMETRY_OTLP_ENABLED", "true")
	t.Setenv("NYAUTH_TELEMETRY_OTLP_ENDPOINT", "http://collector.internal:4318/v1/metrics")
	t.Setenv("NYAUTH_AUDIT_RETENTION", "2160h")
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
	if !cfg.Telemetry.OTLP.Enabled {
		t.Fatal("OTLP telemetry env override was not applied")
	}
	if cfg.Audit.Retention != 90*24*time.Hour {
		t.Fatalf("audit maintenance configuration = %#v", cfg.Audit)
	}
}

func TestLoadRejectsUnsafeProductionConfiguration(t *testing.T) {
	t.Setenv("NYAUTH_BOOTSTRAP_ADMIN_PASSWORD", "changeme")
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

func TestLoadRejectsBootstrapPasswordFromYAML(t *testing.T) {
	_, err := Load(writeConfig(t, `
database:
  driver: postgres
  dsn: postgres://local
redis:
  addr: localhost:6379
auth:
  issuer: http://localhost:8080
  master_key: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
admin:
  password: local-password
`))
	if err == nil || !strings.Contains(err.Error(), "NYAUTH_BOOTSTRAP_ADMIN_PASSWORD") {
		t.Fatalf("Load() error = %v", err)
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

func TestLoadRejectsUnknownConfigurationKeys(t *testing.T) {
	path := writeConfig(t, `
database:
  driver: postgres
  dsn: postgres://local
redis:
  addr: localhost:6379
auth:
  issuer: http://localhost:8080
  master_key: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
providers:
  github:
    client_id: legacy-client
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() unexpectedly accepted a removed configuration key")
	}
	if !strings.Contains(err.Error(), "providers") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadReadsSecretsFromFiles(t *testing.T) {
	unsetEnvironment(t, "NYAUTH_AUTH_MASTER_KEY")
	unsetEnvironment(t, "NYAUTH_REDIS_PASSWORD")
	masterKey := filepath.Join(t.TempDir(), "master-key")
	redisPassword := filepath.Join(t.TempDir(), "redis-password")
	if err := os.WriteFile(masterKey, []byte("ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(redisPassword, []byte("file-backed-password\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NYAUTH_AUTH_MASTER_KEY_FILE", masterKey)
	t.Setenv("NYAUTH_REDIS_PASSWORD_FILE", redisPassword)
	path := writeConfig(t, `
database:
  driver: postgres
  dsn: postgres://local
redis:
  addr: localhost:6379
auth:
  issuer: http://localhost:8080
  master_key: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := string(cfg.Auth.MasterKey); got != "89abcdef0123456789abcdef01234567" {
		t.Fatalf("master key = %q", got)
	}
	if cfg.Redis.Password != "file-backed-password" {
		t.Fatalf("redis password = %q", cfg.Redis.Password)
	}
}

func TestLoadRejectsSecretValueAndFileTogether(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretPath, []byte("not-used"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NYAUTH_REDIS_PASSWORD", "direct-value")
	t.Setenv("NYAUTH_REDIS_PASSWORD_FILE", secretPath)
	_, err := Load(writeConfig(t, `
database:
  driver: postgres
  dsn: postgres://local
auth:
  issuer: http://localhost:8080
  master_key: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
`))
	if err == nil || !strings.Contains(err.Error(), "must not be set together") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadResolvesConnectionAndServerDefaults(t *testing.T) {
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
	if cfg.Database.MaxConns != 25 || cfg.Database.MinConns != 5 || cfg.Database.ConnectTimeout != 5*time.Second || cfg.Database.StatementTimeout != 15*time.Second {
		t.Fatalf("database defaults = %#v", cfg.Database)
	}
	if cfg.Redis.PoolSize != 20 || cfg.Redis.MinIdleConns != 2 || cfg.Redis.DialTimeout != 5*time.Second {
		t.Fatalf("redis defaults = %#v", cfg.Redis)
	}
	if cfg.Server.ReadinessTimeout != 3*time.Second || cfg.Server.ShutdownTimeout != 30*time.Second {
		t.Fatalf("server timeouts = %s, %s", cfg.Server.ReadinessTimeout, cfg.Server.ShutdownTimeout)
	}
}

func TestLoadRejectsPlainSMTPInProduction(t *testing.T) {
	encodedKey := base64.StdEncoding.EncodeToString([]byte("89abcdef0123456789abcdef01234567"))
	t.Setenv("NYAUTH_MAIL_ENABLED", "true")
	t.Setenv("NYAUTH_MAIL_FROM_ADDRESS", "security@company.test")
	t.Setenv("NYAUTH_MAIL_PUBLIC_BASE_URL", "https://auth.company.test")
	t.Setenv("NYAUTH_MAIL_SMTP_HOST", "smtp.company.test")
	t.Setenv("NYAUTH_MAIL_SMTP_TLS_MODE", "plain")
	_, err := Load(writeConfig(t, `
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
`))
	if err == nil || !strings.Contains(err.Error(), "must not be plain") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadRejectsMailConfigurationFromYAML(t *testing.T) {
	_, err := Load(writeConfig(t, `
database:
  driver: postgres
  dsn: postgres://local
redis:
  addr: localhost:6379
auth:
  issuer: http://localhost:8080
  master_key: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
mail:
  enabled: false
`))
	if err == nil || !strings.Contains(err.Error(), "NYAUTH_MAIL_*") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadResolvesOTLPConfigAndAuthorizationFile(t *testing.T) {
	unsetEnvironment(t, "NYAUTH_TELEMETRY_OTLP_AUTHORIZATION")
	authorizationFile := filepath.Join(t.TempDir(), "otlp-authorization")
	if err := os.WriteFile(authorizationFile, []byte("Bearer collector-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NYAUTH_TELEMETRY_OTLP_ENABLED", "true")
	t.Setenv("NYAUTH_TELEMETRY_OTLP_ENDPOINT", "http://127.0.0.1:4318/v1/metrics")
	t.Setenv("NYAUTH_TELEMETRY_OTLP_EXPORT_INTERVAL", "15s")
	t.Setenv("NYAUTH_TELEMETRY_OTLP_TIMEOUT", "4s")
	t.Setenv("NYAUTH_TELEMETRY_OTLP_AUTHORIZATION_FILE", authorizationFile)

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
	if !cfg.Telemetry.OTLP.Enabled || cfg.Telemetry.OTLP.Endpoint != "http://127.0.0.1:4318/v1/metrics" {
		t.Fatalf("OTLP configuration = %#v", cfg.Telemetry.OTLP)
	}
	if cfg.Telemetry.OTLP.Authorization != "Bearer collector-secret" || cfg.Telemetry.OTLP.ExportInterval != 15*time.Second || cfg.Telemetry.OTLP.Timeout != 4*time.Second {
		t.Fatalf("resolved OTLP configuration = %#v", cfg.Telemetry.OTLP)
	}
}

func TestLoadRejectsInsecureProductionOTLP(t *testing.T) {
	encodedKey := base64.StdEncoding.EncodeToString([]byte("89abcdef0123456789abcdef01234567"))
	_, err := Load(writeConfig(t, `
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
telemetry:
  otlp:
    enabled: true
    endpoint: http://collector.internal:4318/v1/metrics
`))
	if err == nil || !strings.Contains(err.Error(), "telemetry.otlp.endpoint must use HTTPS") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadDatabaseMaintenanceIgnoresRuntimeOnlyConfiguration(t *testing.T) {
	missingSecret := filepath.Join(t.TempDir(), "not-mounted")
	for _, key := range []string{
		"NYAUTH_REDIS_PASSWORD_FILE",
		"NYAUTH_AUTH_MASTER_KEY_FILE",
		"NYAUTH_BOOTSTRAP_ADMIN_PASSWORD_FILE",
		"NYAUTH_MAIL_SMTP_PASSWORD_FILE",
		"NYAUTH_TELEMETRY_OTLP_AUTHORIZATION_FILE",
	} {
		t.Setenv(key, missingSecret)
	}
	for key, value := range map[string]string{
		"NYAUTH_REDIS_POOL_SIZE":              "not-a-number",
		"NYAUTH_AUTH_MASTER_KEY":              "not-base64",
		"NYAUTH_BOOTSTRAP_ADMIN_PASSWORD":     "not-used",
		"NYAUTH_MAIL_SMTP_PORT":               "not-a-number",
		"NYAUTH_TELEMETRY_OTLP_ENABLED":       "not-a-boolean",
		"NYAUTH_TELEMETRY_OTLP_AUTHORIZATION": "not-used",
	} {
		t.Setenv(key, value)
	}

	cfg, err := LoadDatabaseMaintenance(writeConfig(t, `
environment: production
server:
  port: 0
database:
  driver: postgres
  dsn: postgres://migrator@postgres.internal/nyauth
  runtime_role: custom_runtime
redis:
  addr: ""
auth:
  issuer: not-a-url
  master_key: invalid
admin:
  password: must-not-be-read
mail:
  enabled: true
  smtp:
    tls_mode: invalid
audit:
  retention: 48h
telemetry:
  otlp:
    enabled: true
    endpoint: not-a-url
`))
	if err != nil {
		t.Fatalf("LoadDatabaseMaintenance() error = %v", err)
	}
	if cfg.Database.RuntimeRole != "custom_runtime" || cfg.Database.MaxConns != 25 || cfg.Database.ConnectTimeout != 5*time.Second {
		t.Fatalf("database maintenance defaults = %#v", cfg.Database)
	}
	if cfg.Audit.Retention != 48*time.Hour {
		t.Fatalf("audit retention = %s", cfg.Audit.Retention)
	}
	if cfg.Redis.Password != "" || len(cfg.Auth.MasterKey) != 0 || cfg.Admin.Password != "" || cfg.Mail.SMTP.Password != "" || cfg.Telemetry.OTLP.Authorization != "" {
		t.Fatalf("runtime-only configuration was loaded: %#v", cfg)
	}
}

func TestLoadDatabaseMaintenanceReadsOnlyDatabaseSecretFile(t *testing.T) {
	unsetEnvironment(t, "NYAUTH_DATABASE_DSN")
	dsnFile := filepath.Join(t.TempDir(), "migration-dsn")
	if err := os.WriteFile(dsnFile, []byte("postgres://migrator@postgres.internal/nyauth\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NYAUTH_DATABASE_DSN_FILE", dsnFile)
	t.Setenv("NYAUTH_AUTH_MASTER_KEY_FILE", filepath.Join(t.TempDir(), "not-mounted"))

	cfg, err := LoadDatabaseMaintenance(writeConfig(t, `
database:
  driver: postgres
`))
	if err != nil {
		t.Fatalf("LoadDatabaseMaintenance() error = %v", err)
	}
	if cfg.Database.DSN != "postgres://migrator@postgres.internal/nyauth" {
		t.Fatalf("database DSN = %q", cfg.Database.DSN)
	}
	if cfg.Database.RuntimeRole != "nyauth_runtime" {
		t.Fatalf("database runtime role = %q", cfg.Database.RuntimeRole)
	}
}

func TestLoadDatabaseMaintenanceRejectsInvalidEnvironment(t *testing.T) {
	_, err := LoadDatabaseMaintenance(writeConfig(t, `
environment: staging
database:
  driver: postgres
  dsn: postgres://migrator@postgres.internal/nyauth
`))
	if err == nil || !strings.Contains(err.Error(), "environment must be") {
		t.Fatalf("LoadDatabaseMaintenance() error = %v", err)
	}
}

func unsetEnvironment(t *testing.T, key string) {
	t.Helper()
	old, existed := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(key, old)
			return
		}
		_ = os.Unsetenv(key)
	})
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
