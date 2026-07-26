package database

import (
	"net/url"
	"testing"
	"time"

	"github.com/nyasharp/nyauth/internal/config"
)

func TestPostgresPoolConfigAppliesPoolTimeoutAndTLSOptions(t *testing.T) {
	t.Parallel()
	databaseConfig := config.DatabaseConfig{
		DSN:               "postgres://user:password@db.internal:5432/nyauth",
		MaxConns:          40,
		MinConns:          4,
		MaxConnLifetime:   2 * time.Hour,
		MaxConnIdleTime:   20 * time.Minute,
		HealthCheckPeriod: 30 * time.Second,
		ConnectTimeout:    7 * time.Second,
		StatementTimeout:  12 * time.Second,
		TLS: config.DatabaseTLSConfig{
			Mode:       "require",
			ServerName: "postgres.company.test",
		},
	}
	poolConfig, err := postgresPoolConfig(databaseConfig)
	if err != nil {
		t.Fatalf("postgresPoolConfig() error = %v", err)
	}
	if poolConfig.MaxConns != 40 || poolConfig.MinConns != 4 {
		t.Fatalf("pool sizes = %d/%d", poolConfig.MinConns, poolConfig.MaxConns)
	}
	if poolConfig.ConnConfig.ConnectTimeout != 7*time.Second {
		t.Fatalf("connect timeout = %s", poolConfig.ConnConfig.ConnectTimeout)
	}
	if got := poolConfig.ConnConfig.RuntimeParams["statement_timeout"]; got != "12000" {
		t.Fatalf("statement_timeout = %q", got)
	}
	if poolConfig.ConnConfig.TLSConfig == nil || poolConfig.ConnConfig.TLSConfig.ServerName != "postgres.company.test" {
		t.Fatalf("TLS config = %#v", poolConfig.ConnConfig.TLSConfig)
	}
}

func TestConfiguredPostgresDSNAppliesTLSOverrides(t *testing.T) {
	t.Parallel()
	dsn, err := configuredPostgresDSN(config.DatabaseConfig{
		DSN: "postgres://user:password@db.internal:5432/nyauth?application_name=nyauth",
		TLS: config.DatabaseTLSConfig{
			Mode:       "verify-full",
			RootCAFile: "/run/secrets/postgres-ca.pem",
		},
	})
	if err != nil {
		t.Fatalf("configuredPostgresDSN() error = %v", err)
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse configured DSN: %v", err)
	}
	query := parsed.Query()
	if query.Get("sslmode") != "verify-full" || query.Get("sslrootcert") != "/run/secrets/postgres-ca.pem" || query.Get("application_name") != "nyauth" {
		t.Fatalf("configured DSN query = %v", query)
	}
}

func TestNewRedisClientAppliesPoolTimeoutAndTLSOptions(t *testing.T) {
	t.Parallel()
	client, err := NewRedisClient(config.RedisConfig{
		Addr:            "redis.internal:6379",
		Username:        "nyauth",
		Password:        "secret",
		DB:              2,
		PoolSize:        30,
		MinIdleConns:    3,
		MaxIdleConns:    10,
		DialTimeout:     6 * time.Second,
		ReadTimeout:     4 * time.Second,
		WriteTimeout:    5 * time.Second,
		PoolTimeout:     8 * time.Second,
		ConnMaxIdleTime: 10 * time.Minute,
		ConnMaxLifetime: time.Hour,
		TLS: config.RedisTLSConfig{
			Enabled:    true,
			ServerName: "redis.company.test",
		},
	})
	if err != nil {
		t.Fatalf("NewRedisClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	options := client.Options()
	if options.PoolSize != 30 || options.MinIdleConns != 3 || options.MaxIdleConns != 10 || options.MaxActiveConns != 30 {
		t.Fatalf("pool options = %#v", options)
	}
	if options.DialTimeout != 6*time.Second || options.ReadTimeout != 4*time.Second || options.WriteTimeout != 5*time.Second {
		t.Fatalf("timeouts = %#v", options)
	}
	if options.TLSConfig == nil || options.TLSConfig.ServerName != "redis.company.test" || options.TLSConfig.MinVersion == 0 {
		t.Fatalf("TLS config = %#v", options.TLSConfig)
	}
}
