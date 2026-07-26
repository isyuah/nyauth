package database

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/redis/go-redis/v9"
)

// NewPostgresPool creates a new PostgreSQL connection pool.
func NewPostgresPool(ctx context.Context, databaseConfig config.DatabaseConfig) (*pgxpool.Pool, error) {
	poolConfig, err := postgresPoolConfig(databaseConfig)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	return pool, nil
}

func postgresPoolConfig(databaseConfig config.DatabaseConfig) (*pgxpool.Config, error) {
	dsn, err := configuredPostgresDSN(databaseConfig)
	if err != nil {
		return nil, err
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("database DSN or TLS configuration is invalid")
	}
	if databaseConfig.TLS.ServerName != "" {
		if poolConfig.ConnConfig.TLSConfig == nil {
			return nil, fmt.Errorf("database.tls.server_name requires TLS to be enabled")
		}
		poolConfig.ConnConfig.TLSConfig.ServerName = databaseConfig.TLS.ServerName
		for _, fallback := range poolConfig.ConnConfig.Fallbacks {
			if fallback.TLSConfig != nil {
				fallback.TLSConfig.ServerName = databaseConfig.TLS.ServerName
			}
		}
	}
	poolConfig.MaxConns = databaseConfig.MaxConns
	poolConfig.MinConns = databaseConfig.MinConns
	poolConfig.MaxConnLifetime = databaseConfig.MaxConnLifetime
	poolConfig.MaxConnIdleTime = databaseConfig.MaxConnIdleTime
	poolConfig.HealthCheckPeriod = databaseConfig.HealthCheckPeriod
	poolConfig.ConnConfig.ConnectTimeout = databaseConfig.ConnectTimeout
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	poolConfig.ConnConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(databaseConfig.StatementTimeout.Milliseconds(), 10)
	return poolConfig, nil
}

// configuredPostgresDSN applies the configured TLS policy to a PostgreSQL URL.
// Migration connections use the same transformation as the serving pool so a
// production TLS override cannot be silently skipped by the migrate command.
func configuredPostgresDSN(databaseConfig config.DatabaseConfig) (string, error) {
	dsn := databaseConfig.DSN
	if databaseConfig.TLS.Mode == "" {
		return dsn, nil
	}
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" {
		return "", fmt.Errorf("database DSN must be an absolute postgres URL when database TLS overrides are configured")
	}
	query := parsed.Query()
	query.Set("sslmode", databaseConfig.TLS.Mode)
	if databaseConfig.TLS.RootCAFile != "" {
		query.Set("sslrootcert", databaseConfig.TLS.RootCAFile)
	}
	if databaseConfig.TLS.ClientCertFile != "" {
		query.Set("sslcert", databaseConfig.TLS.ClientCertFile)
		query.Set("sslkey", databaseConfig.TLS.ClientKeyFile)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// NewRedisClient creates a new Redis client.
func NewRedisClient(redisConfig config.RedisConfig) (*redis.Client, error) {
	options := &redis.Options{
		Addr:                  redisConfig.Addr,
		Username:              redisConfig.Username,
		Password:              redisConfig.Password,
		DB:                    redisConfig.DB,
		DialTimeout:           redisConfig.DialTimeout,
		ReadTimeout:           redisConfig.ReadTimeout,
		WriteTimeout:          redisConfig.WriteTimeout,
		ContextTimeoutEnabled: true,
		PoolSize:              redisConfig.PoolSize,
		PoolTimeout:           redisConfig.PoolTimeout,
		MinIdleConns:          redisConfig.MinIdleConns,
		MaxIdleConns:          redisConfig.MaxIdleConns,
		MaxActiveConns:        redisConfig.PoolSize,
		ConnMaxIdleTime:       redisConfig.ConnMaxIdleTime,
		ConnMaxLifetime:       redisConfig.ConnMaxLifetime,
	}
	if redisConfig.TLS.Enabled {
		tlsConfig, err := newRedisTLSConfig(redisConfig.TLS)
		if err != nil {
			return nil, err
		}
		options.TLSConfig = tlsConfig
	}
	return redis.NewClient(options), nil
}

func newRedisTLSConfig(redisTLS config.RedisTLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         redisTLS.ServerName,
		InsecureSkipVerify: redisTLS.InsecureSkipVerify, // Config validation rejects this in production.
	}
	if redisTLS.RootCAFile != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		contents, err := os.ReadFile(redisTLS.RootCAFile)
		if err != nil {
			return nil, fmt.Errorf("reading Redis root CA: %w", err)
		}
		if !roots.AppendCertsFromPEM(contents) {
			return nil, fmt.Errorf("Redis root CA file does not contain a valid PEM certificate")
		}
		tlsConfig.RootCAs = roots
	}
	if redisTLS.ClientCertFile != "" {
		certificate, err := tls.LoadX509KeyPair(redisTLS.ClientCertFile, redisTLS.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading Redis client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	return tlsConfig, nil
}
