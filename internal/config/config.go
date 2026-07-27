package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	stdmail "net/mail"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

const developmentMasterKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

type Config struct {
	Environment string          `mapstructure:"environment"`
	Server      ServerConfig    `mapstructure:"server"`
	Database    DatabaseConfig  `mapstructure:"database"`
	Redis       RedisConfig     `mapstructure:"redis"`
	Auth        AuthConfig      `mapstructure:"auth"`
	Admin       AdminConfig     `mapstructure:"admin"`
	Web         WebConfig       `mapstructure:"web"`
	Mail        MailConfig      `mapstructure:"mail"`
	Media       MediaConfig     `mapstructure:"media"`
	Audit       AuditConfig     `mapstructure:"audit"`
	Telemetry   TelemetryConfig `mapstructure:"telemetry"`
}

type ServerConfig struct {
	Host                string        `mapstructure:"host"`
	Port                int           `mapstructure:"port"`
	SecureCookie        bool          `mapstructure:"secure_cookie"`
	TrustedProxyCIDRs   []string      `mapstructure:"trusted_proxy_cidrs"`
	TLS                 TLSConfig     `mapstructure:"tls"`
	ReadinessTimeoutRaw string        `mapstructure:"readiness_timeout"`
	ShutdownTimeoutRaw  string        `mapstructure:"shutdown_timeout"`
	ReadinessTimeout    time.Duration `mapstructure:"-"`
	ShutdownTimeout     time.Duration `mapstructure:"-"`
}
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}
type DatabaseConfig struct {
	Driver               string            `mapstructure:"driver"`
	DSN                  string            `mapstructure:"dsn"`
	RuntimeRole          string            `mapstructure:"runtime_role"`
	MaxConns             int32             `mapstructure:"max_conns"`
	MinConns             int32             `mapstructure:"min_conns"`
	MaxConnLifetimeRaw   string            `mapstructure:"max_conn_lifetime"`
	MaxConnIdleTimeRaw   string            `mapstructure:"max_conn_idle_time"`
	HealthCheckPeriodRaw string            `mapstructure:"health_check_period"`
	ConnectTimeoutRaw    string            `mapstructure:"connect_timeout"`
	StatementTimeoutRaw  string            `mapstructure:"statement_timeout"`
	TLS                  DatabaseTLSConfig `mapstructure:"tls"`
	MaxConnLifetime      time.Duration     `mapstructure:"-"`
	MaxConnIdleTime      time.Duration     `mapstructure:"-"`
	HealthCheckPeriod    time.Duration     `mapstructure:"-"`
	ConnectTimeout       time.Duration     `mapstructure:"-"`
	StatementTimeout     time.Duration     `mapstructure:"-"`
}

var postgresRoleNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]{0,62}$`)

type DatabaseTLSConfig struct {
	Mode           string `mapstructure:"mode"`
	RootCAFile     string `mapstructure:"root_ca_file"`
	ClientCertFile string `mapstructure:"client_cert_file"`
	ClientKeyFile  string `mapstructure:"client_key_file"`
	ServerName     string `mapstructure:"server_name"`
}

type RedisConfig struct {
	Addr               string         `mapstructure:"addr"`
	Username           string         `mapstructure:"username"`
	Password           string         `mapstructure:"password"`
	DB                 int            `mapstructure:"db"`
	PoolSize           int            `mapstructure:"pool_size"`
	MinIdleConns       int            `mapstructure:"min_idle_conns"`
	MaxIdleConns       int            `mapstructure:"max_idle_conns"`
	DialTimeoutRaw     string         `mapstructure:"dial_timeout"`
	ReadTimeoutRaw     string         `mapstructure:"read_timeout"`
	WriteTimeoutRaw    string         `mapstructure:"write_timeout"`
	PoolTimeoutRaw     string         `mapstructure:"pool_timeout"`
	ConnMaxIdleTimeRaw string         `mapstructure:"conn_max_idle_time"`
	ConnMaxLifetimeRaw string         `mapstructure:"conn_max_lifetime"`
	TLS                RedisTLSConfig `mapstructure:"tls"`
	DialTimeout        time.Duration  `mapstructure:"-"`
	ReadTimeout        time.Duration  `mapstructure:"-"`
	WriteTimeout       time.Duration  `mapstructure:"-"`
	PoolTimeout        time.Duration  `mapstructure:"-"`
	ConnMaxIdleTime    time.Duration  `mapstructure:"-"`
	ConnMaxLifetime    time.Duration  `mapstructure:"-"`
}

type RedisTLSConfig struct {
	Enabled            bool   `mapstructure:"enabled"`
	RootCAFile         string `mapstructure:"root_ca_file"`
	ClientCertFile     string `mapstructure:"client_cert_file"`
	ClientKeyFile      string `mapstructure:"client_key_file"`
	ServerName         string `mapstructure:"server_name"`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
}

type AuthConfig struct {
	Issuer               string        `mapstructure:"issuer"`
	AccessTokenTTLRaw    int64         `mapstructure:"access_token_ttl"`
	RefreshTokenTTLRaw   int64         `mapstructure:"refresh_token_ttl"`
	AuthCodeTTLRaw       int64         `mapstructure:"authorization_code_ttl"`
	MasterKeyEncoded     string        `mapstructure:"master_key"`
	MasterKey            []byte        `mapstructure:"-"`
	Argon2Concurrency    int           `mapstructure:"argon2_concurrency"`
	JWK                  JWKConfig     `mapstructure:"jwk"`
	AccessTokenTTL       time.Duration `mapstructure:"-"`
	RefreshTokenTTL      time.Duration `mapstructure:"-"`
	AuthorizationCodeTTL time.Duration `mapstructure:"-"`
}
type JWKConfig struct {
	Algorithm           string        `mapstructure:"algorithm"`
	KeySize             int           `mapstructure:"key_size"`
	RotationIntervalRaw string        `mapstructure:"rotation_interval"`
	RotationInterval    time.Duration `mapstructure:"-"`
}
type AdminConfig struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Email    string `mapstructure:"email"`
}
type WebConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Title   string `mapstructure:"title"`
	LogoURL string `mapstructure:"logo_url"`
}

type MailConfig struct {
	Enabled       bool       `mapstructure:"enabled"`
	FromAddress   string     `mapstructure:"from_address"`
	FromName      string     `mapstructure:"from_name"`
	PublicBaseURL string     `mapstructure:"public_base_url"`
	SMTP          SMTPConfig `mapstructure:"smtp"`
}

type SMTPConfig struct {
	Host              string        `mapstructure:"host"`
	Port              int           `mapstructure:"port"`
	Username          string        `mapstructure:"username"`
	Password          string        `mapstructure:"password"`
	TLSMode           string        `mapstructure:"tls_mode"`
	ConnectTimeoutRaw string        `mapstructure:"connect_timeout"`
	SendTimeoutRaw    string        `mapstructure:"send_timeout"`
	ConnectTimeout    time.Duration `mapstructure:"-"`
	SendTimeout       time.Duration `mapstructure:"-"`
}

type MediaConfig struct {
	Backend string           `mapstructure:"backend"`
	Local   LocalMediaConfig `mapstructure:"local"`
	S3      S3MediaConfig    `mapstructure:"s3"`
}

type LocalMediaConfig struct {
	Directory string `mapstructure:"directory"`
}

type S3MediaConfig struct {
	Endpoint        string `mapstructure:"endpoint"`
	Region          string `mapstructure:"region"`
	Bucket          string `mapstructure:"bucket"`
	Prefix          string `mapstructure:"prefix"`
	PathStyle       bool   `mapstructure:"path_style"`
	AccessKeyID     string `mapstructure:"access_key_id"`
	SecretAccessKey string `mapstructure:"secret_access_key"`
	SessionToken    string `mapstructure:"session_token"`
}

type AuditConfig struct {
	RetentionRaw string        `mapstructure:"retention"`
	Retention    time.Duration `mapstructure:"-"`
}

type TelemetryConfig struct {
	OTLP OTLPMetricsConfig `mapstructure:"otlp"`
}

type OTLPMetricsConfig struct {
	Enabled           bool          `mapstructure:"enabled"`
	Endpoint          string        `mapstructure:"endpoint"`
	Authorization     string        `mapstructure:"authorization"`
	ExportIntervalRaw string        `mapstructure:"export_interval"`
	TimeoutRaw        string        `mapstructure:"timeout"`
	ExportInterval    time.Duration `mapstructure:"-"`
	Timeout           time.Duration `mapstructure:"-"`
}

func (cfg *Config) IsProduction() bool { return cfg.Environment == "production" }

func (cfg *Config) Resolve() error {
	cfg.Environment = strings.ToLower(strings.TrimSpace(cfg.Environment))
	if cfg.Environment == "" {
		cfg.Environment = "development"
	}
	var err error
	if cfg.Server.ReadinessTimeout, err = parsePositiveDuration("server.readiness_timeout", cfg.Server.ReadinessTimeoutRaw, 3*time.Second); err != nil {
		return err
	}
	if cfg.Server.ShutdownTimeout, err = parsePositiveDuration("server.shutdown_timeout", cfg.Server.ShutdownTimeoutRaw, 30*time.Second); err != nil {
		return err
	}
	d := &cfg.Database
	d.RuntimeRole = strings.TrimSpace(d.RuntimeRole)
	if d.MaxConnLifetime, err = parsePositiveDuration("database.max_conn_lifetime", d.MaxConnLifetimeRaw, time.Hour); err != nil {
		return err
	}
	if d.MaxConnIdleTime, err = parsePositiveDuration("database.max_conn_idle_time", d.MaxConnIdleTimeRaw, 30*time.Minute); err != nil {
		return err
	}
	if d.HealthCheckPeriod, err = parsePositiveDuration("database.health_check_period", d.HealthCheckPeriodRaw, time.Minute); err != nil {
		return err
	}
	if d.ConnectTimeout, err = parsePositiveDuration("database.connect_timeout", d.ConnectTimeoutRaw, 5*time.Second); err != nil {
		return err
	}
	if d.StatementTimeout, err = parsePositiveDuration("database.statement_timeout", d.StatementTimeoutRaw, 15*time.Second); err != nil {
		return err
	}
	d.TLS.Mode = strings.ToLower(strings.TrimSpace(d.TLS.Mode))
	r := &cfg.Redis
	if r.MaxIdleConns == 0 {
		r.MaxIdleConns = r.PoolSize
	}
	if r.DialTimeout, err = parsePositiveDuration("redis.dial_timeout", r.DialTimeoutRaw, 5*time.Second); err != nil {
		return err
	}
	if r.ReadTimeout, err = parsePositiveDuration("redis.read_timeout", r.ReadTimeoutRaw, 3*time.Second); err != nil {
		return err
	}
	if r.WriteTimeout, err = parsePositiveDuration("redis.write_timeout", r.WriteTimeoutRaw, 3*time.Second); err != nil {
		return err
	}
	if r.PoolTimeout, err = parsePositiveDuration("redis.pool_timeout", r.PoolTimeoutRaw, 4*time.Second); err != nil {
		return err
	}
	if r.ConnMaxIdleTime, err = parsePositiveDuration("redis.conn_max_idle_time", r.ConnMaxIdleTimeRaw, 30*time.Minute); err != nil {
		return err
	}
	if r.ConnMaxLifetime, err = parsePositiveDuration("redis.conn_max_lifetime", r.ConnMaxLifetimeRaw, time.Hour); err != nil {
		return err
	}
	m := &cfg.Mail.SMTP
	m.TLSMode = strings.ToLower(strings.TrimSpace(m.TLSMode))
	if m.TLSMode == "" {
		m.TLSMode = "starttls"
	}
	if m.ConnectTimeout, err = parsePositiveDuration("mail.smtp.connect_timeout", m.ConnectTimeoutRaw, 10*time.Second); err != nil {
		return err
	}
	if m.SendTimeout, err = parsePositiveDuration("mail.smtp.send_timeout", m.SendTimeoutRaw, 30*time.Second); err != nil {
		return err
	}
	if cfg.Audit.Retention, err = parsePositiveDuration("audit.retention", cfg.Audit.RetentionRaw, 365*24*time.Hour); err != nil {
		return err
	}
	media := &cfg.Media
	media.Backend = strings.ToLower(strings.TrimSpace(media.Backend))
	if media.Backend == "" {
		media.Backend = "local"
	}
	media.Local.Directory = strings.TrimSpace(media.Local.Directory)
	media.S3.Endpoint = strings.TrimSpace(media.S3.Endpoint)
	media.S3.Region = strings.TrimSpace(media.S3.Region)
	media.S3.Bucket = strings.TrimSpace(media.S3.Bucket)
	media.S3.Prefix = strings.Trim(strings.TrimSpace(media.S3.Prefix), "/")
	otlp := &cfg.Telemetry.OTLP
	otlp.Endpoint = strings.TrimSpace(otlp.Endpoint)
	if otlp.ExportInterval, err = parsePositiveDuration("telemetry.otlp.export_interval", otlp.ExportIntervalRaw, 30*time.Second); err != nil {
		return err
	}
	if otlp.Timeout, err = parsePositiveDuration("telemetry.otlp.timeout", otlp.TimeoutRaw, 10*time.Second); err != nil {
		return err
	}
	a := &cfg.Auth
	if a.AccessTokenTTLRaw > 0 {
		a.AccessTokenTTL = time.Duration(a.AccessTokenTTLRaw) * time.Second
	} else {
		a.AccessTokenTTL = time.Hour
	}
	if a.RefreshTokenTTLRaw > 0 {
		a.RefreshTokenTTL = time.Duration(a.RefreshTokenTTLRaw) * time.Second
	} else {
		a.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if a.AuthCodeTTLRaw > 0 {
		a.AuthorizationCodeTTL = time.Duration(a.AuthCodeTTLRaw) * time.Second
	} else {
		a.AuthorizationCodeTTL = 5 * time.Minute
	}
	if a.Argon2Concurrency == 0 {
		a.Argon2Concurrency = 4
	}
	if a.JWK.Algorithm == "" {
		a.JWK.Algorithm = "RS256"
	}
	if a.JWK.KeySize == 0 {
		a.JWK.KeySize = 2048
	}
	if a.JWK.RotationIntervalRaw == "" {
		a.JWK.RotationIntervalRaw = "720h"
	}
	rotation, err := time.ParseDuration(a.JWK.RotationIntervalRaw)
	if err != nil {
		return fmt.Errorf("parsing auth.jwk.rotation_interval: %w", err)
	}
	a.JWK.RotationInterval = rotation
	key, err := base64.StdEncoding.DecodeString(a.MasterKeyEncoded)
	if err != nil {
		return fmt.Errorf("auth.master_key must be standard Base64: %w", err)
	}
	if len(key) != 32 {
		return fmt.Errorf("auth.master_key must decode to exactly 32 bytes")
	}
	a.MasterKey = key
	return nil
}

func parsePositiveDuration(field, raw string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parsing %s: %w", field, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be positive", field)
	}
	return value, nil
}

func (cfg *Config) Validate() error {
	var errs []error
	if cfg.Environment != "development" && cfg.Environment != "test" && cfg.Environment != "production" {
		errs = append(errs, fmt.Errorf("environment must be development, test, or production"))
	}
	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		errs = append(errs, fmt.Errorf("server.port must be between 1 and 65535"))
	}
	if cfg.Database.Driver != "postgres" {
		errs = append(errs, fmt.Errorf("database.driver must be postgres"))
	}
	if strings.TrimSpace(cfg.Database.DSN) == "" {
		errs = append(errs, fmt.Errorf("database.dsn is required"))
	} else if parsed, err := url.Parse(cfg.Database.DSN); err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" {
		errs = append(errs, fmt.Errorf("database.dsn must be an absolute postgres:// or postgresql:// URL"))
	}
	if !postgresRoleNamePattern.MatchString(cfg.Database.RuntimeRole) {
		errs = append(errs, fmt.Errorf("database.runtime_role must be a PostgreSQL role name containing at most 63 ASCII letters, digits, underscores, or dollar signs"))
	}
	if cfg.Database.MaxConns < 1 {
		errs = append(errs, fmt.Errorf("database.max_conns must be positive"))
	}
	if cfg.Database.MinConns < 0 || cfg.Database.MinConns > cfg.Database.MaxConns {
		errs = append(errs, fmt.Errorf("database.min_conns must be between 0 and database.max_conns"))
	}
	switch cfg.Database.TLS.Mode {
	case "", "disable", "require", "verify-ca", "verify-full":
	default:
		errs = append(errs, fmt.Errorf("database.tls.mode must be disable, require, verify-ca, or verify-full"))
	}
	if (cfg.Database.TLS.ClientCertFile == "") != (cfg.Database.TLS.ClientKeyFile == "") {
		errs = append(errs, fmt.Errorf("database.tls.client_cert_file and client_key_file must be configured together"))
	}
	if cfg.Database.TLS.Mode == "" && (cfg.Database.TLS.RootCAFile != "" || cfg.Database.TLS.ClientCertFile != "" || cfg.Database.TLS.ServerName != "") {
		errs = append(errs, fmt.Errorf("database.tls.mode is required when database TLS files or server_name are configured"))
	}
	if strings.TrimSpace(cfg.Redis.Addr) == "" {
		errs = append(errs, fmt.Errorf("redis.addr is required"))
	}
	if strings.ContainsAny(cfg.Redis.Password, "\r\n") {
		errs = append(errs, fmt.Errorf("redis.password must be a single-line value"))
	}
	if cfg.Redis.DB < 0 {
		errs = append(errs, fmt.Errorf("redis.db must not be negative"))
	}
	if cfg.Redis.PoolSize < 1 {
		errs = append(errs, fmt.Errorf("redis.pool_size must be positive"))
	}
	if cfg.Redis.MinIdleConns < 0 || cfg.Redis.MinIdleConns > cfg.Redis.PoolSize {
		errs = append(errs, fmt.Errorf("redis.min_idle_conns must be between 0 and redis.pool_size"))
	}
	if cfg.Redis.MaxIdleConns < 0 || cfg.Redis.MaxIdleConns > cfg.Redis.PoolSize || cfg.Redis.MaxIdleConns < cfg.Redis.MinIdleConns {
		errs = append(errs, fmt.Errorf("redis.max_idle_conns must be between redis.min_idle_conns and redis.pool_size"))
	}
	if (cfg.Redis.TLS.ClientCertFile == "") != (cfg.Redis.TLS.ClientKeyFile == "") {
		errs = append(errs, fmt.Errorf("redis.tls.client_cert_file and client_key_file must be configured together"))
	}
	if !cfg.Redis.TLS.Enabled && (cfg.Redis.TLS.RootCAFile != "" || cfg.Redis.TLS.ClientCertFile != "" || cfg.Redis.TLS.ServerName != "" || cfg.Redis.TLS.InsecureSkipVerify) {
		errs = append(errs, fmt.Errorf("redis.tls.enabled must be true when Redis TLS options are configured"))
	}
	if cfg.Auth.Argon2Concurrency < 1 || cfg.Auth.Argon2Concurrency > 64 {
		errs = append(errs, fmt.Errorf("auth.argon2_concurrency must be between 1 and 64"))
	}
	if cfg.Auth.JWK.Algorithm != "RS256" {
		errs = append(errs, fmt.Errorf("auth.jwk.algorithm must be RS256"))
	}
	if cfg.Auth.JWK.KeySize < 2048 {
		errs = append(errs, fmt.Errorf("auth.jwk.key_size must be at least 2048"))
	}
	if cfg.Auth.JWK.RotationInterval <= 0 {
		errs = append(errs, fmt.Errorf("auth.jwk.rotation_interval must be positive"))
	}
	issuer, err := url.Parse(cfg.Auth.Issuer)
	if err != nil || issuer.Host == "" || (issuer.Scheme != "http" && issuer.Scheme != "https") || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		errs = append(errs, fmt.Errorf("auth.issuer must be an absolute HTTP(S) URL without credentials, query, or fragment"))
	}
	for _, cidr := range cfg.Server.TrustedProxyCIDRs {
		_, network, parseErr := net.ParseCIDR(strings.TrimSpace(cidr))
		if parseErr != nil {
			errs = append(errs, fmt.Errorf("server.trusted_proxy_cidrs contains invalid CIDR %q", cidr))
			continue
		}
		ones, _ := network.Mask.Size()
		if cfg.IsProduction() && ones == 0 {
			errs = append(errs, fmt.Errorf("server.trusted_proxy_cidrs must not trust the entire Internet in production"))
		}
	}
	if cfg.Mail.Enabled {
		if strings.TrimSpace(cfg.Mail.FromAddress) == "" {
			errs = append(errs, fmt.Errorf("mail.from_address is required when mail is enabled"))
		} else if _, err := stdmail.ParseAddress(cfg.Mail.FromAddress); err != nil {
			errs = append(errs, fmt.Errorf("mail.from_address must be a valid email address"))
		}
		mailURL, err := url.Parse(cfg.Mail.PublicBaseURL)
		if err != nil || mailURL.Host == "" || (mailURL.Scheme != "http" && mailURL.Scheme != "https") || mailURL.User != nil || mailURL.RawQuery != "" || mailURL.Fragment != "" {
			errs = append(errs, fmt.Errorf("mail.public_base_url must be an absolute HTTP(S) URL without credentials, query, or fragment"))
		}
		if strings.TrimSpace(cfg.Mail.SMTP.Host) == "" {
			errs = append(errs, fmt.Errorf("mail.smtp.host is required when mail is enabled"))
		}
		if cfg.Mail.SMTP.Port < 1 || cfg.Mail.SMTP.Port > 65535 {
			errs = append(errs, fmt.Errorf("mail.smtp.port must be between 1 and 65535"))
		}
		switch cfg.Mail.SMTP.TLSMode {
		case "starttls", "implicit", "plain":
		default:
			errs = append(errs, fmt.Errorf("mail.smtp.tls_mode must be starttls, implicit, or plain"))
		}
	}
	switch cfg.Media.Backend {
	case "local":
		if cfg.Media.Local.Directory == "" {
			errs = append(errs, fmt.Errorf("media.local.directory is required when media.backend is local"))
		}
	case "s3":
		if cfg.Media.S3.Bucket == "" {
			errs = append(errs, fmt.Errorf("media.s3.bucket is required when media.backend is s3"))
		}
		if cfg.Media.S3.Region == "" {
			errs = append(errs, fmt.Errorf("media.s3.region is required when media.backend is s3"))
		}
		if cfg.Media.S3.AccessKeyID == "" {
			errs = append(errs, fmt.Errorf("media.s3.access_key_id is required when media.backend is s3"))
		}
		if cfg.Media.S3.SecretAccessKey == "" {
			errs = append(errs, fmt.Errorf("media.s3.secret_access_key is required when media.backend is s3"))
		}
		if strings.ContainsAny(cfg.Media.S3.AccessKeyID+cfg.Media.S3.SecretAccessKey+cfg.Media.S3.SessionToken, "\r\n") {
			errs = append(errs, fmt.Errorf("media.s3 credentials must be single-line values"))
		}
		if strings.Contains(cfg.Media.S3.Bucket, "/") || strings.Contains(cfg.Media.S3.Prefix, "\\") {
			errs = append(errs, fmt.Errorf("media.s3.bucket and media.s3.prefix must be object storage names, not filesystem paths"))
		}
		if cfg.Media.S3.Endpoint != "" {
			endpoint, err := url.Parse(cfg.Media.S3.Endpoint)
			if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
				errs = append(errs, fmt.Errorf("media.s3.endpoint must be an absolute HTTP(S) URL without credentials, query, or fragment"))
			} else if cfg.IsProduction() && endpoint.Scheme != "https" {
				errs = append(errs, fmt.Errorf("media.s3.endpoint must use HTTPS in production"))
			}
		}
	default:
		errs = append(errs, fmt.Errorf("media.backend must be local or s3"))
	}
	if strings.ContainsAny(cfg.Telemetry.OTLP.Authorization, "\r\n") {
		errs = append(errs, fmt.Errorf("telemetry.otlp.authorization must be a single-line value"))
	}
	var otlpEndpoint *url.URL
	if cfg.Telemetry.OTLP.Endpoint != "" {
		parsed, parseErr := url.Parse(cfg.Telemetry.OTLP.Endpoint)
		if parseErr != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			errs = append(errs, fmt.Errorf("telemetry.otlp.endpoint must be an absolute HTTP(S) URL without credentials, query, or fragment"))
		} else {
			otlpEndpoint = parsed
		}
	}
	if cfg.Telemetry.OTLP.Enabled && otlpEndpoint == nil {
		errs = append(errs, fmt.Errorf("telemetry.otlp.endpoint is required when OTLP is enabled"))
	}
	if cfg.IsProduction() {
		if issuer == nil || issuer.Scheme != "https" {
			errs = append(errs, fmt.Errorf("auth.issuer must use HTTPS in production"))
		}
		if issuer != nil {
			host := strings.ToLower(issuer.Hostname())
			if host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "example.com" || strings.HasSuffix(host, ".example.com") {
				errs = append(errs, fmt.Errorf("auth.issuer must not use a local or example hostname in production"))
			}
		}
		if !cfg.Server.SecureCookie {
			errs = append(errs, fmt.Errorf("server.secure_cookie must be true in production"))
		}
		if len(cfg.Server.TrustedProxyCIDRs) == 0 {
			errs = append(errs, fmt.Errorf("server.trusted_proxy_cidrs must identify the production reverse proxy"))
		}
		if len(cfg.Redis.Password) < 16 || isPlaceholder(cfg.Redis.Password) {
			errs = append(errs, fmt.Errorf("redis.password must be a non-placeholder value of at least 16 characters in production"))
		}
		if cfg.Auth.MasterKeyEncoded == developmentMasterKey || allBytesEqual(cfg.Auth.MasterKey) {
			errs = append(errs, fmt.Errorf("auth.master_key must not use an example or repeated-byte key in production"))
		}
		if cfg.Admin.Password != "" && (len(cfg.Admin.Password) < 12 || isPlaceholder(cfg.Admin.Password)) {
			errs = append(errs, fmt.Errorf("admin.password must be a non-placeholder value of at least 12 characters when provided"))
		}
		if cfg.Redis.TLS.InsecureSkipVerify {
			errs = append(errs, fmt.Errorf("redis.tls.insecure_skip_verify must be false in production"))
		}
		if cfg.Mail.Enabled {
			mailURL, _ := url.Parse(cfg.Mail.PublicBaseURL)
			if mailURL == nil || mailURL.Scheme != "https" {
				errs = append(errs, fmt.Errorf("mail.public_base_url must use HTTPS in production"))
			}
			if cfg.Mail.SMTP.TLSMode == "plain" {
				errs = append(errs, fmt.Errorf("mail.smtp.tls_mode must not be plain in production"))
			}
		}
		if cfg.Telemetry.OTLP.Enabled && otlpEndpoint != nil && otlpEndpoint.Scheme != "https" {
			errs = append(errs, fmt.Errorf("telemetry.otlp.endpoint must use HTTPS in production"))
		}
	}
	return errors.Join(errs...)
}

func isPlaceholder(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, marker := range []string{"changeme", "change-me", "replace-me", "example", "local-dev-only"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
func allBytesEqual(value []byte) bool {
	if len(value) == 0 {
		return true
	}
	for _, b := range value[1:] {
		if b != value[0] {
			return false
		}
	}
	return true
}

var envKeys = []string{
	"environment", "server.host", "server.port", "server.secure_cookie", "server.trusted_proxy_cidrs", "server.readiness_timeout", "server.shutdown_timeout", "server.tls.enabled", "server.tls.cert_file", "server.tls.key_file",
	"database.driver", "database.dsn", "database.runtime_role", "database.max_conns", "database.min_conns", "database.max_conn_lifetime", "database.max_conn_idle_time", "database.health_check_period", "database.connect_timeout", "database.statement_timeout",
	"database.tls.mode", "database.tls.root_ca_file", "database.tls.client_cert_file", "database.tls.client_key_file", "database.tls.server_name",
	"redis.addr", "redis.username", "redis.password", "redis.db", "redis.pool_size", "redis.min_idle_conns", "redis.max_idle_conns", "redis.dial_timeout", "redis.read_timeout", "redis.write_timeout", "redis.pool_timeout", "redis.conn_max_idle_time", "redis.conn_max_lifetime",
	"redis.tls.enabled", "redis.tls.root_ca_file", "redis.tls.client_cert_file", "redis.tls.client_key_file", "redis.tls.server_name", "redis.tls.insecure_skip_verify",
	"auth.issuer", "auth.access_token_ttl", "auth.refresh_token_ttl", "auth.authorization_code_ttl", "auth.master_key", "auth.argon2_concurrency", "auth.jwk.algorithm", "auth.jwk.key_size", "auth.jwk.rotation_interval",
	"web.enabled", "web.title", "web.logo_url", "mail.enabled", "mail.from_address", "mail.from_name", "mail.public_base_url", "mail.smtp.host", "mail.smtp.port", "mail.smtp.username", "mail.smtp.password", "mail.smtp.tls_mode", "mail.smtp.connect_timeout", "mail.smtp.send_timeout",
	"media.backend", "media.local.directory", "media.s3.endpoint", "media.s3.region", "media.s3.bucket", "media.s3.prefix", "media.s3.path_style", "media.s3.access_key_id", "media.s3.secret_access_key", "media.s3.session_token",
	"audit.retention",
	"telemetry.otlp.enabled", "telemetry.otlp.endpoint", "telemetry.otlp.authorization", "telemetry.otlp.export_interval", "telemetry.otlp.timeout",
}

// databaseMaintenanceEnvKeys deliberately excludes runtime-only settings. A
// migration container must be able to start without Redis, auth, mail, or
// telemetry credentials mounted into it.
var databaseMaintenanceEnvKeys = []string{
	"environment",
	"database.driver", "database.dsn", "database.runtime_role", "database.max_conns", "database.min_conns", "database.max_conn_lifetime", "database.max_conn_idle_time", "database.health_check_period", "database.connect_timeout", "database.statement_timeout",
	"database.tls.mode", "database.tls.root_ca_file", "database.tls.client_cert_file", "database.tls.client_key_file", "database.tls.server_name",
	"audit.retention",
}

var mediaMaintenanceEnvKeys = append(append([]string(nil), databaseMaintenanceEnvKeys...),
	"media.backend", "media.local.directory", "media.s3.endpoint", "media.s3.region", "media.s3.bucket", "media.s3.prefix", "media.s3.path_style", "media.s3.access_key_id", "media.s3.secret_access_key", "media.s3.session_token",
)

type secretFileBinding struct {
	key      string
	valueEnv string
	fileEnv  string
}

var secretFileBindings = []secretFileBinding{
	{key: "database.dsn", valueEnv: "NYAUTH_DATABASE_DSN", fileEnv: "NYAUTH_DATABASE_DSN_FILE"},
	{key: "redis.password", valueEnv: "NYAUTH_REDIS_PASSWORD", fileEnv: "NYAUTH_REDIS_PASSWORD_FILE"},
	{key: "auth.master_key", valueEnv: "NYAUTH_AUTH_MASTER_KEY", fileEnv: "NYAUTH_AUTH_MASTER_KEY_FILE"},
	{key: "admin.password", valueEnv: "NYAUTH_BOOTSTRAP_ADMIN_PASSWORD", fileEnv: "NYAUTH_BOOTSTRAP_ADMIN_PASSWORD_FILE"},
	{key: "mail.smtp.password", valueEnv: "NYAUTH_MAIL_SMTP_PASSWORD", fileEnv: "NYAUTH_MAIL_SMTP_PASSWORD_FILE"},
	{key: "media.s3.access_key_id", valueEnv: "NYAUTH_MEDIA_S3_ACCESS_KEY_ID", fileEnv: "NYAUTH_MEDIA_S3_ACCESS_KEY_ID_FILE"},
	{key: "media.s3.secret_access_key", valueEnv: "NYAUTH_MEDIA_S3_SECRET_ACCESS_KEY", fileEnv: "NYAUTH_MEDIA_S3_SECRET_ACCESS_KEY_FILE"},
	{key: "media.s3.session_token", valueEnv: "NYAUTH_MEDIA_S3_SESSION_TOKEN", fileEnv: "NYAUTH_MEDIA_S3_SESSION_TOKEN_FILE"},
	{key: "telemetry.otlp.authorization", valueEnv: "NYAUTH_TELEMETRY_OTLP_AUTHORIZATION", fileEnv: "NYAUTH_TELEMETRY_OTLP_AUTHORIZATION_FILE"},
}

var databaseMaintenanceSecretFileBindings = []secretFileBinding{
	{key: "database.dsn", valueEnv: "NYAUTH_DATABASE_DSN", fileEnv: "NYAUTH_DATABASE_DSN_FILE"},
}

var mediaMaintenanceSecretFileBindings = []secretFileBinding{
	{key: "database.dsn", valueEnv: "NYAUTH_DATABASE_DSN", fileEnv: "NYAUTH_DATABASE_DSN_FILE"},
	{key: "media.s3.access_key_id", valueEnv: "NYAUTH_MEDIA_S3_ACCESS_KEY_ID", fileEnv: "NYAUTH_MEDIA_S3_ACCESS_KEY_ID_FILE"},
	{key: "media.s3.secret_access_key", valueEnv: "NYAUTH_MEDIA_S3_SECRET_ACCESS_KEY", fileEnv: "NYAUTH_MEDIA_S3_SECRET_ACCESS_KEY_FILE"},
	{key: "media.s3.session_token", valueEnv: "NYAUTH_MEDIA_S3_SESSION_TOKEN", fileEnv: "NYAUTH_MEDIA_S3_SESSION_TOKEN_FILE"},
}

func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetDefault("environment", "development")
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.secure_cookie", false)
	v.SetDefault("server.readiness_timeout", "3s")
	v.SetDefault("server.shutdown_timeout", "30s")
	v.SetDefault("database.driver", "postgres")
	v.SetDefault("database.runtime_role", "nyauth_runtime")
	v.SetDefault("database.max_conns", 25)
	v.SetDefault("database.min_conns", 5)
	v.SetDefault("database.max_conn_lifetime", "1h")
	v.SetDefault("database.max_conn_idle_time", "30m")
	v.SetDefault("database.health_check_period", "1m")
	v.SetDefault("database.connect_timeout", "5s")
	v.SetDefault("database.statement_timeout", "15s")
	v.SetDefault("redis.addr", "localhost:6379")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.pool_size", 20)
	v.SetDefault("redis.min_idle_conns", 2)
	v.SetDefault("redis.dial_timeout", "5s")
	v.SetDefault("redis.read_timeout", "3s")
	v.SetDefault("redis.write_timeout", "3s")
	v.SetDefault("redis.pool_timeout", "4s")
	v.SetDefault("redis.conn_max_idle_time", "30m")
	v.SetDefault("redis.conn_max_lifetime", "1h")
	v.SetDefault("auth.argon2_concurrency", 4)
	v.SetDefault("auth.jwk.algorithm", "RS256")
	v.SetDefault("auth.jwk.key_size", 2048)
	v.SetDefault("auth.jwk.rotation_interval", "720h")
	v.SetDefault("web.enabled", true)
	v.SetDefault("web.title", "nyauth")
	v.SetDefault("mail.smtp.port", 587)
	v.SetDefault("mail.smtp.tls_mode", "starttls")
	v.SetDefault("mail.smtp.connect_timeout", "10s")
	v.SetDefault("mail.smtp.send_timeout", "30s")
	v.SetDefault("media.backend", "local")
	v.SetDefault("media.local.directory", "data/media")
	v.SetDefault("media.s3.path_style", false)
	v.SetDefault("audit.retention", "8760h")
	v.SetDefault("telemetry.otlp.enabled", false)
	v.SetDefault("telemetry.otlp.export_interval", "30s")
	v.SetDefault("telemetry.otlp.timeout", "10s")
	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/nyauth")
	}
	v.SetEnvPrefix("NYAUTH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	for _, key := range envKeys {
		if err := v.BindEnv(key); err != nil {
			return nil, fmt.Errorf("binding environment variable for %s: %w", key, err)
		}
	}
	for key, environmentVariable := range map[string]string{
		"admin.username": "NYAUTH_BOOTSTRAP_ADMIN_USERNAME",
		"admin.password": "NYAUTH_BOOTSTRAP_ADMIN_PASSWORD",
		"admin.email":    "NYAUTH_BOOTSTRAP_ADMIN_EMAIL",
	} {
		if err := v.BindEnv(key, environmentVariable); err != nil {
			return nil, fmt.Errorf("binding environment variable for %s: %w", key, err)
		}
	}
	v.AutomaticEnv()
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}
	if err := rejectRestrictedConfigFileValues(v); err != nil {
		return nil, err
	}
	if err := applyFileSecrets(v); err != nil {
		return nil, err
	}
	var cfg Config
	if err := v.UnmarshalExact(&cfg, viper.DecodeHook(mapstructure.StringToSliceHookFunc(","))); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}
	if err := cfg.Resolve(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}
	return &cfg, nil
}

// LoadDatabaseMaintenance loads only the database and audit configuration
// needed by the migrate and maintenance commands. It applies only the database
// DSN file secret and ignores runtime-only configuration.
func LoadDatabaseMaintenance(path string) (*Config, error) {
	return loadDatabaseMaintenance(path, false)
}

// LoadMaintenance adds media storage configuration to the database-only
// maintenance scope so orphaned avatar objects can be reclaimed without
// requiring Redis, issuer, mail, or bootstrap credentials.
func LoadMaintenance(path string) (*Config, error) {
	return loadDatabaseMaintenance(path, true)
}

func loadDatabaseMaintenance(path string, includeMedia bool) (*Config, error) {
	v := viper.New()
	setDatabaseMaintenanceDefaults(v)
	if includeMedia {
		v.SetDefault("media.backend", "local")
		v.SetDefault("media.local.directory", "data/media")
		v.SetDefault("media.s3.path_style", false)
	}
	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/nyauth")
	}
	v.SetEnvPrefix("NYAUTH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	keys := databaseMaintenanceEnvKeys
	if includeMedia {
		keys = mediaMaintenanceEnvKeys
	}
	for _, key := range keys {
		if err := v.BindEnv(key); err != nil {
			return nil, fmt.Errorf("binding environment variable for %s: %w", key, err)
		}
	}
	v.AutomaticEnv()
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}
	bindings := databaseMaintenanceSecretFileBindings
	if includeMedia {
		bindings = mediaMaintenanceSecretFileBindings
	}
	if err := applyFileSecretBindings(v, bindings); err != nil {
		return nil, err
	}
	if includeMedia {
		for _, key := range []string{"media.s3.access_key_id", "media.s3.secret_access_key", "media.s3.session_token"} {
			if v.InConfig(key) {
				return nil, fmt.Errorf("%s must be configured through NYAUTH_MEDIA_S3_* environment variables or *_FILE secrets", key)
			}
		}
	}
	var scoped struct {
		Environment string         `mapstructure:"environment"`
		Database    DatabaseConfig `mapstructure:"database"`
		Audit       AuditConfig    `mapstructure:"audit"`
		Media       MediaConfig    `mapstructure:"media"`
	}
	if err := v.Unmarshal(&scoped, viper.DecodeHook(mapstructure.StringToSliceHookFunc(","))); err != nil {
		return nil, fmt.Errorf("unmarshaling database maintenance config: %w", err)
	}
	cfg := &Config{
		Environment: strings.ToLower(strings.TrimSpace(scoped.Environment)),
		Database:    scoped.Database,
		Audit:       scoped.Audit,
		Media:       scoped.Media,
	}
	if cfg.Environment == "" {
		cfg.Environment = "development"
	}
	if err := resolveDatabaseMaintenance(cfg); err != nil {
		return nil, err
	}
	if err := validateDatabaseMaintenance(cfg); err != nil {
		return nil, fmt.Errorf("validating database maintenance config: %w", err)
	}
	if includeMedia {
		media := &cfg.Media
		media.Backend = strings.ToLower(strings.TrimSpace(media.Backend))
		media.Local.Directory = strings.TrimSpace(media.Local.Directory)
		media.S3.Endpoint = strings.TrimSpace(media.S3.Endpoint)
		media.S3.Region = strings.TrimSpace(media.S3.Region)
		media.S3.Bucket = strings.TrimSpace(media.S3.Bucket)
		media.S3.Prefix = strings.Trim(strings.TrimSpace(media.S3.Prefix), "/")
		if err := validateMaintenanceMedia(*media, cfg.IsProduction()); err != nil {
			return nil, fmt.Errorf("validating maintenance media config: %w", err)
		}
	}
	return cfg, nil
}

func validateMaintenanceMedia(media MediaConfig, production bool) error {
	switch media.Backend {
	case "local":
		if media.Local.Directory == "" {
			return fmt.Errorf("media.local.directory is required when media.backend is local")
		}
	case "s3":
		if media.S3.Region == "" || media.S3.Bucket == "" || media.S3.AccessKeyID == "" || media.S3.SecretAccessKey == "" {
			return fmt.Errorf("media S3 region, bucket, access key ID, and secret access key are required")
		}
		if strings.ContainsAny(media.S3.AccessKeyID+media.S3.SecretAccessKey+media.S3.SessionToken, "\r\n") {
			return fmt.Errorf("media.s3 credentials must be single-line values")
		}
		if strings.Contains(media.S3.Bucket, "/") || strings.Contains(media.S3.Prefix, "\\") {
			return fmt.Errorf("media.s3.bucket and media.s3.prefix must be object storage names, not filesystem paths")
		}
		if media.S3.Endpoint != "" {
			endpoint, err := url.Parse(media.S3.Endpoint)
			if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
				return fmt.Errorf("media.s3.endpoint must be an absolute HTTP(S) URL without credentials, query, or fragment")
			}
			if production && endpoint.Scheme != "https" {
				return fmt.Errorf("media.s3.endpoint must use HTTPS in production")
			}
		}
	default:
		return fmt.Errorf("media.backend must be local or s3")
	}
	return nil
}

func setDatabaseMaintenanceDefaults(v *viper.Viper) {
	v.SetDefault("environment", "development")
	v.SetDefault("database.driver", "postgres")
	v.SetDefault("database.runtime_role", "nyauth_runtime")
	v.SetDefault("database.max_conns", 25)
	v.SetDefault("database.min_conns", 5)
	v.SetDefault("database.max_conn_lifetime", "1h")
	v.SetDefault("database.max_conn_idle_time", "30m")
	v.SetDefault("database.health_check_period", "1m")
	v.SetDefault("database.connect_timeout", "5s")
	v.SetDefault("database.statement_timeout", "15s")
	v.SetDefault("audit.retention", "8760h")
}

func resolveDatabaseMaintenance(cfg *Config) error {
	d := &cfg.Database
	d.RuntimeRole = strings.TrimSpace(d.RuntimeRole)
	var err error
	if d.MaxConnLifetime, err = parsePositiveDuration("database.max_conn_lifetime", d.MaxConnLifetimeRaw, time.Hour); err != nil {
		return err
	}
	if d.MaxConnIdleTime, err = parsePositiveDuration("database.max_conn_idle_time", d.MaxConnIdleTimeRaw, 30*time.Minute); err != nil {
		return err
	}
	if d.HealthCheckPeriod, err = parsePositiveDuration("database.health_check_period", d.HealthCheckPeriodRaw, time.Minute); err != nil {
		return err
	}
	if d.ConnectTimeout, err = parsePositiveDuration("database.connect_timeout", d.ConnectTimeoutRaw, 5*time.Second); err != nil {
		return err
	}
	if d.StatementTimeout, err = parsePositiveDuration("database.statement_timeout", d.StatementTimeoutRaw, 15*time.Second); err != nil {
		return err
	}
	d.TLS.Mode = strings.ToLower(strings.TrimSpace(d.TLS.Mode))
	if cfg.Audit.Retention, err = parsePositiveDuration("audit.retention", cfg.Audit.RetentionRaw, 365*24*time.Hour); err != nil {
		return err
	}
	return nil
}

func validateDatabaseMaintenance(cfg *Config) error {
	var errs []error
	if cfg.Environment != "development" && cfg.Environment != "test" && cfg.Environment != "production" {
		errs = append(errs, fmt.Errorf("environment must be development, test, or production"))
	}
	if cfg.Database.Driver != "postgres" {
		errs = append(errs, fmt.Errorf("database.driver must be postgres"))
	}
	if strings.TrimSpace(cfg.Database.DSN) == "" {
		errs = append(errs, fmt.Errorf("database.dsn is required"))
	} else if parsed, err := url.Parse(cfg.Database.DSN); err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" {
		errs = append(errs, fmt.Errorf("database.dsn must be an absolute postgres:// or postgresql:// URL"))
	}
	if !postgresRoleNamePattern.MatchString(cfg.Database.RuntimeRole) {
		errs = append(errs, fmt.Errorf("database.runtime_role must be a PostgreSQL role name containing at most 63 ASCII letters, digits, underscores, or dollar signs"))
	}
	if cfg.Database.MaxConns < 1 {
		errs = append(errs, fmt.Errorf("database.max_conns must be positive"))
	}
	if cfg.Database.MinConns < 0 || cfg.Database.MinConns > cfg.Database.MaxConns {
		errs = append(errs, fmt.Errorf("database.min_conns must be between 0 and database.max_conns"))
	}
	switch cfg.Database.TLS.Mode {
	case "", "disable", "require", "verify-ca", "verify-full":
	default:
		errs = append(errs, fmt.Errorf("database.tls.mode must be disable, require, verify-ca, or verify-full"))
	}
	if (cfg.Database.TLS.ClientCertFile == "") != (cfg.Database.TLS.ClientKeyFile == "") {
		errs = append(errs, fmt.Errorf("database.tls.client_cert_file and client_key_file must be configured together"))
	}
	if cfg.Database.TLS.Mode == "" && (cfg.Database.TLS.RootCAFile != "" || cfg.Database.TLS.ClientCertFile != "" || cfg.Database.TLS.ServerName != "") {
		errs = append(errs, fmt.Errorf("database.tls.mode is required when database TLS files or server_name are configured"))
	}
	return errors.Join(errs...)
}

func rejectRestrictedConfigFileValues(v *viper.Viper) error {
	if v.InConfig("admin.password") {
		return fmt.Errorf("admin.password must be configured through NYAUTH_BOOTSTRAP_ADMIN_PASSWORD or NYAUTH_BOOTSTRAP_ADMIN_PASSWORD_FILE")
	}
	for _, key := range envKeys {
		if strings.HasPrefix(key, "mail.") && v.InConfig(key) {
			return fmt.Errorf("%s must be configured through NYAUTH_MAIL_* environment variables", key)
		}
	}
	for _, key := range []string{"media.s3.access_key_id", "media.s3.secret_access_key", "media.s3.session_token"} {
		if v.InConfig(key) {
			return fmt.Errorf("%s must be configured through NYAUTH_MEDIA_S3_* environment variables or *_FILE secrets", key)
		}
	}
	return nil
}

func applyFileSecrets(v *viper.Viper) error {
	return applyFileSecretBindings(v, secretFileBindings)
}

func applyFileSecretBindings(v *viper.Viper, bindings []secretFileBinding) error {
	for _, binding := range bindings {
		_, valueSet := os.LookupEnv(binding.valueEnv)
		path, fileSet := os.LookupEnv(binding.fileEnv)
		if !fileSet {
			continue
		}
		if valueSet {
			return fmt.Errorf("%s and %s must not be set together", binding.valueEnv, binding.fileEnv)
		}
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("%s must name a readable file", binding.fileEnv)
		}
		secretFile, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", binding.fileEnv, err)
		}
		contents, readErr := io.ReadAll(io.LimitReader(secretFile, (1<<20)+1))
		closeErr := secretFile.Close()
		if readErr != nil {
			return fmt.Errorf("reading %s: %w", binding.fileEnv, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("closing %s: %w", binding.fileEnv, closeErr)
		}
		if len(contents) > 1<<20 {
			return fmt.Errorf("reading %s: secret file exceeds 1 MiB", binding.fileEnv)
		}
		value := strings.TrimSuffix(string(contents), "\n")
		value = strings.TrimSuffix(value, "\r")
		if strings.ContainsRune(value, 0) {
			return fmt.Errorf("reading %s: secret contains a NUL byte", binding.fileEnv)
		}
		v.Set(binding.key, value)
	}
	return nil
}
