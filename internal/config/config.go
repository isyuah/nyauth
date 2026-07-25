package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

const developmentMasterKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

type Config struct {
	Environment string                    `mapstructure:"environment"`
	Server      ServerConfig              `mapstructure:"server"`
	Database    DatabaseConfig            `mapstructure:"database"`
	Redis       RedisConfig               `mapstructure:"redis"`
	Auth        AuthConfig                `mapstructure:"auth"`
	Providers   map[string]ProviderConfig `mapstructure:"providers"`
	Admin       AdminConfig               `mapstructure:"admin"`
	Web         WebConfig                 `mapstructure:"web"`
}

type ServerConfig struct {
	Host              string    `mapstructure:"host"`
	Port              int       `mapstructure:"port"`
	SecureCookie      bool      `mapstructure:"secure_cookie"`
	TrustedProxyCIDRs []string  `mapstructure:"trusted_proxy_cidrs"`
	TLS               TLSConfig `mapstructure:"tls"`
}
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}
type DatabaseConfig struct {
	Driver string `mapstructure:"driver"`
	DSN    string `mapstructure:"dsn"`
}
type RedisConfig struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
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
type ProviderConfig struct {
	Type             string   `mapstructure:"type"`
	ClientID         string   `mapstructure:"client_id"`
	ClientSecret     string   `mapstructure:"client_secret"`
	Scopes           []string `mapstructure:"scopes"`
	DiscoveryURL     string   `mapstructure:"discovery_url"`
	AuthorizationURL string   `mapstructure:"authorization_url"`
	TokenURL         string   `mapstructure:"token_url"`
	UserinfoURL      string   `mapstructure:"userinfo_url"`
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

func (cfg *Config) IsProduction() bool { return cfg.Environment == "production" }

func (cfg *Config) Resolve() error {
	cfg.Environment = strings.ToLower(strings.TrimSpace(cfg.Environment))
	if cfg.Environment == "" {
		cfg.Environment = "development"
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
	}
	if strings.TrimSpace(cfg.Redis.Addr) == "" {
		errs = append(errs, fmt.Errorf("redis.addr is required"))
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
	"environment", "server.host", "server.port", "server.secure_cookie", "server.trusted_proxy_cidrs", "server.tls.enabled", "server.tls.cert_file", "server.tls.key_file",
	"database.driver", "database.dsn", "redis.addr", "redis.password", "redis.db", "auth.issuer", "auth.access_token_ttl", "auth.refresh_token_ttl", "auth.authorization_code_ttl",
	"auth.master_key", "auth.argon2_concurrency", "auth.jwk.algorithm", "auth.jwk.key_size", "auth.jwk.rotation_interval", "admin.username", "admin.password", "admin.email", "web.enabled", "web.title", "web.logo_url",
}

func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetDefault("environment", "development")
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.secure_cookie", false)
	v.SetDefault("database.driver", "postgres")
	v.SetDefault("redis.addr", "localhost:6379")
	v.SetDefault("redis.db", 0)
	v.SetDefault("auth.argon2_concurrency", 4)
	v.SetDefault("auth.jwk.algorithm", "RS256")
	v.SetDefault("auth.jwk.key_size", 2048)
	v.SetDefault("auth.jwk.rotation_interval", "720h")
	v.SetDefault("web.enabled", true)
	v.SetDefault("web.title", "nyauth")
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
	_ = v.BindEnv("admin.username", "NYAUTH_BOOTSTRAP_ADMIN_USERNAME")
	_ = v.BindEnv("admin.password", "NYAUTH_BOOTSTRAP_ADMIN_PASSWORD")
	_ = v.BindEnv("admin.email", "NYAUTH_BOOTSTRAP_ADMIN_EMAIL")
	v.AutomaticEnv()
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}
	var cfg Config
	if err := v.Unmarshal(&cfg, viper.DecodeHook(mapstructure.StringToSliceHookFunc(","))); err != nil {
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
