package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server    ServerConfig            `mapstructure:"server"`
	Database  DatabaseConfig          `mapstructure:"database"`
	Redis     RedisConfig             `mapstructure:"redis"`
	Auth      AuthConfig              `mapstructure:"auth"`
	Providers map[string]ProviderConfig `mapstructure:"providers"`
	Admin     AdminConfig             `mapstructure:"admin"`
	Web       WebConfig               `mapstructure:"web"`
}

type ServerConfig struct {
	Host string    `mapstructure:"host"`
	Port int       `mapstructure:"port"`
	TLS  TLSConfig `mapstructure:"tls"`
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

// AuthConfig uses raw int64 for TTL (in seconds) from YAML, then converts.
type AuthConfig struct {
	Issuer               string    `mapstructure:"issuer"`
	AccessTokenTTLRaw    int64     `mapstructure:"access_token_ttl"`
	RefreshTokenTTLRaw   int64     `mapstructure:"refresh_token_ttl"`
	AuthCodeTTLRaw       int64     `mapstructure:"authorization_code_ttl"`
	EncryptionKey        string    `mapstructure:"encryption_key"`
	JWK                  JWKConfig `mapstructure:"jwk"`

	// Resolved durations (populated by Resolve())
	AccessTokenTTL      time.Duration `mapstructure:"-"`
	RefreshTokenTTL     time.Duration `mapstructure:"-"`
	AuthorizationCodeTTL time.Duration `mapstructure:"-"`
}

type JWKConfig struct {
	Algorithm        string `mapstructure:"algorithm"`
	KeySize          int    `mapstructure:"key_size"`
	RotationIntervalRaw string `mapstructure:"rotation_interval"` // e.g., "720h"

	// Resolved
	RotationInterval time.Duration `mapstructure:"-"`
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

// Resolve converts raw config values into Go types.
func (cfg *Config) Resolve() {
	a := &cfg.Auth

	// TTL: seconds → time.Duration
	if a.AccessTokenTTLRaw > 0 {
		a.AccessTokenTTL = time.Duration(a.AccessTokenTTLRaw) * time.Second
	} else {
		a.AccessTokenTTL = 1 * time.Hour
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

	// JWK
	if a.JWK.Algorithm == "" {
		a.JWK.Algorithm = "RS256"
	}
	if a.JWK.KeySize == 0 {
		a.JWK.KeySize = 2048
	}
	if a.JWK.RotationIntervalRaw != "" {
		d, err := time.ParseDuration(a.JWK.RotationIntervalRaw)
		if err == nil {
			a.JWK.RotationInterval = d
		}
	}
	if a.JWK.RotationInterval == 0 {
		a.JWK.RotationInterval = 720 * time.Hour // 30 days
	}
}

func Load(path string) (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("database.driver", "postgres")
	v.SetDefault("redis.addr", "localhost:6379")
	v.SetDefault("redis.db", 0)
	v.SetDefault("web.enabled", true)
	v.SetDefault("web.title", "nyauth")

	// Config file
	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/nyauth")
	}

	// Environment variables
	v.SetEnvPrefix("NYAUTH")
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	cfg.Resolve()
	return &cfg, nil
}
