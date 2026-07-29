package settings

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ProtectionDisableConfirmation = "DISABLE RATE LIMITS"
	DefaultOwnedClientLimit       = 10
	MinOwnedClientLimit           = 0
	MaxOwnedClientLimit           = 1000
	minRateLimitCount             = 1
	maxRateLimitCount             = 100000
	minRateLimitWindow            = 10 * time.Second
	maxRateLimitWindow            = 24 * time.Hour
	minSessionAbsoluteTTL         = 15 * time.Minute
	maxSessionAbsoluteTTL         = 720 * time.Hour
	minSessionIdleTTL             = 5 * time.Minute
	maxSessionIdleTTL             = 720 * time.Hour
	minRecentAuthenticationTTL    = time.Minute
	maxRecentAuthenticationTTL    = time.Hour
	minAccessTokenTTL             = 5 * time.Minute
	maxAccessTokenTTL             = 24 * time.Hour
	minRefreshTokenTTL            = time.Hour
	maxRefreshTokenTTL            = 8760 * time.Hour
	minAuthorizationCodeTTL       = 30 * time.Second
	maxAuthorizationCodeTTL       = 10 * time.Minute
	MinConcurrentSessions         = 0
	MaxConcurrentSessions         = 100
	MinAuditRetentionDays         = 7
	MaxAuditRetentionDays         = 3650
)

const (
	// MaxAccessTokenTTL and MaxRefreshTokenTTL are exported so signing-key and
	// revocation retention can cover every value accepted at runtime.
	MaxAccessTokenTTL       = maxAccessTokenTTL
	MaxRefreshTokenTTL      = maxRefreshTokenTTL
	MaxAuthorizationCodeTTL = maxAuthorizationCodeTTL
)

var (
	ErrRevisionConflict              = errors.New("settings revision conflict")
	ErrProtectionDisableConfirmation = errors.New("rate limit disable confirmation is required")
	ErrRetentionConfirmation         = errors.New("audit retention confirmation is required")
)

// Versioned keeps a setting value and the database revision that produced it
// in one atomic publication unit.
type Versioned[T any] struct {
	Revision int64
	Value    T
}

type LoginProtection struct {
	Enabled                bool   `json:"enabled"`
	Window                 string `json:"window"`
	IdentityLimit          int    `json:"identity_limit"`
	IPLimit                int    `json:"ip_limit"`
	PasskeyCeremonyIPLimit int    `json:"passkey_ceremony_ip_limit"`
}

type AccountProtection struct {
	Enabled      bool   `json:"enabled"`
	Window       string `json:"window"`
	SubjectLimit int    `json:"subject_limit"`
	IPLimit      int    `json:"ip_limit"`
}

type AvatarProtection struct {
	Enabled   bool   `json:"enabled"`
	Window    string `json:"window"`
	UserLimit int    `json:"user_limit"`
	IPLimit   int    `json:"ip_limit"`
}

type MailProtection struct {
	Enabled       bool   `json:"enabled"`
	Window        string `json:"window"`
	SaveLimit     int    `json:"save_limit"`
	TestLimit     int    `json:"test_limit"`
	ActivateLimit int    `json:"activate_limit"`
	RollbackLimit int    `json:"rollback_limit"`
	DisableLimit  int    `json:"disable_limit"`
	IPLimit       int    `json:"ip_limit"`
}

// Protection contains only policy that may safely change while the process is
// running. Limits protecting this settings endpoint and service control stay
// compiled into the server so administrators cannot lock themselves out.
type Protection struct {
	Login                   LoginProtection   `json:"login"`
	Account                 AccountProtection `json:"account"`
	Avatar                  AvatarProtection  `json:"avatar"`
	Mail                    MailProtection    `json:"mail"`
	OwnedClientDefaultLimit int               `json:"owned_client_default_limit"`
}

func DefaultProtection() Protection {
	return Protection{
		Login: LoginProtection{
			Enabled: true, Window: "5m", IdentityLimit: 5, IPLimit: 30,
			PasskeyCeremonyIPLimit: 120,
		},
		Account: AccountProtection{
			Enabled: true, Window: "15m", SubjectLimit: 5, IPLimit: 20,
		},
		Avatar: AvatarProtection{
			Enabled: true, Window: "15m", UserLimit: 30, IPLimit: 200,
		},
		Mail: MailProtection{
			Enabled: true, Window: "15m", SaveLimit: 60, TestLimit: 30,
			ActivateLimit: 30, RollbackLimit: 30, DisableLimit: 30, IPLimit: 200,
		},
		OwnedClientDefaultLimit: DefaultOwnedClientLimit,
	}
}

func ValidateProtection(value Protection) error {
	checks := []struct {
		name   string
		window string
		limits []int
	}{
		{"login", value.Login.Window, []int{value.Login.IdentityLimit, value.Login.IPLimit, value.Login.PasskeyCeremonyIPLimit}},
		{"account", value.Account.Window, []int{value.Account.SubjectLimit, value.Account.IPLimit}},
		{"avatar", value.Avatar.Window, []int{value.Avatar.UserLimit, value.Avatar.IPLimit}},
		{"mail", value.Mail.Window, []int{value.Mail.SaveLimit, value.Mail.TestLimit, value.Mail.ActivateLimit, value.Mail.RollbackLimit, value.Mail.DisableLimit, value.Mail.IPLimit}},
	}
	for _, check := range checks {
		if _, err := parseBoundedDuration(check.name+" window", check.window, minRateLimitWindow, maxRateLimitWindow); err != nil {
			return err
		}
		for _, limit := range check.limits {
			if limit < minRateLimitCount || limit > maxRateLimitCount {
				return fmt.Errorf("%s limits must be between %d and %d", check.name, minRateLimitCount, maxRateLimitCount)
			}
		}
	}
	if value.OwnedClientDefaultLimit < MinOwnedClientLimit || value.OwnedClientDefaultLimit > MaxOwnedClientLimit {
		return fmt.Errorf("owned_client_default_limit must be between %d and %d", MinOwnedClientLimit, MaxOwnedClientLimit)
	}
	return nil
}

func ProtectionDisables(previous, next Protection) bool {
	return previous.Login.Enabled && !next.Login.Enabled ||
		previous.Account.Enabled && !next.Account.Enabled ||
		previous.Avatar.Enabled && !next.Avatar.Enabled ||
		previous.Mail.Enabled && !next.Mail.Enabled
}

func (p Protection) LoginWindow() time.Duration   { return mustDuration(p.Login.Window) }
func (p Protection) AccountWindow() time.Duration { return mustDuration(p.Account.Window) }
func (p Protection) AvatarWindow() time.Duration  { return mustDuration(p.Avatar.Window) }
func (p Protection) MailWindow() time.Duration    { return mustDuration(p.Mail.Window) }

type Lifecycle struct {
	SessionAbsoluteTTL      string `json:"session_absolute_ttl"`
	SessionIdleTTL          string `json:"session_idle_ttl"`
	MaxConcurrentSessions   int    `json:"max_concurrent_sessions"`
	RecentAuthenticationTTL string `json:"recent_authentication_ttl"`
	AccessTokenTTL          string `json:"access_token_ttl"`
	RefreshTokenTTL         string `json:"refresh_token_ttl"`
	AuthorizationCodeTTL    string `json:"authorization_code_ttl"`
	AuditRetentionDays      int    `json:"audit_retention_days"`
}

func DefaultLifecycle(auditRetentionDays int) Lifecycle {
	return DefaultLifecycleWithAuthentication(
		auditRetentionDays, time.Hour, 30*24*time.Hour, 5*time.Minute,
	)
}

func DefaultLifecycleWithAuthentication(
	auditRetentionDays int,
	accessTokenTTL time.Duration,
	refreshTokenTTL time.Duration,
	authorizationCodeTTL time.Duration,
) Lifecycle {
	if auditRetentionDays < MinAuditRetentionDays || auditRetentionDays > MaxAuditRetentionDays {
		auditRetentionDays = 365
	}
	if accessTokenTTL <= 0 {
		accessTokenTTL = time.Hour
	}
	if refreshTokenTTL <= 0 {
		refreshTokenTTL = 30 * 24 * time.Hour
	}
	if authorizationCodeTTL <= 0 {
		authorizationCodeTTL = 5 * time.Minute
	}
	return Lifecycle{
		SessionAbsoluteTTL: "24h", SessionIdleTTL: "24h", MaxConcurrentSessions: 0,
		RecentAuthenticationTTL: "10m",
		AccessTokenTTL:          accessTokenTTL.String(), RefreshTokenTTL: refreshTokenTTL.String(),
		AuthorizationCodeTTL: authorizationCodeTTL.String(),
		AuditRetentionDays:   auditRetentionDays,
	}
}

func ValidateLifecycle(value Lifecycle) error {
	if _, err := parseBoundedDuration("session_absolute_ttl", value.SessionAbsoluteTTL, minSessionAbsoluteTTL, maxSessionAbsoluteTTL); err != nil {
		return err
	}
	idleTTL, err := parseBoundedDuration("session_idle_ttl", value.SessionIdleTTL, minSessionIdleTTL, maxSessionIdleTTL)
	if err != nil {
		return err
	}
	if idleTTL > value.SessionAbsoluteDuration() {
		return fmt.Errorf("session_idle_ttl must not exceed session_absolute_ttl")
	}
	if value.MaxConcurrentSessions < MinConcurrentSessions || value.MaxConcurrentSessions > MaxConcurrentSessions {
		return fmt.Errorf("max_concurrent_sessions must be between %d and %d", MinConcurrentSessions, MaxConcurrentSessions)
	}
	if _, err := parseBoundedDuration("recent_authentication_ttl", value.RecentAuthenticationTTL, minRecentAuthenticationTTL, maxRecentAuthenticationTTL); err != nil {
		return err
	}
	if _, err := parseBoundedDuration("access_token_ttl", value.AccessTokenTTL, minAccessTokenTTL, maxAccessTokenTTL); err != nil {
		return err
	}
	if _, err := parseBoundedDuration("refresh_token_ttl", value.RefreshTokenTTL, minRefreshTokenTTL, maxRefreshTokenTTL); err != nil {
		return err
	}
	if _, err := parseBoundedDuration("authorization_code_ttl", value.AuthorizationCodeTTL, minAuthorizationCodeTTL, maxAuthorizationCodeTTL); err != nil {
		return err
	}
	if value.AuditRetentionDays < MinAuditRetentionDays || value.AuditRetentionDays > MaxAuditRetentionDays {
		return fmt.Errorf("audit_retention_days must be between %d and %d", MinAuditRetentionDays, MaxAuditRetentionDays)
	}
	return nil
}

func (l Lifecycle) SessionAbsoluteDuration() time.Duration {
	return mustDuration(l.SessionAbsoluteTTL)
}

func (l Lifecycle) SessionIdleDuration() time.Duration {
	return mustDuration(l.SessionIdleTTL)
}

func (l Lifecycle) RecentAuthenticationDuration() time.Duration {
	return mustDuration(l.RecentAuthenticationTTL)
}

func (l Lifecycle) AccessTokenDuration() time.Duration {
	return mustDuration(l.AccessTokenTTL)
}

func (l Lifecycle) RefreshTokenDuration() time.Duration {
	return mustDuration(l.RefreshTokenTTL)
}

func (l Lifecycle) AuthorizationCodeDuration() time.Duration {
	return mustDuration(l.AuthorizationCodeTTL)
}

func RetentionConfirmation(days int) string {
	return fmt.Sprintf("RETENTION %d DAYS", days)
}

func parseBoundedDuration(name, raw string, minimum, maximum time.Duration) (time.Duration, error) {
	value, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be a duration between %s and %s", name, minimum, maximum)
	}
	return value, nil
}

func mustDuration(raw string) time.Duration {
	value, _ := time.ParseDuration(raw)
	return value
}
