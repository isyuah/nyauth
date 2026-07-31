package settings

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/pkg/models"
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
	MinRedirectURILimit           = 1
	MaxRedirectURILimit           = 100
	MinPostLogoutRedirectURILimit = 0
	MaxPostLogoutRedirectURILimit = 100
	MinOperationalAlertCount      = 1
	MaxOperationalAlertCount      = 1_000_000
	MaxTemporaryDebugDuration     = 24 * time.Hour
)

const (
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
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

// OperationalAlertThresholds contains only bounded, low-cardinality signals.
// Crossing a threshold surfaces a warning and metric; it never changes
// readiness or pauses application capabilities.
type OperationalAlertThresholds struct {
	MailBacklogCount          int64  `json:"mail_backlog_count"`
	MailOldestPendingAge      string `json:"mail_oldest_pending_age"`
	AuditOutboxBacklogCount   int64  `json:"audit_outbox_backlog_count"`
	AuditOldestPendingAge     string `json:"audit_oldest_pending_age"`
	AvatarCleanupPendingCount int64  `json:"avatar_cleanup_pending_count"`
}

// Observability controls process-local verbosity and operational warning
// thresholds. Debug is intentionally temporary; the persisted base level is
// restored automatically when DebugUntil is reached.
type Observability struct {
	LogLevel   string                     `json:"log_level"`
	DebugUntil *time.Time                 `json:"debug_until,omitempty"`
	Alerts     OperationalAlertThresholds `json:"alerts"`
}

func DefaultObservability() Observability {
	return Observability{
		LogLevel: LogLevelInfo,
		Alerts: OperationalAlertThresholds{
			MailBacklogCount: 100, MailOldestPendingAge: "15m",
			AuditOutboxBacklogCount: 1000, AuditOldestPendingAge: "10m",
			AvatarCleanupPendingCount: 100,
		},
	}
}

func ValidateObservability(value Observability) error {
	switch value.LogLevel {
	case LogLevelInfo, LogLevelWarn, LogLevelError:
	default:
		return errors.New("log_level must be info, warn, or error")
	}
	for name, count := range map[string]int64{
		"mail_backlog_count":           value.Alerts.MailBacklogCount,
		"audit_outbox_backlog_count":   value.Alerts.AuditOutboxBacklogCount,
		"avatar_cleanup_pending_count": value.Alerts.AvatarCleanupPendingCount,
	} {
		if count < MinOperationalAlertCount || count > MaxOperationalAlertCount {
			return fmt.Errorf("%s must be between %d and %d", name, MinOperationalAlertCount, MaxOperationalAlertCount)
		}
	}
	for name, encoded := range map[string]string{
		"mail_oldest_pending_age":  value.Alerts.MailOldestPendingAge,
		"audit_oldest_pending_age": value.Alerts.AuditOldestPendingAge,
	} {
		if _, err := parseBoundedDuration(name, encoded, time.Minute, 7*24*time.Hour); err != nil {
			return err
		}
	}
	return nil
}

func ValidateTemporaryDebug(value Observability, now time.Time) error {
	if value.DebugUntil == nil {
		return nil
	}
	until := value.DebugUntil.UTC()
	if until.Before(now.UTC().Add(time.Minute)) || until.After(now.UTC().Add(MaxTemporaryDebugDuration)) {
		return fmt.Errorf("debug_until must be between 1 minute and %s from now", MaxTemporaryDebugDuration)
	}
	return nil
}

func (o Observability) MailOldestPendingDuration() time.Duration {
	return mustDuration(o.Alerts.MailOldestPendingAge)
}

func (o Observability) AuditOldestPendingDuration() time.Duration {
	return mustDuration(o.Alerts.AuditOldestPendingAge)
}

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

var supportedOAuthScopes = []string{"openid", "profile", "email", "offline_access"}
var supportedOAuthGrantTypes = []string{
	models.GrantAuthorizationCode,
	models.GrantRefreshToken,
	models.GrantClientCredentials,
}

// OAuthPolicy controls future client registrations. Tightening it does not
// mutate or disable clients that were valid when they were registered.
type OAuthPolicy struct {
	SelfServiceClientCreationEnabled bool     `json:"self_service_client_creation_enabled"`
	PublicClientsEnabled             bool     `json:"public_clients_enabled"`
	AllowedGrantTypes                []string `json:"allowed_grant_types"`
	AllowedScopes                    []string `json:"allowed_scopes"`
	MaxRedirectURIs                  int      `json:"max_redirect_uris"`
	MaxPostLogoutRedirectURIs        int      `json:"max_post_logout_redirect_uris"`
}

func DefaultOAuthPolicy() OAuthPolicy {
	return OAuthPolicy{
		SelfServiceClientCreationEnabled: true,
		PublicClientsEnabled:             true,
		AllowedGrantTypes:                slices.Clone(supportedOAuthGrantTypes),
		AllowedScopes:                    slices.Clone(supportedOAuthScopes),
		MaxRedirectURIs:                  20,
		MaxPostLogoutRedirectURIs:        20,
	}
}

func SupportedOAuthGrantTypes() []string { return slices.Clone(supportedOAuthGrantTypes) }
func SupportedOAuthScopes() []string     { return slices.Clone(supportedOAuthScopes) }

func NormalizeOAuthPolicy(value OAuthPolicy) (OAuthPolicy, error) {
	grants, err := normalizeAllowedValues("allowed_grant_types", value.AllowedGrantTypes, supportedOAuthGrantTypes)
	if err != nil {
		return OAuthPolicy{}, err
	}
	scopes, err := normalizeAllowedScopes(value.AllowedScopes)
	if err != nil {
		return OAuthPolicy{}, err
	}
	value.AllowedGrantTypes = grants
	value.AllowedScopes = scopes
	if value.MaxRedirectURIs < MinRedirectURILimit || value.MaxRedirectURIs > MaxRedirectURILimit {
		return OAuthPolicy{}, fmt.Errorf("max_redirect_uris must be between %d and %d", MinRedirectURILimit, MaxRedirectURILimit)
	}
	if value.MaxPostLogoutRedirectURIs < MinPostLogoutRedirectURILimit || value.MaxPostLogoutRedirectURIs > MaxPostLogoutRedirectURILimit {
		return OAuthPolicy{}, fmt.Errorf("max_post_logout_redirect_uris must be between %d and %d", MinPostLogoutRedirectURILimit, MaxPostLogoutRedirectURILimit)
	}
	if slices.Contains(grants, models.GrantRefreshToken) && !slices.Contains(grants, models.GrantAuthorizationCode) {
		return OAuthPolicy{}, errors.New("allowing refresh_token requires authorization_code")
	}
	if slices.Contains(scopes, "offline_access") && !slices.Contains(grants, models.GrantRefreshToken) {
		return OAuthPolicy{}, errors.New("allowing offline_access requires refresh_token")
	}
	if value.PublicClientsEnabled && !slices.Contains(grants, models.GrantAuthorizationCode) {
		return OAuthPolicy{}, errors.New("allowing public clients requires authorization_code")
	}
	return value, nil
}

func normalizeAllowedValues(name string, values, supported []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%s must contain at least one value", name)
	}
	selected := make(map[string]bool, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" || !slices.Contains(supported, value) {
			return nil, fmt.Errorf("%s contains unsupported value %q", name, raw)
		}
		if selected[value] {
			return nil, fmt.Errorf("%s contains duplicate value %q", name, value)
		}
		selected[value] = true
	}
	ordered := make([]string, 0, len(values))
	for _, value := range supported {
		if selected[value] {
			ordered = append(ordered, value)
		}
	}
	return ordered, nil
}

func normalizeAllowedScopes(values []string) ([]string, error) {
	selected := make(map[string]bool, len(values))
	custom := make([]string, 0, len(values))
	for _, scope := range values {
		if !models.ValidOAuthScope(scope) {
			return nil, fmt.Errorf("allowed_scopes contains invalid value %q", scope)
		}
		if selected[scope] {
			return nil, fmt.Errorf("allowed_scopes contains duplicate value %q", scope)
		}
		selected[scope] = true
		if !slices.Contains(supportedOAuthScopes, scope) {
			custom = append(custom, scope)
		}
	}
	ordered := make([]string, 0, len(values))
	for _, scope := range supportedOAuthScopes {
		if selected[scope] {
			ordered = append(ordered, scope)
		}
	}
	slices.Sort(custom)
	return append(ordered, custom...), nil
}

func (p OAuthPolicy) AllowsGrant(grant string) bool {
	return slices.Contains(p.AllowedGrantTypes, grant)
}
func (p OAuthPolicy) AllowsScope(scope string) bool { return slices.Contains(p.AllowedScopes, scope) }

func SameOAuthPolicy(left, right OAuthPolicy) bool {
	return left.SelfServiceClientCreationEnabled == right.SelfServiceClientCreationEnabled &&
		left.PublicClientsEnabled == right.PublicClientsEnabled &&
		slices.Equal(left.AllowedGrantTypes, right.AllowedGrantTypes) &&
		slices.Equal(left.AllowedScopes, right.AllowedScopes) &&
		left.MaxRedirectURIs == right.MaxRedirectURIs &&
		left.MaxPostLogoutRedirectURIs == right.MaxPostLogoutRedirectURIs
}

const (
	SiteBannerSeverityInfo     = "info"
	SiteBannerSeverityWarning  = "warning"
	SiteBannerSeverityCritical = "critical"
)

type SiteBanner struct {
	Version     int64      `json:"version"`
	Enabled     bool       `json:"enabled"`
	Severity    string     `json:"severity"`
	Title       string     `json:"title"`
	Message     string     `json:"message"`
	Dismissible bool       `json:"dismissible"`
	StartsAt    *time.Time `json:"starts_at"`
	EndsAt      *time.Time `json:"ends_at"`
}

type Communications struct {
	Email      account.EmailTemplateSettings `json:"email"`
	SiteBanner SiteBanner                    `json:"site_banner"`
}

func DefaultCommunications() Communications {
	return Communications{
		Email: account.DefaultEmailTemplateSettings(),
		SiteBanner: SiteBanner{
			Severity: SiteBannerSeverityInfo, Dismissible: true,
		},
	}
}

func NormalizeCommunications(value Communications) (Communications, error) {
	email, err := account.NormalizeEmailTemplateSettings(value.Email)
	if err != nil {
		return Communications{}, err
	}
	value.Email = email
	siteBanner, err := normalizeSiteBanner(value.SiteBanner)
	if err != nil {
		return Communications{}, err
	}
	value.SiteBanner = siteBanner
	return value, nil
}

func normalizeSiteBanner(value SiteBanner) (SiteBanner, error) {
	value.Title = strings.TrimSpace(value.Title)
	value.Message = strings.TrimSpace(value.Message)
	if value.Severity == "" {
		value.Severity = SiteBannerSeverityInfo
	}
	if value.Version < 0 {
		return SiteBanner{}, errors.New("site banner version must not be negative")
	}
	if value.Severity != SiteBannerSeverityInfo && value.Severity != SiteBannerSeverityWarning && value.Severity != SiteBannerSeverityCritical {
		return SiteBanner{}, errors.New("site banner severity is unsupported")
	}
	if value.Enabled && (value.Title == "" || value.Message == "") {
		return SiteBanner{}, errors.New("enabled site banner requires a title and message")
	}
	for _, field := range []struct {
		name         string
		value        string
		limit        int
		allowNewline bool
	}{
		{"site banner title", value.Title, 120, false},
		{"site banner message", value.Message, 1000, true},
	} {
		if utf8.RuneCountInString(field.value) > field.limit {
			return SiteBanner{}, fmt.Errorf("%s must be at most %d characters", field.name, field.limit)
		}
		if containsSiteBannerControl(field.value, field.allowNewline) {
			return SiteBanner{}, fmt.Errorf("%s contains unsupported control characters", field.name)
		}
	}
	if _, err := RenderSiteBannerMarkdown(value.Message); err != nil {
		return SiteBanner{}, err
	}
	if value.StartsAt != nil {
		start := value.StartsAt.UTC()
		value.StartsAt = &start
	}
	if value.EndsAt != nil {
		end := value.EndsAt.UTC()
		value.EndsAt = &end
	}
	if value.StartsAt != nil && value.EndsAt != nil && !value.EndsAt.After(*value.StartsAt) {
		return SiteBanner{}, errors.New("site banner ends_at must be later than starts_at")
	}
	return value, nil
}

func SameSiteBannerContent(left, right SiteBanner) bool {
	return left.Enabled == right.Enabled && left.Severity == right.Severity &&
		left.Title == right.Title && left.Message == right.Message &&
		left.Dismissible == right.Dismissible && sameOptionalTime(left.StartsAt, right.StartsAt) &&
		sameOptionalTime(left.EndsAt, right.EndsAt)
}

func SiteBannerActiveAt(value SiteBanner, now time.Time) bool {
	if !value.Enabled {
		return false
	}
	now = now.UTC()
	if value.StartsAt != nil && now.Before(*value.StartsAt) {
		return false
	}
	return value.EndsAt == nil || now.Before(*value.EndsAt)
}

func sameOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func containsSiteBannerControl(value string, allowNewline bool) bool {
	for _, character := range value {
		if character == '\n' && allowNewline {
			continue
		}
		if character == '\r' || character == 0 || isSiteBannerBidirectionalControl(character) || unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func isSiteBannerBidirectionalControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		(character >= '\u202a' && character <= '\u202e') ||
		(character >= '\u2066' && character <= '\u2069')
}

func validSiteBannerURL(value string) bool {
	if strings.Contains(value, `\`) {
		return false
	}
	if strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") {
		parsed, err := url.Parse(value)
		return err == nil && parsed.Host == "" && parsed.User == nil
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil
}

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
