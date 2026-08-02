// Package settings stores operational settings that administrators may change
// at runtime without restarting the service. Deployment-shape configuration
// (issuer, keys, connection strings) deliberately stays in the config file.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	brandingKey            = "branding"
	registrationKey        = "registration"
	securityKey            = "security"
	protectionKey          = "protection"
	lifecycleKey           = "lifecycle"
	oauthKey               = "oauth"
	communicationsKey      = "communications"
	observabilityKey       = "observability"
	notificationChannel    = "nyauth_settings_changed"
	reconciliationInterval = 60 * time.Second
)

var (
	ErrRegistrationChanged     = errors.New("registration settings changed")
	ErrMailConfigurationNeeded = errors.New("mail configuration is required for self-registration")
	ErrServiceControlConflict  = errors.New("registration settings conflict with service control")
)

// AdminsMissingMFAError identifies active administrators that prevent the
// mandatory-MFA policy from being enabled.
type AdminsMissingMFAError struct {
	Usernames []string
}

func (e *AdminsMissingMFAError) Error() string {
	return "all active administrators must enroll MFA before it can be required"
}

// Branding holds the values the web UI uses to present the deployment
// (sidebar wordmark, login heading, logo).
type Branding struct {
	Title            string `json:"title"`
	PrimaryColor     string `json:"primary_color"`
	PrimaryTextColor string `json:"primary_text_color"`
	LightLogoURL     string `json:"light_logo_url"`
	DarkLogoURL      string `json:"dark_logo_url"`
	FaviconURL       string `json:"favicon_url"`
}

const (
	DefaultPrimaryColor    = "#704DE8"
	PrimaryTextAuto        = "auto"
	PrimaryTextWhite       = "white"
	PrimaryTextBlack       = "black"
	brandingTitleMaxRunes  = 64
	brandingAssetURLMaxLen = 512
)

var brandingColorPattern = regexp.MustCompile(`^#[0-9A-F]{6}$`)

func DefaultBranding(title, logoURL string) Branding {
	return Branding{
		Title: title, PrimaryColor: DefaultPrimaryColor, PrimaryTextColor: PrimaryTextAuto,
		LightLogoURL: logoURL, DarkLogoURL: logoURL,
	}
}

// NormalizeBranding canonicalizes and validates runtime branding before it is
// published to process snapshots or persisted by an administrator.
func NormalizeBranding(value Branding) (Branding, error) {
	value.Title = strings.TrimSpace(value.Title)
	value.PrimaryColor = strings.ToUpper(strings.TrimSpace(value.PrimaryColor))
	value.PrimaryTextColor = strings.ToLower(strings.TrimSpace(value.PrimaryTextColor))
	if value.PrimaryTextColor == "" {
		value.PrimaryTextColor = PrimaryTextAuto
	}
	value.LightLogoURL = strings.TrimSpace(value.LightLogoURL)
	value.DarkLogoURL = strings.TrimSpace(value.DarkLogoURL)
	value.FaviconURL = strings.TrimSpace(value.FaviconURL)
	if value.Title == "" {
		return Branding{}, errors.New("title is required")
	}
	if utf8.RuneCountInString(value.Title) > brandingTitleMaxRunes {
		return Branding{}, fmt.Errorf("title must be at most %d characters", brandingTitleMaxRunes)
	}
	for _, character := range value.Title {
		if unicode.IsControl(character) || isBidirectionalControl(character) {
			return Branding{}, errors.New("title contains unsupported control characters")
		}
	}
	if !brandingColorPattern.MatchString(value.PrimaryColor) {
		return Branding{}, errors.New("primary_color must use #RRGGBB format")
	}
	if value.PrimaryTextColor != PrimaryTextAuto && value.PrimaryTextColor != PrimaryTextWhite && value.PrimaryTextColor != PrimaryTextBlack {
		return Branding{}, errors.New("primary_text_color must be auto, white, or black")
	}
	for field, assetURL := range map[string]string{
		"light_logo_url": value.LightLogoURL,
		"dark_logo_url":  value.DarkLogoURL,
		"favicon_url":    value.FaviconURL,
	} {
		if err := validateBrandingAssetURL(field, assetURL); err != nil {
			return Branding{}, err
		}
	}
	return value, nil
}

func validateBrandingAssetURL(field, value string) error {
	if value == "" {
		return nil
	}
	if len(value) > brandingAssetURLMaxLen {
		return fmt.Errorf("%s must be at most %d characters", field, brandingAssetURLMaxLen)
	}
	parsed, err := url.Parse(value)
	sameOriginPath := err == nil && !parsed.IsAbs() && parsed.Host == "" && strings.HasPrefix(parsed.Path, "/") &&
		!strings.HasPrefix(value, "//") && !strings.Contains(value, `\`)
	secureAbsolute := err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil
	if !sameOriginPath && !secureAbsolute {
		return fmt.Errorf("%s must be a same-origin path or an absolute HTTPS URL without credentials", field)
	}
	return nil
}

func isBidirectionalControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		(character >= '\u202a' && character <= '\u202e') ||
		(character >= '\u2066' && character <= '\u2069')
}

// Registration modes for public self-registration.
const (
	RegistrationClosed     = "closed"
	RegistrationInviteOnly = "invite_only"
	RegistrationOpen       = "open"
)

// ValidRegistrationMode reports whether the value is a known mode.
func ValidRegistrationMode(mode string) bool {
	switch mode {
	case RegistrationClosed, RegistrationInviteOnly, RegistrationOpen:
		return true
	}
	return false
}

// Registration controls public self-registration and invite defaults.
type Registration struct {
	Mode                     string   `json:"mode"`
	RequireEmailVerification bool     `json:"require_email_verification"`
	AllowedEmailDomains      []string `json:"allowed_email_domains"`
	PendingRegistrationTTL   string   `json:"pending_registration_ttl"`
	InviteDefaultTTL         string   `json:"invite_default_ttl"`
	InviteDefaultMaxUses     int      `json:"invite_default_max_uses"`
}

// DefaultRegistration returns the safe out-of-the-box registration settings:
// self-registration disabled, verification required once it is opened.
func DefaultRegistration() Registration {
	return Registration{
		Mode:                     RegistrationClosed,
		RequireEmailVerification: true,
		AllowedEmailDomains:      []string{},
		PendingRegistrationTTL:   "72h",
		InviteDefaultTTL:         "168h",
		InviteDefaultMaxUses:     1,
	}
}

// Security controls runtime enrollment and administrator MFA policy. Turning
// off enrollment does not deactivate factors users already enrolled.
type Security struct {
	TOTPEnabled           bool   `json:"totp_enabled"`
	PasskeysEnabled       bool   `json:"passkeys_enabled"`
	RequireMFAForAdmins   bool   `json:"require_mfa_for_admins"`
	TrustedDevicesEnabled bool   `json:"trusted_devices_enabled"`
	TrustedDeviceTTL      string `json:"trusted_device_ttl"`
}

func DefaultSecurity() Security {
	return Security{
		TOTPEnabled: true, PasskeysEnabled: true, RequireMFAForAdmins: false,
		TrustedDevicesEnabled: true, TrustedDeviceTTL: (30 * 24 * time.Hour).String(),
	}
}

const (
	MinTrustedDeviceTTL = 24 * time.Hour
	MaxTrustedDeviceTTL = 90 * 24 * time.Hour
)

var ErrInvalidSecurity = errors.New("invalid security settings")

func (s Security) TrustedDeviceDuration() time.Duration {
	duration, err := time.ParseDuration(s.TrustedDeviceTTL)
	if err != nil {
		return 0
	}
	return duration
}

func ValidateSecurity(value Security) error {
	duration := value.TrustedDeviceDuration()
	if duration < MinTrustedDeviceTTL || duration > MaxTrustedDeviceTTL {
		return fmt.Errorf("%w: trusted device TTL must be between %s and %s", ErrInvalidSecurity, MinTrustedDeviceTTL, MaxTrustedDeviceTTL)
	}
	return nil
}

// Manager caches the current settings snapshot and keeps it consistent across
// instances with the same LISTEN/NOTIFY + reconciliation pattern the provider
// manager uses. Config values act as defaults when nothing is stored yet.
type Manager struct {
	db                 *pgxpool.Pool
	brandingDefaults   Branding
	auditRetentionDays int
	accessTokenTTL     time.Duration
	refreshTokenTTL    time.Duration
	authCodeTTL        time.Duration
	passkeyRPID        string
	branding           atomic.Pointer[Versioned[Branding]]
	registration       atomic.Pointer[Versioned[Registration]]
	security           atomic.Pointer[Versioned[Security]]
	protection         atomic.Pointer[Versioned[Protection]]
	lifecycle          atomic.Pointer[Versioned[Lifecycle]]
	oauth              atomic.Pointer[Versioned[OAuthPolicy]]
	communications     atomic.Pointer[Versioned[Communications]]
	observability      atomic.Pointer[Versioned[Observability]]
	observabilityApply func(Versioned[Observability])
	loadMu             sync.Mutex
}

func NewManager(db *pgxpool.Pool, brandingDefaults Branding) *Manager {
	return &Manager{db: db, brandingDefaults: normalizeBrandingDefaults(brandingDefaults), auditRetentionDays: 365}
}

// NewManagerForRP scopes factor-policy checks to Passkeys that are usable by
// the deployment's current WebAuthn relying party.
func NewManagerForRP(db *pgxpool.Pool, brandingDefaults Branding, passkeyRPID string) *Manager {
	return &Manager{
		db: db, brandingDefaults: normalizeBrandingDefaults(brandingDefaults),
		auditRetentionDays: 365,
		passkeyRPID:        strings.ToLower(strings.TrimSpace(passkeyRPID)),
	}
}

func normalizeBrandingDefaults(value Branding) Branding {
	if value.PrimaryColor == "" {
		value.PrimaryColor = DefaultPrimaryColor
	}
	if value.PrimaryTextColor == "" {
		value.PrimaryTextColor = PrimaryTextAuto
	}
	return value
}

// SetAuditRetentionFallback sets the deployment fallback used only while no
// lifecycle row exists. Call it during process construction, before Load or
// request handling starts.
func (m *Manager) SetAuditRetentionFallback(retention time.Duration) {
	days := int(retention / (24 * time.Hour))
	if days >= MinAuditRetentionDays && days <= MaxAuditRetentionDays {
		m.auditRetentionDays = days
	}
}

// SetAuthenticationFallbacks configures the deployment values used until an
// administrator stores a lifecycle policy. Existing lifecycle rows from C2
// also inherit missing C4 fields from these values.
func (m *Manager) SetAuthenticationFallbacks(accessTokenTTL, refreshTokenTTL, authorizationCodeTTL time.Duration) {
	if accessTokenTTL > 0 {
		m.accessTokenTTL = accessTokenTTL
	}
	if refreshTokenTTL > 0 {
		m.refreshTokenTTL = refreshTokenTTL
	}
	if authorizationCodeTTL > 0 {
		m.authCodeTTL = authorizationCodeTTL
	}
}

func (m *Manager) lifecycleDefaults() Lifecycle {
	return DefaultLifecycleWithAuthentication(
		m.auditRetentionDays, m.accessTokenTTL, m.refreshTokenTTL, m.authCodeTTL,
	)
}

// Branding returns the stored branding, or the config defaults before the
// first successful load and when nothing has been stored.
func (m *Manager) Branding() Branding {
	return m.BrandingSnapshot().Value
}

func (m *Manager) BrandingSnapshot() Versioned[Branding] {
	if snapshot := m.branding.Load(); snapshot != nil {
		return *snapshot
	}
	return Versioned[Branding]{Value: m.brandingDefaults}
}

// Registration returns the stored registration settings or the safe defaults.
func (m *Manager) Registration() Registration {
	return m.RegistrationSnapshot().Value
}

func (m *Manager) RegistrationSnapshot() Versioned[Registration] {
	if snapshot := m.registration.Load(); snapshot != nil {
		return *snapshot
	}
	return Versioned[Registration]{Value: DefaultRegistration()}
}

// Security returns the stored security policy or the safe defaults.
func (m *Manager) Security() Security {
	return m.SecuritySnapshot().Value
}

func (m *Manager) SecuritySnapshot() Versioned[Security] {
	if snapshot := m.security.Load(); snapshot != nil {
		return *snapshot
	}
	return Versioned[Security]{Value: DefaultSecurity()}
}

func (m *Manager) Protection() Protection {
	return m.ProtectionSnapshot().Value
}

func (m *Manager) ProtectionSnapshot() Versioned[Protection] {
	if snapshot := m.protection.Load(); snapshot != nil {
		return *snapshot
	}
	return Versioned[Protection]{Value: DefaultProtection()}
}

func (m *Manager) Lifecycle() Lifecycle {
	return m.LifecycleSnapshot().Value
}

func (m *Manager) LifecycleSnapshot() Versioned[Lifecycle] {
	if snapshot := m.lifecycle.Load(); snapshot != nil {
		return *snapshot
	}
	return Versioned[Lifecycle]{Value: m.lifecycleDefaults()}
}

func (m *Manager) OAuthPolicy() OAuthPolicy {
	return m.OAuthPolicySnapshot().Value
}

func (m *Manager) OAuthPolicySnapshot() Versioned[OAuthPolicy] {
	if snapshot := m.oauth.Load(); snapshot != nil {
		return *snapshot
	}
	return Versioned[OAuthPolicy]{Value: DefaultOAuthPolicy()}
}

func (m *Manager) Communications() Communications {
	return m.CommunicationsSnapshot().Value
}

func (m *Manager) CommunicationsSnapshot() Versioned[Communications] {
	if snapshot := m.communications.Load(); snapshot != nil {
		return *snapshot
	}
	return Versioned[Communications]{Value: DefaultCommunications()}
}

// Observability returns runtime logging and operational alert settings.
func (m *Manager) Observability() Observability {
	return m.ObservabilitySnapshot().Value
}

func (m *Manager) ObservabilitySnapshot() Versioned[Observability] {
	if snapshot := m.observability.Load(); snapshot != nil {
		return *snapshot
	}
	return Versioned[Observability]{Value: DefaultObservability()}
}

// SetObservabilityApply installs the process-local consumer used to update
// logging and telemetry behavior whenever a validated snapshot is published.
// It must be configured during process construction before Load is called.
func (m *Manager) SetObservabilityApply(apply func(Versioned[Observability])) {
	m.observabilityApply = apply
}

func decodeLifecycle(raw []byte, defaults Lifecycle) (Lifecycle, error) {
	value := defaults
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return Lifecycle{}, err
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return Lifecycle{}, err
	}
	if _, ok := fields["session_idle_ttl"]; !ok {
		// C2 rows predate idle expiration. Inheriting the row's absolute TTL
		// preserves their previous behavior instead of silently shortening it.
		value.SessionIdleTTL = value.SessionAbsoluteTTL
	}
	if _, ok := fields["max_concurrent_sessions"]; !ok {
		value.MaxConcurrentSessions = 0
	}

	validationValue := value
	codeDefaults := DefaultLifecycle(defaults.AuditRetentionDays)
	if _, ok := fields["access_token_ttl"]; !ok {
		validationValue.AccessTokenTTL = codeDefaults.AccessTokenTTL
	}
	if _, ok := fields["refresh_token_ttl"]; !ok {
		validationValue.RefreshTokenTTL = codeDefaults.RefreshTokenTTL
	}
	if _, ok := fields["authorization_code_ttl"]; !ok {
		validationValue.AuthorizationCodeTTL = codeDefaults.AuthorizationCodeTTL
	}
	if err := ValidateLifecycle(validationValue); err != nil {
		return Lifecycle{}, err
	}
	return value, nil
}

// Load refreshes every settings group from the database. Missing rows reset
// the corresponding group to its defaults so deletes propagate too.
func (m *Manager) Load(ctx context.Context) error {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	if m.db == nil {
		return nil
	}
	rows, err := m.db.Query(ctx, `SELECT key, value, revision FROM runtime_settings WHERE key = ANY($1)`,
		[]string{brandingKey, registrationKey, securityKey, protectionKey, lifecycleKey, oauthKey, communicationsKey, observabilityKey})
	if err != nil {
		return fmt.Errorf("loading runtime settings: %w", err)
	}
	defer rows.Close()
	type storedSetting struct {
		value    []byte
		revision int64
	}
	stored := map[string]storedSetting{}
	for rows.Next() {
		var key string
		var value []byte
		var revision int64
		if err := rows.Scan(&key, &value, &revision); err != nil {
			return fmt.Errorf("scanning runtime setting: %w", err)
		}
		if revision < 1 {
			return fmt.Errorf("runtime setting %s has invalid revision %d", key, revision)
		}
		stored[key] = storedSetting{value: value, revision: revision}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("reading runtime settings: %w", err)
	}

	var branding *Versioned[Branding]
	if storedValue, ok := stored[brandingKey]; ok {
		value := m.brandingDefaults
		if err := json.Unmarshal(storedValue.value, &value); err != nil {
			return fmt.Errorf("decoding stored branding: %w", err)
		}
		value, err := NormalizeBranding(value)
		if err != nil {
			return fmt.Errorf("decoding stored branding: %w", err)
		}
		branding = &Versioned[Branding]{Revision: storedValue.revision, Value: value}
	}

	var registration *Versioned[Registration]
	if storedValue, ok := stored[registrationKey]; ok {
		value := DefaultRegistration()
		if err := json.Unmarshal(storedValue.value, &value); err != nil {
			return fmt.Errorf("decoding stored registration settings: %w", err)
		}
		if !ValidRegistrationMode(value.Mode) {
			return fmt.Errorf("decoding stored registration settings: unsupported mode %q", value.Mode)
		}
		registration = &Versioned[Registration]{Revision: storedValue.revision, Value: value}
	}

	var security *Versioned[Security]
	if storedValue, ok := stored[securityKey]; ok {
		value := DefaultSecurity()
		if err := json.Unmarshal(storedValue.value, &value); err != nil {
			return fmt.Errorf("decoding stored security settings: %w", err)
		}
		if err := ValidateSecurity(value); err != nil {
			return fmt.Errorf("decoding stored security settings: %w", err)
		}
		security = &Versioned[Security]{Revision: storedValue.revision, Value: value}
	}

	var protection *Versioned[Protection]
	if storedValue, ok := stored[protectionKey]; ok {
		value := DefaultProtection()
		if err := json.Unmarshal(storedValue.value, &value); err != nil {
			return fmt.Errorf("decoding stored protection settings: %w", err)
		}
		if err := ValidateProtection(value); err != nil {
			return fmt.Errorf("decoding stored protection settings: %w", err)
		}
		protection = &Versioned[Protection]{Revision: storedValue.revision, Value: value}
	}

	var lifecycle *Versioned[Lifecycle]
	if storedValue, ok := stored[lifecycleKey]; ok {
		value, err := decodeLifecycle(storedValue.value, m.lifecycleDefaults())
		if err != nil {
			return fmt.Errorf("decoding stored lifecycle settings: %w", err)
		}
		lifecycle = &Versioned[Lifecycle]{Revision: storedValue.revision, Value: value}
	}

	var oauthPolicy *Versioned[OAuthPolicy]
	if storedValue, ok := stored[oauthKey]; ok {
		value := DefaultOAuthPolicy()
		if err := json.Unmarshal(storedValue.value, &value); err != nil {
			return fmt.Errorf("decoding stored OAuth settings: %w", err)
		}
		value, err = NormalizeOAuthPolicy(value)
		if err != nil {
			return fmt.Errorf("decoding stored OAuth settings: %w", err)
		}
		oauthPolicy = &Versioned[OAuthPolicy]{Revision: storedValue.revision, Value: value}
	}

	var communications *Versioned[Communications]
	if storedValue, ok := stored[communicationsKey]; ok {
		value := DefaultCommunications()
		if err := json.Unmarshal(storedValue.value, &value); err != nil {
			return fmt.Errorf("decoding stored communication settings: %w", err)
		}
		value, err = NormalizeCommunications(value)
		if err != nil {
			return fmt.Errorf("decoding stored communication settings: %w", err)
		}
		communications = &Versioned[Communications]{Revision: storedValue.revision, Value: value}
	}

	var observability *Versioned[Observability]
	if storedValue, ok := stored[observabilityKey]; ok {
		value := DefaultObservability()
		if err := json.Unmarshal(storedValue.value, &value); err != nil {
			return fmt.Errorf("decoding stored observability settings: %w", err)
		}
		if err := ValidateObservability(value); err != nil {
			return fmt.Errorf("decoding stored observability settings: %w", err)
		}
		observability = &Versioned[Observability]{Revision: storedValue.revision, Value: value}
	}

	// Publish only after every stored group decodes and validates, so a corrupt
	// row cannot partially replace the last known-good process snapshot.
	m.branding.Store(branding)
	m.registration.Store(registration)
	m.security.Store(security)
	m.protection.Store(protection)
	m.lifecycle.Store(lifecycle)
	m.oauth.Store(oauthPolicy)
	m.communications.Store(communications)
	m.observability.Store(observability)
	if m.observabilityApply != nil {
		m.observabilityApply(m.ObservabilitySnapshot())
	}
	return nil
}

// SetBranding persists the branding, refreshes the local snapshot, and
// notifies other instances.
func (m *Manager) SetBranding(
	ctx context.Context,
	branding Branding,
	expectedRevision int64,
	updatedBy string,
	mutation audit.MutationAudit,
) (int64, error) {
	branding, err := NormalizeBranding(branding)
	if err != nil {
		return 0, err
	}
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	revision, err := m.storeAudited(ctx, brandingKey, branding, expectedRevision, updatedBy, mutation, map[string]any{
		"title": branding.Title, "primary_color": branding.PrimaryColor,
		"primary_text_color":    branding.PrimaryTextColor,
		"light_logo_configured": branding.LightLogoURL != "", "dark_logo_configured": branding.DarkLogoURL != "",
		"favicon_configured": branding.FaviconURL != "",
	})
	if err != nil {
		return 0, err
	}
	m.branding.Store(&Versioned[Branding]{Revision: revision, Value: branding})
	return revision, nil
}

// SetRegistration persists the registration settings, refreshes the local
// snapshot, and notifies other instances. Validation is the caller's
// responsibility.
func (m *Manager) SetRegistration(
	ctx context.Context,
	registration Registration,
	expectedRevision int64,
	updatedBy string,
	fallbackMailConfigured bool,
	mutation audit.MutationAudit,
) (int64, error) {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	if m.db == nil {
		return 0, errors.New("runtime settings storage is unavailable")
	}
	if err := mutation.ValidateEvent(models.AuditSettingsUpdated); err != nil {
		return 0, fmt.Errorf("validating registration settings audit: %w", err)
	}
	encoded, err := json.Marshal(registration)
	if err != nil {
		return 0, fmt.Errorf("encoding %s settings: %w", registrationKey, err)
	}
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("starting registration settings transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockRegistrationExclusive(ctx, tx); err != nil {
		return 0, err
	}
	if registration.Mode != RegistrationClosed {
		configured, configuredErr := runtimecoord.MailConfigured(ctx, tx, fallbackMailConfigured)
		if configuredErr != nil {
			return 0, configuredErr
		}
		if !configured {
			return 0, ErrMailConfigurationNeeded
		}
	}
	if err := validateRegistrationServiceControlTx(ctx, tx, registration.Mode); err != nil {
		return 0, err
	}
	revision, err := storeSettingTx(ctx, tx, registrationKey, encoded, expectedRevision, updatedBy)
	if err != nil {
		return 0, err
	}
	mutation = mutation.WithTarget("settings", registrationKey).WithDetails(map[string]any{
		"revision": revision, "mode": registration.Mode,
		"require_email_verification": registration.RequireEmailVerification,
		"pending_registration_ttl":   registration.PendingRegistrationTTL,
		"invite_default_ttl":         registration.InviteDefaultTTL,
		"invite_default_max_uses":    registration.InviteDefaultMaxUses,
	})
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return 0, fmt.Errorf("auditing registration settings: %w", err)
	}
	if err := notifySettingTx(ctx, tx, registrationKey); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("committing registration settings: %w", err)
	}
	m.registration.Store(&Versioned[Registration]{Revision: revision, Value: registration})
	return revision, nil
}

func validateRegistrationServiceControlTx(ctx context.Context, tx pgx.Tx, mode string) error {
	rows, err := tx.Query(ctx, `
		SELECT capability FROM service_control_pauses
		WHERE capability IN ('self_registration','auth_issuance','mail_delivery')
	`)
	if err != nil {
		return fmt.Errorf("checking registration service control: %w", err)
	}
	defer rows.Close()
	paused := make(map[string]bool, 3)
	for rows.Next() {
		var capability string
		if err := rows.Scan(&capability); err != nil {
			return fmt.Errorf("reading registration service control: %w", err)
		}
		paused[capability] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("checking registration service control: %w", err)
	}
	if paused["auth_issuance"] && !paused["self_registration"] {
		return ErrServiceControlConflict
	}
	if mode != RegistrationClosed && paused["mail_delivery"] && !paused["self_registration"] {
		return ErrServiceControlConflict
	}
	return nil
}

// SetSecurity persists the runtime MFA policy. Mandatory administrator MFA is
// enabled only while every active administrator has at least one confirmed
// factor. Enrollment switches do not deactivate factors already registered.
// Management callers pass one trusted mutation audit so the setting and its
// successful audit event commit atomically.
func (m *Manager) SetSecurity(
	ctx context.Context,
	security Security,
	expectedRevision int64,
	updatedBy string,
	mutation audit.MutationAudit,
) (int64, error) {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	if m.db == nil {
		return 0, errors.New("runtime settings storage is unavailable")
	}
	if err := ValidateSecurity(security); err != nil {
		return 0, err
	}
	if err := mutation.ValidateEvent(models.AuditSettingsUpdated); err != nil {
		return 0, fmt.Errorf("validating security settings audit: %w", err)
	}
	mutation = mutation.WithTarget("settings", securityKey).WithDetails(map[string]any{
		"totp_enabled":            security.TOTPEnabled,
		"passkeys_enabled":        security.PasskeysEnabled,
		"require_mfa_for_admins":  security.RequireMFAForAdmins,
		"trusted_devices_enabled": security.TrustedDevicesEnabled,
		"trusted_device_ttl":      security.TrustedDeviceTTL,
	})
	encoded, err := json.Marshal(security)
	if err != nil {
		return 0, fmt.Errorf("encoding %s settings: %w", securityKey, err)
	}
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("starting security settings transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockSecurityExclusive(ctx, tx); err != nil {
		return 0, err
	}
	previous, err := LoadSecurityTx(ctx, tx)
	if err != nil {
		return 0, err
	}
	if security.RequireMFAForAdmins {
		rows, err := tx.Query(ctx, `
			SELECT u.username
			FROM users AS u
			WHERE u.status='active' AND u.role='admin'
			  AND NOT EXISTS (
				SELECT 1 FROM user_totp_credentials AS totp
				WHERE totp.user_id=u.id AND totp.confirmed_at IS NOT NULL
			  )
			  AND NOT EXISTS (
				SELECT 1 FROM user_passkey_credentials AS passkey
				WHERE passkey.user_id=u.id AND ($1='' OR passkey.rp_id=$1)
			  )
			ORDER BY u.username
		`, m.passkeyRPID)
		if err != nil {
			return 0, fmt.Errorf("checking administrator MFA enrollment: %w", err)
		}
		var missing []string
		for rows.Next() {
			var username string
			if err := rows.Scan(&username); err != nil {
				rows.Close()
				return 0, fmt.Errorf("reading administrator MFA enrollment: %w", err)
			}
			missing = append(missing, username)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, fmt.Errorf("checking administrator MFA enrollment: %w", err)
		}
		if len(missing) > 0 {
			return 0, &AdminsMissingMFAError{Usernames: missing}
		}
	}
	revision, err := storeSettingTx(ctx, tx, securityKey, encoded, expectedRevision, updatedBy)
	if err != nil {
		return 0, err
	}
	var revokedTrustedDevices int64
	if previous.TrustedDevicesEnabled && !security.TrustedDevicesEnabled {
		tag, err := tx.Exec(ctx, `
			UPDATE user_trusted_devices SET revoked_at=NOW()
			WHERE revoked_at IS NULL
		`)
		if err != nil {
			return 0, fmt.Errorf("revoking trusted devices while disabling policy: %w", err)
		}
		revokedTrustedDevices = tag.RowsAffected()
	}
	mutation = mutation.WithDetails(map[string]any{
		"revision": revision, "totp_enabled": security.TOTPEnabled,
		"passkeys_enabled":        security.PasskeysEnabled,
		"require_mfa_for_admins":  security.RequireMFAForAdmins,
		"trusted_devices_enabled": security.TrustedDevicesEnabled,
		"trusted_device_ttl":      security.TrustedDeviceTTL,
		"trusted_devices_revoked": revokedTrustedDevices,
	})
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return 0, fmt.Errorf("auditing security settings: %w", err)
	}
	if err := notifySettingTx(ctx, tx, securityKey); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("committing security settings: %w", err)
	}
	m.security.Store(&Versioned[Security]{Revision: revision, Value: security})
	return revision, nil
}

// LoadSecurityTx reads the authoritative security policy while the caller's
// transaction holds the shared policy lock.
func LoadSecurityTx(ctx context.Context, tx pgx.Tx) (Security, error) {
	security := DefaultSecurity()
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT value FROM runtime_settings WHERE key=$1 FOR SHARE`, securityKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return security, nil
	}
	if err != nil {
		return Security{}, fmt.Errorf("locking security settings: %w", err)
	}
	if err := json.Unmarshal(raw, &security); err != nil {
		return Security{}, fmt.Errorf("decoding stored security settings: %w", err)
	}
	if err := ValidateSecurity(security); err != nil {
		return Security{}, fmt.Errorf("decoding stored security settings: %w", err)
	}
	return security, nil
}

// LoadRegistrationTx reads and locks the authoritative registration policy.
// A missing row represents the safe defaults, and the coordination advisory
// lock prevents a concurrent first insert from bypassing this observation.
func LoadRegistrationTx(ctx context.Context, tx pgx.Tx) (Registration, error) {
	registration := DefaultRegistration()
	var raw []byte
	err := tx.QueryRow(ctx, `
		SELECT value FROM runtime_settings
		WHERE key=$1
		FOR SHARE
	`, registrationKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return registration, nil
	}
	if err != nil {
		return Registration{}, fmt.Errorf("locking registration settings: %w", err)
	}
	if err := json.Unmarshal(raw, &registration); err != nil {
		return Registration{}, fmt.Errorf("decoding stored registration settings: %w", err)
	}
	return registration, nil
}

// RequireRegistrationTx verifies that a request still uses the complete
// authoritative policy that was validated by the HTTP layer.
func RequireRegistrationTx(ctx context.Context, tx pgx.Tx, expected Registration) error {
	current, err := LoadRegistrationTx(ctx, tx)
	if err != nil {
		return err
	}
	if !sameRegistration(current, expected) {
		return ErrRegistrationChanged
	}
	return nil
}

func sameRegistration(left, right Registration) bool {
	return left.Mode == right.Mode &&
		left.RequireEmailVerification == right.RequireEmailVerification &&
		slices.Equal(left.AllowedEmailDomains, right.AllowedEmailDomains) &&
		left.PendingRegistrationTTL == right.PendingRegistrationTTL &&
		left.InviteDefaultTTL == right.InviteDefaultTTL &&
		left.InviteDefaultMaxUses == right.InviteDefaultMaxUses
}

// StartSynchronization keeps the snapshot consistent across instances:
// LISTEN/NOTIFY for low latency, periodic reconciliation for dropped
// notifications and reconnects.
func (m *Manager) StartSynchronization(ctx context.Context) {
	if m == nil || m.db == nil {
		return
	}
	go m.listenForChanges(ctx)
	go m.reconcile(ctx)
}

func (m *Manager) reconcile(ctx context.Context) {
	ticker := time.NewTicker(reconciliationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Load(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.ErrorContext(ctx, "settings reconciliation failed", "error", err)
			}
		}
	}
}

func (m *Manager) listenForChanges(ctx context.Context) {
	for ctx.Err() == nil {
		connection, err := m.db.Acquire(ctx)
		if err != nil {
			m.waitBeforeReconnect(ctx, err)
			continue
		}
		if _, err = connection.Exec(ctx, `LISTEN nyauth_settings_changed`); err != nil {
			connection.Release()
			m.waitBeforeReconnect(ctx, err)
			continue
		}
		for ctx.Err() == nil {
			if _, err = connection.Conn().WaitForNotification(ctx); err != nil {
				break
			}
			if err = m.Load(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.ErrorContext(ctx, "settings notification reload failed", "error", err)
			}
		}
		connection.Release()
		if ctx.Err() == nil {
			m.waitBeforeReconnect(ctx, err)
		}
	}
}

func (m *Manager) waitBeforeReconnect(ctx context.Context, err error) {
	if err != nil && !errors.Is(err, context.Canceled) {
		slog.WarnContext(ctx, "settings notification listener disconnected", "error", err)
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
