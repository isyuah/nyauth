// Package humanverification provides runtime-selectable bot verification
// without coupling public account flows to a specific third-party provider.
package humanverification

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	ProviderTurnstile = "turnstile"

	ModeActive   = "active"
	ModeDisabled = "disabled"

	WidgetManaged        = "managed"
	WidgetNonInteractive = "non-interactive"
	WidgetInvisible      = "invisible"

	LoginOff      = "off"
	LoginAdaptive = "adaptive"
	LoginAlways   = "always"

	TestSuccess = "success"
	TestFailure = "failure"

	NotificationChannel    = "nyauth_human_verification_changed"
	SecretEnvelopePurpose  = "human-verification-provider-secret"
	CandidateTestValidity  = 10 * time.Minute
	DefaultRequestTimeout  = 5 * time.Second
	DefaultReconcilePeriod = time.Minute

	AuditSettingsSaved      = models.AuditHumanVerificationSaved
	AuditSettingsTested     = models.AuditHumanVerificationTested
	AuditSettingsActivated  = models.AuditHumanVerificationActivated
	AuditSettingsEnabled    = models.AuditHumanVerificationEnabled
	AuditSettingsUpdated    = models.AuditHumanVerificationUpdated
	AuditSettingsDisabled   = models.AuditHumanVerificationDisabled
	AuditSettingsRolledBack = models.AuditHumanVerificationRolledBack
	AuditCLIDisabled        = models.AuditHumanVerificationCLIDisabled
)

// Action is the closed vocabulary shared by policy evaluation, provider
// verification and telemetry. Its external string is defined once in the
// action catalog in validation.go.
type Action uint8

const (
	ActionRegistration Action = iota + 1
	ActionLogin
	ActionPasswordReset
	ActionEmailVerificationResend
	ActionProviderLogin
	ActionAdminTest
)

var (
	ErrStoreUnavailable        = errors.New("human verification store is unavailable")
	ErrInvalidConfig           = errors.New("invalid human verification configuration")
	ErrStateConflict           = errors.New("human verification state revision conflict")
	ErrCandidateNotFound       = errors.New("human verification candidate not found")
	ErrVersionNotFound         = errors.New("human verification version not found")
	ErrSecretInheritance       = errors.New("human verification secret cannot be inherited")
	ErrCandidateTestRequired   = errors.New("recent successful candidate test is required")
	ErrCandidateTestExpired    = errors.New("successful candidate test has expired")
	ErrNoPreviousVersion       = errors.New("previous human verification version is unavailable")
	ErrNoActiveVersion         = errors.New("active human verification version is unavailable")
	ErrAlreadyDisabled         = errors.New("human verification is already disabled")
	ErrAlreadyEnabled          = errors.New("human verification is already enabled")
	ErrVerificationRejected    = errors.New("human verification was rejected")
	ErrVerificationUnavailable = errors.New("human verification is unavailable")
)

type Policy struct {
	Registration            bool   `json:"registration"`
	LoginMode               string `json:"login_mode"`
	LoginTriggerAfter       int    `json:"login_trigger_after"`
	PasswordReset           bool   `json:"password_reset"`
	EmailVerificationResend bool   `json:"email_verification_resend"`
	ProviderLogin           bool   `json:"provider_login"`
}

func DefaultPolicy() Policy {
	return Policy{
		Registration:            true,
		LoginMode:               LoginAdaptive,
		LoginTriggerAfter:       3,
		PasswordReset:           true,
		EmailVerificationResend: true,
		ProviderLogin:           true,
	}
}

type Settings struct {
	Provider   string `json:"provider"`
	SiteKey    string `json:"site_key"`
	WidgetMode string `json:"widget_mode"`
}

type Config struct {
	Settings
	Secret string `json:"-"`
}

type Version struct {
	ID       uuid.UUID `json:"id"`
	Revision int64     `json:"revision"`
	Settings
	SecretConfigured bool       `json:"secret_configured"`
	CreatedBy        *uuid.UUID `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
}

type State struct {
	Mode               string     `json:"mode"`
	ActiveVersionID    *uuid.UUID `json:"active_version_id"`
	CandidateVersionID *uuid.UUID `json:"candidate_version_id"`
	PreviousVersionID  *uuid.UUID `json:"previous_version_id"`
	Policy             Policy     `json:"policy"`
	Revision           int64      `json:"revision"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type EffectiveConfig struct {
	State      State    `json:"-"`
	Configured bool     `json:"configured"`
	Available  bool     `json:"available"`
	Version    *Version `json:"version,omitempty"`
	Config     *Config  `json:"-"`
}

type CreateCandidateInput struct {
	ExpectedRevision int64
	Settings         Settings
	Secret           *string
	Audit            audit.MutationAudit
}

type CandidateResult struct {
	Version Version `json:"version"`
	State   State   `json:"state"`
}

type RecordTestInput struct {
	ExpectedRevision int64
	VersionID        uuid.UUID
	Result           string
	ErrorCode        *string
	Audit            audit.MutationAudit
}

type TestRecord struct {
	ID        uuid.UUID  `json:"id"`
	VersionID uuid.UUID  `json:"version_id"`
	Result    string     `json:"result"`
	ErrorCode *string    `json:"error_code"`
	TestedBy  *uuid.UUID `json:"tested_by"`
	CreatedAt time.Time  `json:"created_at"`
}

type TestResult struct {
	Record TestRecord `json:"record"`
	State  State      `json:"state"`
}

type ActivateInput struct {
	ExpectedRevision int64
	VersionID        uuid.UUID
	Policy           Policy
	Audit            audit.MutationAudit
}

type StateMutationInput struct {
	ExpectedRevision int64
	Audit            audit.MutationAudit
}

type PolicyMutationInput struct {
	ExpectedRevision int64
	Policy           Policy
	Audit            audit.MutationAudit
}

type VerifyInput struct {
	Token          string
	RemoteIP       string
	Action         Action
	IdempotencyKey string
}

type VerifyResult struct {
	Hostname   string
	Action     string
	ErrorCodes []string
}

type RecoveryDisableReport struct {
	State   State `json:"state"`
	Changed bool  `json:"changed"`
}
