// Package mailruntime persists immutable SMTP configuration versions and the
// shared runtime state used by every nyauth instance.
package mailruntime

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	ModeFallback = "fallback"
	ModeActive   = "active"
	ModeDisabled = "disabled"

	TLSModeStartTLS = "starttls"
	TLSModeImplicit = "implicit"
	TLSModePlain    = "plain"

	TestResultSuccess = "success"
	TestResultFailure = "failure"

	ErrorCategoryConfiguration  = "configuration"
	ErrorCategoryAuthentication = "authentication"
	ErrorCategoryTLS            = "tls"
	ErrorCategoryTransport      = "transport"
	ErrorCategoryRecipient      = "recipient"
	ErrorCategoryUnknown        = "unknown"

	CircuitClosed = "closed"
	CircuitOpen   = "open"

	AuditSettingsSaved      = models.AuditMailSettingsSaved
	AuditSettingsTested     = models.AuditMailSettingsTested
	AuditSettingsActivated  = models.AuditMailSettingsActivated
	AuditSettingsDisabled   = models.AuditMailSettingsDisabled
	AuditSettingsRolledBack = models.AuditMailSettingsRolledBack
	AuditCircuitOpened      = models.AuditMailCircuitOpened
	AuditCircuitRecovered   = models.AuditMailCircuitRecovered

	NotificationChannel     = "nyauth_mail_runtime_changed"
	PasswordEnvelopePurpose = "mail-runtime-smtp-password"
)

const (
	CandidateTestValidity  = 10 * time.Minute
	TransportFailureWindow = 2 * time.Minute
	TransportFailureLimit  = 3
	CircuitProbeInterval   = 30 * time.Second
)

var (
	ErrStoreUnavailable      = errors.New("mail runtime store is unavailable")
	ErrInvalidConfig         = errors.New("invalid mail runtime configuration")
	ErrInvalidOutcome        = errors.New("invalid mail runtime outcome")
	ErrVersionNotFound       = errors.New("mail configuration version not found")
	ErrCandidateNotFound     = errors.New("mail configuration candidate not found")
	ErrCandidateChanged      = errors.New("mail configuration candidate changed")
	ErrStateConflict         = errors.New("mail runtime state revision conflict")
	ErrPasswordInheritance   = errors.New("mail configuration password cannot be inherited")
	ErrCandidateTestRequired = errors.New("recent successful candidate test is required")
	ErrCandidateTestExpired  = errors.New("successful candidate test has expired")
	ErrNoPreviousVersion     = errors.New("previous mail configuration version is unavailable")
	ErrAlreadyDisabled       = errors.New("runtime mail is already disabled")
	ErrRegistrationOpen      = errors.New("self-registration must be closed before disabling mail")
	ErrCircuitClosed         = errors.New("mail runtime circuit is closed")
	ErrProbeNotDue           = errors.New("mail runtime circuit probe is not due")
	ErrStaleEffectiveConfig  = errors.New("mail runtime effective configuration changed")
)

type StoreOptions struct {
	ActiveKeyID string
	MasterKeys  map[string][]byte
	Clock       func() time.Time
}

// Settings contains the non-secret portion of an SMTP configuration.
type Settings struct {
	Host           string        `json:"host"`
	Port           int           `json:"port"`
	Username       string        `json:"username"`
	TLSMode        string        `json:"tls_mode"`
	FromAddress    string        `json:"from_address"`
	FromName       string        `json:"from_name"`
	PublicBaseURL  string        `json:"public_base_url"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	SendTimeout    time.Duration `json:"send_timeout"`
}

// SMTPConfig is an internal runtime value. Password is intentionally excluded
// from JSON so an API cannot expose it by serializing this type directly.
type SMTPConfig struct {
	Settings
	Password string `json:"-"`
}

// Version is the only public representation of a persisted configuration.
// The encrypted password is deliberately absent.
type Version struct {
	ID       uuid.UUID `json:"id"`
	Revision int64     `json:"revision"`
	Settings
	PasswordConfigured bool       `json:"password_configured"`
	CreatedBy          *uuid.UUID `json:"created_by"`
	CreatedAt          time.Time  `json:"created_at"`
}

type State struct {
	Mode                          string     `json:"mode"`
	ActiveVersionID               *uuid.UUID `json:"active_version_id"`
	CandidateVersionID            *uuid.UUID `json:"candidate_version_id"`
	PreviousVersionID             *uuid.UUID `json:"previous_version_id"`
	Revision                      int64      `json:"revision"`
	CircuitState                  string     `json:"circuit_state"`
	CircuitOpenReason             *string    `json:"circuit_open_reason"`
	CircuitOpenCategory           *string    `json:"circuit_open_category"`
	CircuitOpenedAt               *time.Time `json:"circuit_opened_at"`
	TransportFailureWindowStarted *time.Time `json:"transport_failure_window_started_at"`
	TransportFailureCount         int        `json:"transport_failure_count"`
	NextProbeAt                   *time.Time `json:"next_probe_at"`
	UpdatedAt                     time.Time  `json:"updated_at"`
}

type EffectiveConfig struct {
	Mode            string      `json:"mode"`
	StateRevision   int64       `json:"state_revision"`
	VersionID       *uuid.UUID  `json:"version_id"`
	VersionRevision *int64      `json:"version_revision"`
	Configured      bool        `json:"configured"`
	Available       bool        `json:"available"`
	CircuitState    string      `json:"circuit_state"`
	Config          *SMTPConfig `json:"-"`
}

type CreateCandidateInput struct {
	ExpectedRevision int64
	Settings         Settings
	// Password nil means inherit from the currently effective configuration.
	// A pointer to an empty string explicitly configures passwordless SMTP.
	Password *string `json:"-"`
	// Fallback is consulted only while state.mode is fallback and is never
	// persisted as a configuration version by itself.
	Fallback *SMTPConfig         `json:"-"`
	Audit    audit.MutationAudit `json:"-"`
}

type CandidateResult struct {
	Version Version
	State   State
}

type RecordTestInput struct {
	ExpectedRevision int64
	VersionID        uuid.UUID
	RecipientHash    []byte
	Result           string
	ErrorCategory    *string
	Audit            audit.MutationAudit `json:"-"`
}

type TestRecord struct {
	ID            uuid.UUID  `json:"id"`
	VersionID     uuid.UUID  `json:"version_id"`
	Result        string     `json:"result"`
	ErrorCategory *string    `json:"error_category"`
	TestedBy      *uuid.UUID `json:"tested_by"`
	CreatedAt     time.Time  `json:"created_at"`
}

type TestResult struct {
	Record TestRecord
	State  State
}

type VersionMutationInput struct {
	ExpectedRevision int64
	VersionID        uuid.UUID
	Audit            audit.MutationAudit `json:"-"`
}

type StateMutationInput struct {
	ExpectedRevision int64
	Audit            audit.MutationAudit `json:"-"`
}

// EffectiveSource identifies the sender snapshot that produced an outcome.
// VersionID is nil only for the environment fallback.
type EffectiveSource struct {
	Mode      string
	VersionID *uuid.UUID
}

type DeliveryOutcome struct {
	Source   EffectiveSource
	Success  bool
	Category string
	// Reason is a bounded machine-readable code, never a raw SMTP error.
	Reason string
}

type CircuitTransition struct {
	State     State
	Changed   bool
	Opened    bool
	Recovered bool
}

type ProbeClaim struct {
	Acquired         bool
	ExpectedRevision int64
	State            State
}

type ProbeOutcome struct {
	Source           EffectiveSource
	ExpectedRevision int64
	Success          bool
	Category         string
	Reason           string
}
