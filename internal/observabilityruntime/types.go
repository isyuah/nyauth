// Package observabilityruntime persists immutable OTLP configuration versions
// and coordinates one effective exporter across all application instances.
package observabilityruntime

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

	TestSuccess                            = "success"
	TestFailure                            = "failure"
	TestErrorTimeout                       = "timeout"
	TestErrorConnectionOrCollectorRejected = "connection_or_collector_rejected"

	NotificationChannel           = "nyauth_otlp_runtime_changed"
	EnvelopePurpose               = "runtime-otlp-authorization"
	CandidateTestValidity         = 10 * time.Minute
	DefaultReconciliationInterval = time.Minute
)

var (
	ErrStoreUnavailable         = errors.New("OTLP runtime store is unavailable")
	ErrInvalidConfig            = errors.New("invalid OTLP configuration")
	ErrStateConflict            = errors.New("OTLP runtime state revision conflict")
	ErrCandidateNotFound        = errors.New("OTLP configuration candidate not found")
	ErrCandidateChanged         = errors.New("OTLP configuration candidate changed")
	ErrAuthorizationInheritance = errors.New("OTLP authorization cannot be inherited")
	ErrCandidateTestRequired    = errors.New("recent successful OTLP candidate test is required")
	ErrCandidateTestExpired     = errors.New("successful OTLP candidate test has expired")
	ErrNoPreviousVersion        = errors.New("previous OTLP configuration version is unavailable")
	ErrAlreadyDisabled          = errors.New("OTLP export is already disabled")
)

type StoreOptions struct {
	ActiveKeyID string
	MasterKeys  map[string][]byte
	Clock       func() time.Time
}

type Settings struct {
	Endpoint       string        `json:"endpoint"`
	ExportInterval time.Duration `json:"export_interval"`
	Timeout        time.Duration `json:"timeout"`
}

type Config struct {
	Settings
	Authorization string `json:"-"`
}

type Version struct {
	ID       uuid.UUID `json:"id"`
	Revision int64     `json:"revision"`
	Settings
	AuthorizationConfigured bool       `json:"authorization_configured"`
	CreatedBy               *uuid.UUID `json:"created_by"`
	CreatedAt               time.Time  `json:"created_at"`
}

type State struct {
	Mode               string     `json:"mode"`
	ActiveVersionID    *uuid.UUID `json:"active_version_id"`
	CandidateVersionID *uuid.UUID `json:"candidate_version_id"`
	PreviousVersionID  *uuid.UUID `json:"previous_version_id"`
	Revision           int64      `json:"revision"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type EffectiveConfig struct {
	Mode          string
	StateRevision int64
	VersionID     *uuid.UUID
	Configured    bool
	Config        *Config
}

type CreateCandidateInput struct {
	ExpectedRevision int64
	Settings         Settings
	Authorization    *string
	Fallback         *Config
	Audit            audit.MutationAudit
}

type CandidateResult struct {
	Version Version
	State   State
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
	Revision  int64      `json:"revision"`
	VersionID uuid.UUID  `json:"version_id"`
	Result    string     `json:"result"`
	ErrorCode *string    `json:"error_code"`
	TestedBy  *uuid.UUID `json:"tested_by"`
	CreatedAt time.Time  `json:"created_at"`
}

type TestResult struct {
	Record TestRecord
	State  State
}
type VersionMutationInput struct {
	ExpectedRevision int64
	VersionID        uuid.UUID
	Audit            audit.MutationAudit
}
type StateMutationInput struct {
	ExpectedRevision int64
	Audit            audit.MutationAudit
}

const (
	AuditSettingsSaved      = models.AuditTelemetrySettingsSaved
	AuditSettingsTested     = models.AuditTelemetrySettingsTested
	AuditSettingsActivated  = models.AuditTelemetrySettingsActivated
	AuditSettingsDisabled   = models.AuditTelemetrySettingsDisabled
	AuditSettingsRolledBack = models.AuditTelemetrySettingsRolledBack
)
