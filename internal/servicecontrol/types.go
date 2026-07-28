package servicecontrol

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
)

const (
	NotificationChannel = "nyauth_service_control_changed"

	AuditUpdated  = "service_control.updated"
	AuditExpired  = "service_control.expired"
	AuditCLIReset = "service_control.cli_reset"
)

var (
	ErrStoreUnavailable    = errors.New("service control store is unavailable")
	ErrRevisionConflict    = errors.New("service control revision conflict")
	ErrDependencyViolation = errors.New("service control dependency violation")
	ErrInstanceNotFound    = errors.New("service control instance was not found")
	ErrInvalidState        = errors.New("invalid service control state")
	ErrStaleRevision       = errors.New("stale service control revision")
	ErrSuperseded          = errors.New("service control revision was superseded")
	ErrCapabilityPaused    = errors.New("service capability is paused")
)

type Snapshot struct {
	Revision           int64        `json:"revision"`
	PausedCapabilities []Capability `json:"paused_capabilities"`
	PublicMessage      string       `json:"public_message"`
	InternalReason     string       `json:"internal_reason"`
	ExpiresAt          *time.Time   `json:"expires_at"`
	UpdatedBy          *uuid.UUID   `json:"updated_by"`
	UpdatedByName      *string      `json:"updated_by_name"`
	UpdatedAt          time.Time    `json:"updated_at"`
	// DatabaseNow is the PostgreSQL clock observed while this revision was
	// read. ObservedAt is the local clock immediately after that query. They
	// calibrate expiration without exposing coordination details through APIs.
	DatabaseNow time.Time `json:"-"`
	ObservedAt  time.Time `json:"-"`
}

// EffectiveAt removes an expired pause locally without pretending that the
// database revision has already been advanced by the expiration leader.
func (s Snapshot) EffectiveAt(now time.Time) Snapshot {
	result := cloneSnapshot(s)
	if result.ExpiresAt != nil && !now.UTC().Before(*result.ExpiresAt) {
		result.PausedCapabilities = []Capability{}
		result.PublicMessage = ""
		result.InternalReason = ""
		result.ExpiresAt = nil
	}
	return result
}

type Instance struct {
	ID              uuid.UUID `json:"id"`
	Version         string    `json:"version"`
	StartedAt       time.Time `json:"started_at"`
	HeartbeatAt     time.Time `json:"heartbeat_at"`
	LoadedRevision  int64     `json:"loaded_revision"`
	AppliedRevision int64     `json:"applied_revision"`
}

type State struct {
	Snapshot         Snapshot   `json:"snapshot"`
	Instances        []Instance `json:"instances"`
	ActiveInstances  int        `json:"active_instances"`
	AppliedInstances int        `json:"applied_instances"`
	Applied          bool       `json:"applied"`
}

type ApplicationStatus struct {
	Revision         int64      `json:"revision"`
	Instances        []Instance `json:"instances"`
	ActiveInstances  int        `json:"active_instances"`
	AppliedInstances int        `json:"applied_instances"`
	Applied          bool       `json:"applied"`
}

type UpdateInput struct {
	ExpectedRevision   int64
	PausedCapabilities []Capability
	PublicMessage      string
	InternalReason     string
	ExpiresAt          *time.Time
	UpdatedBy          uuid.UUID
	UpdatedByName      string
	Audit              audit.MutationAudit
}

// UpdateRequest is the administrator-controlled portion of an update. The
// expected revision and trusted audit metadata are separate Manager arguments
// so HTTP handlers cannot accidentally accept either from JSON.
type UpdateRequest struct {
	PausedCapabilities []Capability `json:"paused_capabilities"`
	PublicMessage      string       `json:"public_message"`
	InternalReason     string       `json:"internal_reason"`
	ExpiresAt          *time.Time   `json:"expires_at"`
}

type ResetInput struct {
	Reason    string
	ActorName string
}

type RegisterInstanceInput struct {
	ID              uuid.UUID
	Version         string
	StartedAt       time.Time
	LoadedRevision  int64
	AppliedRevision int64
}

type HeartbeatInput struct {
	ID              uuid.UUID
	LoadedRevision  int64
	AppliedRevision int64
}

type ExpireResult struct {
	Leader  bool
	Expired bool
	State   Snapshot
}

// PausedError describes the exact capabilities that rejected an atomic
// acquisition. FailClosed distinguishes planned maintenance from a stale
// instance that can no longer prove the database state is current.
type PausedError struct {
	Capabilities []Capability
	RetryAfter   time.Duration
	ExpiresAt    *time.Time
	FailClosed   bool
}

func (e *PausedError) Error() string {
	if e.FailClosed {
		return "service capabilities are unavailable because runtime control synchronization is stale"
	}
	return fmt.Sprintf("%s: %v", ErrCapabilityPaused, e.Capabilities)
}

func (e *PausedError) Unwrap() error { return ErrCapabilityPaused }

func cloneSnapshot(value Snapshot) Snapshot {
	value.PausedCapabilities = append([]Capability(nil), value.PausedCapabilities...)
	if value.ExpiresAt != nil {
		expires := value.ExpiresAt.UTC()
		value.ExpiresAt = &expires
	}
	if value.UpdatedBy != nil {
		updatedBy := *value.UpdatedBy
		value.UpdatedBy = &updatedBy
	}
	if value.UpdatedByName != nil {
		updatedByName := *value.UpdatedByName
		value.UpdatedByName = &updatedByName
	}
	value.UpdatedAt = value.UpdatedAt.UTC()
	value.DatabaseNow = value.DatabaseNow.UTC()
	value.ObservedAt = value.ObservedAt.UTC()
	return value
}
