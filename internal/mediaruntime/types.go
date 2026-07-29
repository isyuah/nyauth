package mediaruntime

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/config"
)

const (
	NotificationChannel   = "nyauth_media_runtime_changed"
	CredentialPurpose     = "media-runtime-s3-credential"
	CandidateTestValidity = 10 * time.Minute
)

var (
	ErrStoreUnavailable      = errors.New("media runtime store is unavailable")
	ErrInvalidConfig         = errors.New("media storage configuration is invalid")
	ErrStateConflict         = errors.New("media storage state revision conflict")
	ErrCandidateNotFound     = errors.New("media storage candidate was not found")
	ErrCandidateChanged      = errors.New("media storage candidate changed")
	ErrCandidateTestRequired = errors.New("recent successful media storage test is required")
	ErrMigrationActive       = errors.New("a media storage migration is already active")
	ErrMigrationNotFound     = errors.New("media storage migration was not found")
	ErrMigrationNotPaused    = errors.New("media writes must be paused before migration")
	ErrInstancesNotReady     = errors.New("active instances have not prepared the media storage candidate")
)

type ProfileSettings struct {
	Endpoint  string `json:"endpoint"`
	Region    string `json:"region"`
	Bucket    string `json:"bucket"`
	Prefix    string `json:"prefix"`
	PathStyle bool   `json:"path_style"`
}

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

type Profile struct {
	ID                     uuid.UUID       `json:"id"`
	Backend                string          `json:"backend"`
	Settings               ProfileSettings `json:"settings"`
	CredentialsConfigured  bool            `json:"credentials_configured"`
	SessionTokenConfigured bool            `json:"session_token_configured"`
	CreatedBy              *uuid.UUID      `json:"created_by,omitempty"`
	CreatedByName          string          `json:"created_by_name"`
	CreatedAt              time.Time       `json:"created_at"`
	TestedAt               *time.Time      `json:"tested_at,omitempty"`
	TestResult             *string         `json:"test_result,omitempty"`
	TestErrorCategory      *string         `json:"test_error_category,omitempty"`
	TestError              *string         `json:"test_error,omitempty"`
}

type ProfileConfig struct {
	Profile
	Credentials Credentials
}

func (c ProfileConfig) S3Config() config.S3MediaConfig {
	return config.S3MediaConfig{
		Endpoint: c.Settings.Endpoint, Region: c.Settings.Region, Bucket: c.Settings.Bucket,
		Prefix: c.Settings.Prefix, PathStyle: c.Settings.PathStyle,
		AccessKeyID: c.Credentials.AccessKeyID, SecretAccessKey: c.Credentials.SecretAccessKey,
		SessionToken: c.Credentials.SessionToken,
	}
}

type State struct {
	Revision           int64      `json:"revision"`
	ActiveProfileID    *uuid.UUID `json:"active_profile_id,omitempty"`
	CandidateProfileID *uuid.UUID `json:"candidate_profile_id,omitempty"`
	PreviousProfileID  *uuid.UUID `json:"previous_profile_id,omitempty"`
	UpdatedBy          *uuid.UUID `json:"updated_by,omitempty"`
	UpdatedByName      *string    `json:"updated_by_name,omitempty"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type Migration struct {
	ID                     uuid.UUID      `json:"id"`
	SourceProfileID        *uuid.UUID     `json:"source_profile_id,omitempty"`
	SourceBackend          string         `json:"source_backend"`
	TargetProfileID        uuid.UUID      `json:"target_profile_id"`
	Status                 string         `json:"status"`
	TotalCount             int64          `json:"total_count"`
	CopiedCount            int64          `json:"copied_count"`
	CompletedCount         int64          `json:"completed_count"`
	FailedCount            int64          `json:"failed_count"`
	ServiceControlRevision *int64         `json:"service_control_revision,omitempty"`
	ServiceControlPrevious map[string]any `json:"-"`
	CreatedBy              *uuid.UUID     `json:"created_by,omitempty"`
	CreatedByName          string         `json:"created_by_name"`
	CreatedAt              time.Time      `json:"created_at"`
	StartedAt              *time.Time     `json:"started_at,omitempty"`
	CompletedAt            *time.Time     `json:"completed_at,omitempty"`
	FailedAt               *time.Time     `json:"failed_at,omitempty"`
	LastError              *string        `json:"last_error,omitempty"`
	UpdatedAt              time.Time      `json:"updated_at"`
}

type Status struct {
	Mode      string     `json:"mode"`
	Revision  int64      `json:"revision"`
	Available bool       `json:"available"`
	Active    *Profile   `json:"active,omitempty"`
	Candidate *Profile   `json:"candidate,omitempty"`
	Previous  *Profile   `json:"previous,omitempty"`
	Migration *Migration `json:"migration,omitempty"`
}

type CreateCandidateInput struct {
	ExpectedRevision int64
	Settings         ProfileSettings
	Credentials      Credentials
	Audit            audit.MutationAudit
}

type TestCandidateInput struct {
	ExpectedRevision int64
	ProfileID        uuid.UUID
	Audit            audit.MutationAudit
}

type StartMigrationInput struct {
	ExpectedRevision       int64
	ProfileID              uuid.UUID
	SourceBackend          string
	ServiceControlRevision int64
	ServiceControlPrevious map[string]any
	Audit                  audit.MutationAudit
}

type RetryMigrationInput struct {
	MigrationID            uuid.UUID
	ServiceControlRevision int64
	ServiceControlPrevious map[string]any
	Audit                  audit.MutationAudit
}
