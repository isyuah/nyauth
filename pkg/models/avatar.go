package models

import (
	"time"

	"github.com/google/uuid"
)

type AvatarStatus string

const (
	AvatarStatusStaging  AvatarStatus = "staging"
	AvatarStatusActive   AvatarStatus = "active"
	AvatarStatusReplaced AvatarStatus = "replaced"
	AvatarStatusFailed   AvatarStatus = "failed"
	AvatarStatusDeleted  AvatarStatus = "deleted"
)

type AvatarSource string

const (
	AvatarSourceUserUpload     AvatarSource = "user_upload"
	AvatarSourceAdminUpload    AvatarSource = "admin_upload"
	AvatarSourceProviderImport AvatarSource = "provider_import"
)

type AvatarStorageBackend string

const (
	AvatarStorageLocal AvatarStorageBackend = "local"
	AvatarStorageS3    AvatarStorageBackend = "s3"
)

var AvatarVariantSizes = [...]int{64, 128, 256, 512}

type AvatarVariant struct {
	Size        int    `json:"size"`
	ObjectKey   string `json:"object_key"`
	ContentType string `json:"content_type"`
	Bytes       int64  `json:"bytes"`
}

type UserAvatar struct {
	ID                uuid.UUID            `json:"id" db:"id"`
	UserID            uuid.UUID            `json:"user_id" db:"user_id"`
	Source            AvatarSource         `json:"source" db:"source"`
	Status            AvatarStatus         `json:"status" db:"status"`
	StorageBackend    AvatarStorageBackend `json:"storage_backend" db:"storage_backend"`
	StorageProfileID  *uuid.UUID           `json:"-" db:"storage_profile_id"`
	ObjectPrefix      string               `json:"object_prefix" db:"object_prefix"`
	Variants          []AvatarVariant      `json:"variants" db:"variants"`
	ContentSHA256     []byte               `json:"-" db:"content_sha256"`
	OriginalMediaType string               `json:"original_media_type" db:"original_media_type"`
	OriginalWidth     int                  `json:"original_width" db:"original_width"`
	OriginalHeight    int                  `json:"original_height" db:"original_height"`
	CreatedAt         time.Time            `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time            `json:"updated_at" db:"updated_at"`
	ActivatedAt       *time.Time           `json:"activated_at,omitempty" db:"activated_at"`
	ReplacedAt        *time.Time           `json:"replaced_at,omitempty" db:"replaced_at"`
	DeletedAt         *time.Time           `json:"deleted_at,omitempty" db:"deleted_at"`
	FailedAt          *time.Time           `json:"failed_at,omitempty" db:"failed_at"`
	StorageDeletedAt  *time.Time           `json:"storage_deleted_at,omitempty" db:"storage_deleted_at"`
	CleanupClaimedAt  *time.Time           `json:"-" db:"cleanup_claimed_at"`
	LastError         *string              `json:"last_error,omitempty" db:"last_error"`
}

type ProviderAvatarImportJobStatus string

const (
	ProviderAvatarImportPending    ProviderAvatarImportJobStatus = "pending"
	ProviderAvatarImportProcessing ProviderAvatarImportJobStatus = "processing"
	ProviderAvatarImportCompleted  ProviderAvatarImportJobStatus = "completed"
	ProviderAvatarImportFailed     ProviderAvatarImportJobStatus = "failed"
)

type ProviderAvatarImportJob struct {
	ID                 uuid.UUID                     `json:"id" db:"id"`
	ProviderID         uuid.UUID                     `json:"provider_id" db:"provider_id"`
	UserID             uuid.UUID                     `json:"user_id" db:"user_id"`
	EncryptedAvatarURL string                        `json:"-" db:"encrypted_avatar_url"`
	Status             ProviderAvatarImportJobStatus `json:"status" db:"status"`
	AttemptCount       int                           `json:"attempt_count" db:"attempt_count"`
	AvailableAt        time.Time                     `json:"available_at" db:"available_at"`
	LockedAt           *time.Time                    `json:"locked_at,omitempty" db:"locked_at"`
	LockedBy           *string                       `json:"locked_by,omitempty" db:"locked_by"`
	CompletedAt        *time.Time                    `json:"completed_at,omitempty" db:"completed_at"`
	FailedAt           *time.Time                    `json:"failed_at,omitempty" db:"failed_at"`
	LastError          *string                       `json:"last_error,omitempty" db:"last_error"`
	CreatedAt          time.Time                     `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time                     `json:"updated_at" db:"updated_at"`
}
