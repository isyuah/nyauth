package models

import (
	"time"

	"github.com/google/uuid"
)

// Identity represents a binding between a local user and an external OAuth provider.
type Identity struct {
	ID               uuid.UUID         `json:"id" db:"id"`
	UserID           uuid.UUID         `json:"user_id" db:"user_id"`
	Provider         string            `json:"provider" db:"provider"`
	ExternalID       string            `json:"external_id" db:"external_id"`
	ExternalUsername *string           `json:"external_username,omitempty" db:"external_username"`
	ExternalEmail    *string           `json:"external_email,omitempty" db:"external_email"`
	Metadata         map[string]string `json:"metadata,omitempty" db:"metadata"`
	CreatedAt        time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at" db:"updated_at"`
}

// ExternalUser is the user info returned by an external provider.
type ExternalUser struct {
	Provider      string
	ID            string
	Username      string
	Email         string
	EmailVerified bool
	AvatarURL     string
	RawClaims     map[string]interface{}
}
