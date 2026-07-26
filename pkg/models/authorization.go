package models

import (
	"time"

	"github.com/google/uuid"
)

// OAuthAuthorization is a user's active grant to an OAuth client.
type OAuthAuthorization struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	UserID     uuid.UUID  `json:"-" db:"user_id"`
	ClientID   string     `json:"client_id" db:"client_id"`
	ClientName string     `json:"client_name" db:"client_name"`
	Scopes     []string   `json:"scopes" db:"scopes"`
	GrantedAt  time.Time  `json:"granted_at" db:"granted_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
}
