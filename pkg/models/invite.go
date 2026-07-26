package models

import (
	"time"

	"github.com/google/uuid"
)

// Invite is an invitation code for invite-only self-registration. The code
// itself is stored only as a hash and returned in plaintext exactly once at
// creation time.
type Invite struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	CodeHash      string     `json:"-" db:"code_hash"`
	CreatedBy     *uuid.UUID `json:"created_by" db:"created_by"`
	Note          string     `json:"note" db:"note"`
	MaxUses       int        `json:"max_uses" db:"max_uses"`
	UsedCount     int        `json:"used_count" db:"used_count"`
	ReservedCount int        `json:"reserved_count" db:"reserved_count"`
	ExpiresAt     time.Time  `json:"expires_at" db:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at" db:"revoked_at"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	Status        string     `json:"status" db:"-"`
}

// StatusAt derives the display status of an invite at the given time.
func (i *Invite) StatusAt(now time.Time) string {
	switch {
	case i.RevokedAt != nil:
		return "revoked"
	case !now.Before(i.ExpiresAt):
		return "expired"
	case i.UsedCount+i.ReservedCount >= i.MaxUses:
		return "exhausted"
	default:
		return "active"
	}
}

// CreateInviteRequest is the admin payload to create an invite. Omitted
// fields fall back to the runtime registration settings.
type CreateInviteRequest struct {
	Note    string `json:"note,omitempty"`
	MaxUses int    `json:"max_uses,omitempty"`
	TTL     string `json:"ttl,omitempty"`
}

// CreateInviteResponse carries the one-time plaintext code.
type CreateInviteResponse struct {
	Invite
	Code        string `json:"code"`
	RegisterURL string `json:"register_url"`
}

// RegisterResponse reports whether the new account is ready to use or waiting
// for email verification. VerificationExpiresAt is present only for pending
// registrations.
type RegisterResponse struct {
	Status                string     `json:"status"`
	VerificationExpiresAt *time.Time `json:"verification_expires_at,omitempty"`
}

// RegisterRequest is the public self-registration payload.
type RegisterRequest struct {
	Username   string `json:"username"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	InviteCode string `json:"invite_code,omitempty"`
}
