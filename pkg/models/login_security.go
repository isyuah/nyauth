package models

import (
	"time"

	"github.com/google/uuid"
)

// LoginHistoryEntry is the user-facing, deliberately restricted projection of
// an authentication audit event. Arbitrary audit details are never exposed.
type LoginHistoryEntry struct {
	ID                   uuid.UUID `json:"id"`
	Result               string    `json:"result"`
	AuthenticationMethod string    `json:"authentication_method"`
	SecondFactor         string    `json:"second_factor,omitempty"`
	Provider             string    `json:"provider,omitempty"`
	IPAddress            string    `json:"ip_address,omitempty"`
	UserAgent            string    `json:"user_agent,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
}

// TrustedDevice is a long-lived MFA trust record. It never contains the
// bearer secret or its hash.
type TrustedDevice struct {
	ID         uuid.UUID `json:"id"`
	IPAddress  string    `json:"ip_address,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Current    bool      `json:"current"`
}
