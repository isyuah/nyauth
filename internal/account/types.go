package account

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

type Action string

const (
	ActionPasswordReset     Action = "password_reset"
	ActionEmailVerification Action = "email_verification"
	ActionEmailChange       Action = "email_change"
)

const DefaultReauthenticationTTL = 10 * time.Minute

const (
	MessagePasswordReset      = "account.password_reset"
	MessagePasswordChanged    = "account.password_changed"
	MessageEmailVerification  = "account.email_verification"
	MessageEmailChangeConfirm = "account.email_change_confirm"
	MessageEmailChangedOld    = "account.email_changed_old"
	MessageEmailChangedNew    = "account.email_changed_new"
	MessageRoleChanged        = "security.role_changed"
	MessageStatusChanged      = "security.status_changed"
	MessagePasswordConfigured = "security.password_configured"
	MessagePasswordResetAdmin = "security.password_reset_admin"
	MessageIdentityBound      = "security.identity_bound"
	MessageIdentityUnbound    = "security.identity_unbound"
)

var (
	ErrInvalidInput                 = errors.New("invalid account request")
	ErrInvalidActionToken           = errors.New("invalid or expired account action token")
	ErrEmailInUse                   = errors.New("email address is already in use")
	ErrRecentAuthenticationRequired = errors.New("recent authentication is required")
	ErrAccountUnavailable           = errors.New("account is unavailable")
	ErrOutboxLeaseLost              = errors.New("email outbox lease is no longer owned by this worker")
)

type RequestMetadata struct {
	IPAddress string
	UserAgent string
}

// SecurityNotice contains only the small set of non-secret values permitted in
// a security notification template.
type SecurityNotice struct {
	MessageType string
	Role        string
	Status      string
	Provider    string
}

type SecurityNotificationBuilder interface {
	BuildSecurityNotification(*models.User, SecurityNotice) (*OutboxEmail, error)
}

type ActionToken struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	Action            Action
	TokenHash         []byte
	PayloadCiphertext string
	RequestedIP       *string
	UserAgent         *string
	ExpiresAt         time.Time
	ConsumedAt        *time.Time
	RevokedAt         *time.Time
	CreatedAt         time.Time
}

type EmailMessage struct {
	To       string `json:"to"`
	Subject  string `json:"subject"`
	TextBody string `json:"text_body"`
	HTMLBody string `json:"html_body,omitempty"`
}

type OutboxEmail struct {
	ID               uuid.UUID
	UserID           *uuid.UUID
	MessageType      string
	RecipientHash    []byte
	EncryptedMessage string
	Status           string
	AttemptCount     int
	AvailableAt      time.Time
	LockedAt         *time.Time
	LockedBy         *string
	ExpiresAt        time.Time
	CreatedAt        time.Time
}

// PreparedActionEmail contains encrypted account-action artifacts that have
// completed all CPU-only preparation and can be committed by a caller's
// database transaction.
type PreparedActionEmail struct {
	Action *ActionToken
	Email  *OutboxEmail
}

type actionClaims struct {
	Email         string `json:"email"`
	PreviousEmail string `json:"previous_email,omitempty"`
}
