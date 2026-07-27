package models

import (
	"time"

	"github.com/google/uuid"
)

// UserStatus represents the status of a user account.
type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusPending   UserStatus = "pending"
)

// User represents a registered user.
type User struct {
	ID                  uuid.UUID         `json:"id" db:"id"`
	Username            string            `json:"username" db:"username"`
	Email               *string           `json:"email,omitempty" db:"email"`
	EmailVerifiedAt     *time.Time        `json:"email_verified_at,omitempty" db:"email_verified_at"`
	PasswordHash        *string           `json:"-" db:"password_hash"`
	PasswordChangedAt   *time.Time        `json:"-" db:"password_changed_at"`
	DisplayName         *string           `json:"display_name,omitempty" db:"display_name"`
	AvatarURL           *string           `json:"avatar_url,omitempty" db:"avatar_url"`
	Status              UserStatus        `json:"status" db:"status"`
	Role                string            `json:"role" db:"role"`
	AuthVersion         int64             `json:"-" db:"auth_version"`
	SessionVersion      int64             `json:"-" db:"session_version"`
	MustChangePassword  bool              `json:"must_change_password" db:"must_change_password"`
	LastAuthenticatedAt *time.Time        `json:"-" db:"last_authenticated_at"`
	LastLoginAt         *time.Time        `json:"last_login_at,omitempty" db:"last_login_at"`
	LastLoginIP         *string           `json:"last_login_ip,omitempty" db:"last_login_ip"`
	Metadata            map[string]string `json:"metadata,omitempty" db:"metadata"`
	CreatedAt           time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at" db:"updated_at"`
}

// CreateUserRequest is the payload to create a user.
type CreateUserRequest struct {
	Username    string            `json:"username" validate:"required,min=3,max=64"`
	Email       string            `json:"email,omitempty" validate:"omitempty,email"`
	Password    string            `json:"password" validate:"required,min=8"`
	DisplayName string            `json:"display_name,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// UpdateUserRequest is the payload to update a user.
type UpdateUserRequest struct {
	Email       *string `json:"email,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
}

// AdminUpdateUserRequest contains fields that only administrators may change.
type AdminUpdateUserRequest struct {
	Email       *string           `json:"email,omitempty"`
	DisplayName *string           `json:"display_name,omitempty"`
	AvatarURL   *string           `json:"avatar_url,omitempty"`
	Status      *UserStatus       `json:"status,omitempty"`
	Role        *string           `json:"role,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// LoginRequest is the payload for username/password login.
type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
	ReturnTo string `json:"return_to,omitempty"`
}

type MFARequiredResponse struct {
	Status    string    `json:"status"`
	Purpose   string    `json:"purpose"`
	Username  string    `json:"username"`
	Methods   []string  `json:"methods"`
	CSRFToken string    `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ChangePasswordRequest changes the password for the current user.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// SessionResponse is returned after login and when loading the browser session.
type SessionResponse struct {
	User               *User      `json:"user"`
	CSRFToken          string     `json:"csrf_token"`
	MustChangePassword bool       `json:"must_change_password"`
	HasPassword        bool       `json:"has_password"`
	EmailVerified      bool       `json:"email_verified"`
	AuthenticatedAt    *time.Time `json:"authenticated_at"`
}
