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
	ID           uuid.UUID         `json:"id" db:"id"`
	Username     string            `json:"username" db:"username"`
	Email        *string           `json:"email,omitempty" db:"email"`
	PasswordHash string            `json:"-" db:"password_hash"`
	DisplayName  *string           `json:"display_name,omitempty" db:"display_name"`
	AvatarURL    *string           `json:"avatar_url,omitempty" db:"avatar_url"`
	Status       UserStatus        `json:"status" db:"status"`
	Role         string            `json:"role" db:"role"`
	LastLoginAt  *time.Time        `json:"last_login_at,omitempty" db:"last_login_at"`
	LastLoginIP  *string           `json:"last_login_ip,omitempty" db:"last_login_ip"`
	Metadata     map[string]string `json:"metadata,omitempty" db:"metadata"`
	CreatedAt    time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at" db:"updated_at"`
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
	Email       *string           `json:"email,omitempty"`
	DisplayName *string           `json:"display_name,omitempty"`
	AvatarURL   *string           `json:"avatar_url,omitempty"`
	Status      *UserStatus       `json:"status,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// LoginRequest is the payload for username/password login.
type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// LoginResponse is the response after a successful login.
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}
