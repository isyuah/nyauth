package models

import (
	"time"

	"github.com/google/uuid"
)

// ExternalProvider represents an external OAuth/OIDC provider configuration.
type ExternalProvider struct {
	ID              uuid.UUID         `json:"id" db:"id"`
	Name            string            `json:"name" db:"name"`
	Type            string            `json:"type" db:"type"` // github, google, generic
	ClientID        string            `json:"client_id" db:"client_id"`
	ClientSecret    string            `json:"-" db:"client_secret"` // encrypted
	Scopes          []string          `json:"scopes" db:"scopes"`
	DiscoveryURL    *string           `json:"discovery_url,omitempty" db:"discovery_url"`
	AuthorizationURL *string          `json:"authorization_url,omitempty" db:"authorization_url"`
	TokenURL        *string           `json:"token_url,omitempty" db:"token_url"`
	UserinfoURL     *string           `json:"userinfo_url,omitempty" db:"userinfo_url"`
	Enabled         bool              `json:"enabled" db:"enabled"`
	Metadata        map[string]string `json:"metadata,omitempty" db:"metadata"`
	CreatedAt       time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at" db:"updated_at"`
}

// CreateProviderRequest is the payload to create an external provider.
type CreateProviderRequest struct {
	Name             string   `json:"name" validate:"required"`
	Type             string   `json:"type" validate:"required,oneof=github google generic"`
	ClientID         string   `json:"client_id" validate:"required"`
	ClientSecret     string   `json:"client_secret" validate:"required"`
	Scopes           []string `json:"scopes"`
	DiscoveryURL     string   `json:"discovery_url,omitempty"`
	AuthorizationURL string   `json:"authorization_url,omitempty"`
	TokenURL         string   `json:"token_url,omitempty"`
	UserinfoURL      string   `json:"userinfo_url,omitempty"`
}

// UpdateProviderRequest is the payload to update a provider.
type UpdateProviderRequest struct {
	ClientID         *string  `json:"client_id,omitempty"`
	ClientSecret     *string  `json:"client_secret,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	DiscoveryURL     *string  `json:"discovery_url,omitempty"`
	AuthorizationURL *string  `json:"authorization_url,omitempty"`
	TokenURL         *string  `json:"token_url,omitempty"`
	UserinfoURL      *string  `json:"userinfo_url,omitempty"`
	Enabled          *bool    `json:"enabled,omitempty"`
}
