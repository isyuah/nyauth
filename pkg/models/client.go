package models

import (
	"strings"
	"time"
)

// OAuthClient represents a registered OAuth 2.0 client application.
type OAuthClient struct {
	ID           string            `json:"id" db:"id"`
	SecretHash   *string           `json:"-" db:"secret_hash"`
	Name         string            `json:"name" db:"name"`
	RedirectURIs []string          `json:"redirect_uris" db:"redirect_uris"`
	Grants       []string          `json:"grants" db:"grants"`
	Scopes       []string          `json:"scopes" db:"scopes"`
	IsPublic     bool              `json:"is_public" db:"is_public"`
	Metadata     map[string]string `json:"metadata,omitempty" db:"metadata"`
	CreatedAt    time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at" db:"updated_at"`
}

// CreateClientRequest is the payload to create a client.
type CreateClientRequest struct {
	Name         string            `json:"name" validate:"required"`
	RedirectURIs []string          `json:"redirect_uris" validate:"required,min=1"`
	Grants       []string          `json:"grants" validate:"required,min=1"`
	Scopes       []string          `json:"scopes"`
	IsPublic     bool              `json:"is_public"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// UpdateClientRequest is the payload to update a client.
type UpdateClientRequest struct {
	Name         *string           `json:"name,omitempty"`
	RedirectURIs []string          `json:"redirect_uris,omitempty"`
	Grants       []string          `json:"grants,omitempty"`
	Scopes       []string          `json:"scopes,omitempty"`
	IsPublic     *bool             `json:"is_public,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// CreateClientResponse includes the client secret in plaintext (only returned at creation).
type CreateClientResponse struct {
	OAuthClient
	Secret string `json:"secret,omitempty"`
}

// Grant types
const (
	GrantAuthorizationCode = "authorization_code"
	GrantClientCredentials = "client_credentials"
	GrantRefreshToken      = "refresh_token"
	GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
)

// HasGrant checks if a client supports a specific grant type.
func (c *OAuthClient) HasGrant(grant string) bool {
	for _, g := range c.Grants {
		if strings.EqualFold(g, grant) {
			return true
		}
	}
	return false
}

// HasScope checks if a client has a specific scope.
func (c *OAuthClient) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if strings.EqualFold(s, scope) {
			return true
		}
	}
	return false
}

// HasRedirectURI checks if a client has a specific redirect URI.
func (c *OAuthClient) HasRedirectURI(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}
