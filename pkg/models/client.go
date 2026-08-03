package models

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// OAuthClient represents a registered OAuth 2.0 client application.
type OAuthClient struct {
	ID                     string            `json:"id" db:"id"`
	SecretHash             *string           `json:"-" db:"secret_hash"`
	SecretHint             *string           `json:"secret_hint,omitempty" db:"secret_hint"`
	SecretVersion          int64             `json:"secret_version" db:"secret_version"`
	SecretRotatedAt        *time.Time        `json:"secret_rotated_at,omitempty" db:"secret_rotated_at"`
	SecretLastUsedAt       *time.Time        `json:"secret_last_used_at,omitempty" db:"secret_last_used_at"`
	Name                   string            `json:"name" db:"name"`
	HomepageURI            string            `json:"homepage_uri" db:"homepage_uri"`
	PrivacyPolicyURI       string            `json:"privacy_policy_uri" db:"privacy_policy_uri"`
	TermsOfServiceURI      string            `json:"terms_of_service_uri" db:"terms_of_service_uri"`
	CurrentLogoID          *string           `json:"current_logo_id,omitempty" db:"current_logo_id"`
	LogoURL                string            `json:"logo_url,omitempty" db:"-"`
	IdentityRevision       int64             `json:"identity_revision" db:"identity_revision"`
	AuthorizationRevision  int64             `json:"authorization_revision" db:"authorization_revision"`
	RedirectURIs           []string          `json:"redirect_uris" db:"redirect_uris"`
	PostLogoutRedirectURIs []string          `json:"post_logout_redirect_uris" db:"post_logout_redirect_uris"`
	Grants                 []string          `json:"grants" db:"grants"`
	Scopes                 []string          `json:"scopes" db:"scopes"`
	OptionalScopes         []string          `json:"optional_scopes" db:"optional_scopes"`
	AllowedClaims          []string          `json:"allowed_claims" db:"allowed_claims"`
	IsPublic               bool              `json:"is_public" db:"is_public"`
	AccessPolicy           string            `json:"access_policy" db:"access_policy"`
	OwnerID                *string           `json:"owner_id,omitempty" db:"owner_id"`
	OwnerUsername          *string           `json:"owner_username,omitempty" db:"-"`
	AuthorizationCount     int64             `json:"authorization_count" db:"-"`
	SuccessCount7d         int64             `json:"success_count_7d" db:"-"`
	FailureCount7d         int64             `json:"failure_count_7d" db:"-"`
	LastActivityAt         *time.Time        `json:"last_activity_at,omitempty" db:"-"`
	PublisherType          string            `json:"publisher_type" db:"publisher_type"`
	PublisherVerification  string            `json:"publisher_verification_status" db:"publisher_verification_status"`
	PublisherVerifiedAt    *time.Time        `json:"publisher_verified_at,omitempty" db:"publisher_verified_at"`
	PublisherVerifiedBy    *string           `json:"-" db:"publisher_verified_by"`
	Metadata               map[string]string `json:"metadata,omitempty" db:"metadata"`
	CreatedAt              time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time         `json:"updated_at" db:"updated_at"`
}

// Access policies restricting which users may complete an OAuth flow against a
// client. Machine flows (client_credentials) are not user-bound and are never
// restricted by these policies.
const (
	ClientAccessOpen       = "open"
	ClientAccessAdminsOnly = "admins_only"
	ClientAccessAllowlist  = "allowlist"
)

const (
	PublisherTypeSystemManaged  = "system_managed"
	PublisherTypeUserRegistered = "user_registered"

	PublisherVerificationNotApplicable = "not_applicable"
	PublisherVerificationUnverified    = "unverified"
	PublisherVerificationVerified      = "verified"
)

// ValidClientAccessPolicy reports whether the value is a known access policy.
func ValidClientAccessPolicy(policy string) bool {
	switch policy {
	case ClientAccessOpen, ClientAccessAdminsOnly, ClientAccessAllowlist:
		return true
	}
	return false
}

// CreateClientRequest is the payload to create a client.
type CreateClientRequest struct {
	Name                   string            `json:"name" validate:"required"`
	HomepageURI            string            `json:"homepage_uri,omitempty"`
	PrivacyPolicyURI       string            `json:"privacy_policy_uri,omitempty"`
	TermsOfServiceURI      string            `json:"terms_of_service_uri,omitempty"`
	RedirectURIs           []string          `json:"redirect_uris" validate:"required,min=1"`
	PostLogoutRedirectURIs []string          `json:"post_logout_redirect_uris,omitempty"`
	Grants                 []string          `json:"grants" validate:"required,min=1"`
	Scopes                 []string          `json:"scopes"`
	OptionalScopes         []string          `json:"optional_scopes,omitempty"`
	AllowedClaims          []string          `json:"allowed_claims,omitempty"`
	IsPublic               bool              `json:"is_public"`
	AccessPolicy           string            `json:"access_policy,omitempty"`
	OwnerID                *string           `json:"owner_id,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
}

// UpdateClientRequest is the payload to update a client.
type UpdateClientRequest struct {
	Name                   *string           `json:"name,omitempty"`
	HomepageURI            *string           `json:"homepage_uri,omitempty"`
	PrivacyPolicyURI       *string           `json:"privacy_policy_uri,omitempty"`
	TermsOfServiceURI      *string           `json:"terms_of_service_uri,omitempty"`
	RedirectURIs           []string          `json:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs []string          `json:"post_logout_redirect_uris,omitempty"`
	Grants                 []string          `json:"grants,omitempty"`
	Scopes                 []string          `json:"scopes,omitempty"`
	OptionalScopes         []string          `json:"optional_scopes,omitempty"`
	AllowedClaims          []string          `json:"allowed_claims,omitempty"`
	IsPublic               *bool             `json:"is_public,omitempty"`
	AccessPolicy           *string           `json:"access_policy,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
}

// ReplaceClientAccessUsersRequest replaces the allowlist for a client.
type ReplaceClientAccessUsersRequest struct {
	UserIDs []string `json:"user_ids"`
}

// ClientAccessUser is one allowlisted user shown in the admin UI.
type ClientAccessUser struct {
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

// UpdateClientOwnerRequest assigns a client to an active user. A null owner
// removes the current ownership assignment.
type UpdateClientOwnerRequest struct {
	OwnerID *string `json:"owner_id"`
}

func (r *UpdateClientOwnerRequest) UnmarshalJSON(data []byte) error {
	var payload struct {
		OwnerID json.RawMessage `json:"owner_id"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return err
	}
	if len(payload.OwnerID) == 0 {
		return fmt.Errorf("owner_id is required")
	}
	if bytes.Equal(bytes.TrimSpace(payload.OwnerID), []byte("null")) {
		r.OwnerID = nil
		return nil
	}
	var ownerID string
	if err := json.Unmarshal(payload.OwnerID, &ownerID); err != nil {
		return fmt.Errorf("owner_id must be a string or null")
	}
	r.OwnerID = &ownerID
	return nil
}

// CreateClientResponse includes the client secret in plaintext (only returned at creation).
type CreateClientResponse struct {
	OAuthClient
	Secret string `json:"secret,omitempty"`
}

// RotateClientSecretResponse contains the newly generated secret. The Secret
// field is returned exactly once and is never persisted in plaintext.
type RotateClientSecretResponse struct {
	ClientID        string    `json:"client_id"`
	Secret          string    `json:"secret"`
	SecretHint      string    `json:"secret_hint"`
	SecretVersion   int64     `json:"secret_version"`
	SecretRotatedAt time.Time `json:"secret_rotated_at"`
}

// Grant types
const (
	GrantAuthorizationCode = "authorization_code"
	GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
	GrantClientCredentials = "client_credentials"
	GrantRefreshToken      = "refresh_token"
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

// ValidOAuthScope reports whether scope is an RFC 6749 scope-token.
func ValidOAuthScope(scope string) bool {
	if scope == "" {
		return false
	}
	for index := 0; index < len(scope); index++ {
		value := scope[index]
		if value < 0x21 || value > 0x7e || value == 0x22 || value == 0x5c {
			return false
		}
	}
	return true
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

// HasPostLogoutRedirectURI checks whether a logout redirect URI is registered.
func (c *OAuthClient) HasPostLogoutRedirectURI(uri string) bool {
	for _, registered := range c.PostLogoutRedirectURIs {
		if registered == uri {
			return true
		}
	}
	return false
}
