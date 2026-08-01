package models

import (
	"time"

	"github.com/google/uuid"
)

// OAuthAuthorization is a user's active grant to an OAuth client.
type OAuthAuthorization struct {
	ID                           uuid.UUID  `json:"id" db:"id"`
	UserID                       uuid.UUID  `json:"-" db:"user_id"`
	ClientID                     string     `json:"client_id" db:"client_id"`
	ClientName                   string     `json:"client_name" db:"client_name"`
	ClientNameAtGrant            string     `json:"client_name_at_grant" db:"client_name_snapshot"`
	LogoURL                      string     `json:"logo_url,omitempty" db:"-"`
	HomepageURI                  string     `json:"homepage_uri,omitempty" db:"homepage_uri"`
	PrivacyPolicyURI             string     `json:"privacy_policy_uri,omitempty" db:"privacy_policy_uri"`
	TermsOfServiceURI            string     `json:"terms_of_service_uri,omitempty" db:"terms_of_service_uri"`
	HomepageURIAtGrant           string     `json:"homepage_uri_at_grant,omitempty" db:"homepage_uri_snapshot"`
	PrivacyPolicyURIAtGrant      string     `json:"privacy_policy_uri_at_grant,omitempty" db:"privacy_policy_uri_snapshot"`
	TermsOfServiceURIAtGrant     string     `json:"terms_of_service_uri_at_grant,omitempty" db:"terms_of_service_uri_snapshot"`
	ClientIdentityRevision       int64      `json:"client_identity_revision" db:"client_identity_revision"`
	CurrentIdentityRevision      int64      `json:"current_identity_revision" db:"current_identity_revision"`
	ClientAuthorizationRevision  int64      `json:"client_authorization_revision" db:"client_authorization_revision"`
	CurrentAuthorizationRevision int64      `json:"current_authorization_revision" db:"current_authorization_revision"`
	ApplicationChanged           bool       `json:"application_changed" db:"-"`
	ReauthorizationRequired      bool       `json:"reauthorization_required" db:"-"`
	Scopes                       []string   `json:"scopes" db:"scopes"`
	AllowedClaims                []string   `json:"allowed_claims" db:"allowed_claims"`
	GrantedAt                    time.Time  `json:"granted_at" db:"granted_at"`
	LastUsedAt                   *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	RevokedAt                    *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	CreatedAt                    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt                    time.Time  `json:"updated_at" db:"updated_at"`
}
