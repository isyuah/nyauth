package models

import "time"

// JWKStatus describes a signing key's lifecycle.
type JWKStatus string

const (
	JWKStatusSigning      JWKStatus = "signing"
	JWKStatusVerification JWKStatus = "verification"
	JWKStatusRetired      JWKStatus = "retired"
)

// JWK represents an encrypted JSON Web Key stored in the database.
type JWK struct {
	Kid                 string    `json:"kid" db:"kid"`
	KeyType             string    `json:"kty" db:"key_type"`
	Usage               string    `json:"use" db:"usage"`
	Algorithm           string    `json:"alg" db:"algorithm"`
	EncryptedPrivateKey *string   `json:"-" db:"encrypted_private_key"`
	PublicKey           string    `json:"public_key" db:"public_key"`
	Status              JWKStatus `json:"status" db:"status"`
	SigningStartedAt    time.Time `json:"signing_started_at" db:"signing_started_at"`
	VerifyUntil         time.Time `json:"verify_until" db:"verify_until"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time `json:"updated_at" db:"updated_at"`
}
