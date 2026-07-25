package models

import "time"

// JWK represents a JSON Web Key stored in the database.
type JWK struct {
	Kid        string     `json:"kid" db:"kid"`
	KeyType    string     `json:"kty" db:"key_type"`
	Usage      string     `json:"use" db:"usage"`
	Algorithm  string     `json:"alg" db:"algorithm"`
	PrivateKey string     `json:"-" db:"private_key"` // encrypted PEM
	PublicKey  string     `json:"public_key" db:"public_key"`
	IsActive   bool       `json:"is_active" db:"is_active"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" db:"expires_at"`
}
