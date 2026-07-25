package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/pkg/models"
)

// JWKManager manages JSON Web Keys.
type JWKManager struct {
	db       *pgxpool.Pool
	keySize  int
	rotation time.Duration
}

// NewJWKManager creates a new JWK manager.
func NewJWKManager(db *pgxpool.Pool, keySize int, rotation time.Duration) *JWKManager {
	return &JWKManager{
		db:       db,
		keySize:  keySize,
		rotation: rotation,
	}
}

// EnsureActiveKey makes sure there's at least one active signing key.
// If none exist, generates a new one.
func (m *JWKManager) EnsureActiveKey(ctx context.Context) error {
	var count int
	err := m.db.QueryRow(ctx, `SELECT COUNT(*) FROM jwk_keys WHERE is_active = TRUE`).Scan(&count)
	if err != nil {
		return fmt.Errorf("counting active keys: %w", err)
	}

	if count == 0 {
		_, err := m.GenerateKey(ctx)
		return err
	}
	return nil
}

// GenerateKey generates a new RSA key pair and stores it.
func (m *JWKManager) GenerateKey(ctx context.Context) (*models.JWK, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, m.keySize)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	})

	// Actually need to marshal as PKIX for public key
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}
	pubPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	kid := uuid.New().String()[:8]
	now := time.Now()
	expiresAt := now.Add(m.rotation)

	jwk := &models.JWK{
		Kid:        kid,
		KeyType:    "RSA",
		Usage:      "sig",
		Algorithm:  "RS256",
		PrivateKey: string(privPEM),
		PublicKey:  string(pubPEM),
		IsActive:   true,
		CreatedAt:  now,
		ExpiresAt:  &expiresAt,
	}

	_, err = m.db.Exec(ctx, `
		INSERT INTO jwk_keys (kid, key_type, usage, algorithm, private_key, public_key, is_active, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, jwk.Kid, jwk.KeyType, jwk.Usage, jwk.Algorithm, jwk.PrivateKey, jwk.PublicKey, jwk.IsActive, jwk.CreatedAt, jwk.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("storing key: %w", err)
	}

	return jwk, nil
}

// GetActiveKey returns the most recently created active key.
func (m *JWKManager) GetActiveKey(ctx context.Context) (*models.JWK, error) {
	jwk := &models.JWK{}
	err := m.db.QueryRow(ctx, `
		SELECT kid, key_type, usage, algorithm, private_key, public_key, is_active, created_at, expires_at
		FROM jwk_keys WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 1
	`).Scan(&jwk.Kid, &jwk.KeyType, &jwk.Usage, &jwk.Algorithm, &jwk.PrivateKey, &jwk.PublicKey, &jwk.IsActive, &jwk.CreatedAt, &jwk.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("getting active key: %w", err)
	}
	return jwk, nil
}

// GetActivePublicKeyPEM returns the PEM-encoded public key for the active signing key.
func (m *JWKManager) GetActivePublicKeyPEM(ctx context.Context) (string, error) {
	jwk, err := m.GetActiveKey(ctx)
	if err != nil {
		return "", err
	}
	return jwk.PublicKey, nil
}

// GetPrivateKey parses and returns the RSA private key for the active signing key.
func (m *JWKManager) GetPrivateKey(ctx context.Context) (*rsa.PrivateKey, string, error) {
	jwk, err := m.GetActiveKey(ctx)
	if err != nil {
		return nil, "", err
	}

	block, _ := pem.Decode([]byte(jwk.PrivateKey))
	if block == nil {
		return nil, "", fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parsing private key: %w", err)
	}

	return key, jwk.Kid, nil
}

// ListActivePublicKeys returns all active public keys (for JWKS endpoint).
func (m *JWKManager) ListActivePublicKeys(ctx context.Context) ([]models.JWK, error) {
	rows, err := m.db.Query(ctx, `
		SELECT kid, key_type, usage, algorithm, public_key, is_active, created_at
		FROM jwk_keys WHERE is_active = TRUE ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []models.JWK
	for rows.Next() {
		var k models.JWK
		if err := rows.Scan(&k.Kid, &k.KeyType, &k.Usage, &k.Algorithm, &k.PublicKey, &k.IsActive, &k.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// RotateKeys deactivates expired keys and generates a new one if needed.
func (m *JWKManager) RotateKeys(ctx context.Context) error {
	// Deactivate expired keys
	_, err := m.db.Exec(ctx, `
		UPDATE jwk_keys SET is_active = FALSE
		WHERE is_active = TRUE AND expires_at IS NOT NULL AND expires_at < NOW()
	`)
	if err != nil {
		return fmt.Errorf("deactivating expired keys: %w", err)
	}

	// Ensure at least one active key
	return m.EnsureActiveKey(ctx)
}
