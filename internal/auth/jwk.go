package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	internalcrypto "github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	jwkEnvelopeKeyID         = "primary"
	jwkEnvelopePurpose       = "jwk-private-key"
	jwkRotationLockID  int64 = 0x4e59414a574b // "NYAJWK"
	defaultClockSkew         = 2 * time.Minute
)

// JWKManager manages encrypted RSA signing keys and their verification window.
type JWKManager struct {
	db                    *pgxpool.Pool
	keySize               int
	rotation              time.Duration
	verificationRetention time.Duration
	derivedKey            []byte
}

// NewJWKManager creates a manager. Configure must be called before private-key operations.
func NewJWKManager(db *pgxpool.Pool, keySize int, rotation time.Duration) *JWKManager {
	return &JWKManager{db: db, keySize: keySize, rotation: rotation, verificationRetention: 31*24*time.Hour + defaultClockSkew}
}

// Configure derives the JWK envelope key and sets how long old public keys remain available.
func (m *JWKManager) Configure(masterKey []byte, maximumTokenTTL time.Duration) error {
	if len(masterKey) != 32 {
		return fmt.Errorf("JWK master key must be exactly 32 bytes")
	}
	mac := hmac.New(sha256.New, masterKey)
	_, _ = mac.Write([]byte("nyauth/jwk-private-key/v1"))
	m.derivedKey = mac.Sum(nil)
	if maximumTokenTTL > 0 {
		m.verificationRetention = maximumTokenTTL + defaultClockSkew
	}
	return nil
}

// EnsureActiveKey creates or rotates the signing key while holding a database lock.
func (m *JWKManager) EnsureActiveKey(ctx context.Context) error {
	return m.rotate(ctx, false)
}

// GenerateKey forces creation of a new signing key.
func (m *JWKManager) GenerateKey(ctx context.Context) (*models.JWK, error) {
	if err := m.requireConfigured(); err != nil {
		return nil, err
	}
	var generated *models.JWK
	err := m.withRotationLock(ctx, func(tx pgx.Tx, now time.Time) error {
		if _, err := tx.Exec(ctx, `
			UPDATE jwk_keys SET status='verification',encrypted_private_key=NULL,verify_until=$2,updated_at=$1
			WHERE status='signing'
		`, now, now.Add(m.verificationRetention)); err != nil {
			return fmt.Errorf("moving signing key to verification: %w", err)
		}
		var err error
		generated, err = m.generateKey(ctx, tx, now)
		return err
	})
	return generated, err
}

// GetActiveKey returns the current signing key.
func (m *JWKManager) GetActiveKey(ctx context.Context) (*models.JWK, error) {
	jwk := &models.JWK{}
	err := m.db.QueryRow(ctx, `
		SELECT kid,key_type,usage,algorithm,encrypted_private_key,public_key,status,
		       signing_started_at,verify_until,created_at,updated_at
		FROM jwk_keys WHERE status='signing' ORDER BY signing_started_at DESC LIMIT 1
	`).Scan(&jwk.Kid, &jwk.KeyType, &jwk.Usage, &jwk.Algorithm, &jwk.EncryptedPrivateKey,
		&jwk.PublicKey, &jwk.Status, &jwk.SigningStartedAt, &jwk.VerifyUntil, &jwk.CreatedAt, &jwk.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("getting signing key: %w", err)
	}
	return jwk, nil
}

func (m *JWKManager) GetActivePublicKeyPEM(ctx context.Context) (string, error) {
	jwk, err := m.GetActiveKey(ctx)
	if err != nil {
		return "", err
	}
	return jwk.PublicKey, nil
}

// GetPrivateKey decrypts and parses the current signing key.
func (m *JWKManager) GetPrivateKey(ctx context.Context) (*rsa.PrivateKey, string, error) {
	if err := m.requireConfigured(); err != nil {
		return nil, "", err
	}
	jwk, err := m.GetActiveKey(ctx)
	if err != nil {
		return nil, "", err
	}
	if jwk.EncryptedPrivateKey == nil || *jwk.EncryptedPrivateKey == "" {
		return nil, "", errors.New("signing key has no encrypted private key")
	}
	plaintext, err := internalcrypto.DecryptEnvelope(
		map[string][]byte{jwkEnvelopeKeyID: m.derivedKey}, jwkEnvelopePurpose,
		*jwk.EncryptedPrivateKey, []byte(jwk.Kid),
	)
	if err != nil {
		return nil, "", fmt.Errorf("decrypting signing key: %w", err)
	}
	block, _ := pem.Decode(plaintext)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, "", errors.New("invalid RSA private key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parsing private key: %w", err)
	}
	return key, jwk.Kid, nil
}

// ListActivePublicKeys returns signing and non-expired verification keys.
func (m *JWKManager) ListActivePublicKeys(ctx context.Context) ([]models.JWK, error) {
	rows, err := m.db.Query(ctx, `
		SELECT kid,key_type,usage,algorithm,public_key,status,signing_started_at,
		       verify_until,created_at,updated_at
		FROM jwk_keys
		WHERE status='signing' OR (status='verification' AND verify_until > NOW())
		ORDER BY signing_started_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("querying verification keys: %w", err)
	}
	defer rows.Close()
	keys := make([]models.JWK, 0)
	for rows.Next() {
		var key models.JWK
		if err := rows.Scan(&key.Kid, &key.KeyType, &key.Usage, &key.Algorithm, &key.PublicKey,
			&key.Status, &key.SigningStartedAt, &key.VerifyUntil, &key.CreatedAt, &key.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning verification key: %w", err)
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating verification keys: %w", err)
	}
	return keys, nil
}

// RotateKeys rotates due signing keys and retires expired verification keys.
func (m *JWKManager) RotateKeys(ctx context.Context) error {
	return m.rotate(ctx, false)
}

func (m *JWKManager) rotate(ctx context.Context, force bool) error {
	if err := m.requireConfigured(); err != nil {
		return err
	}
	return m.withRotationLock(ctx, func(tx pgx.Tx, now time.Time) error {
		if _, err := tx.Exec(ctx, `UPDATE jwk_keys SET status='retired',encrypted_private_key=NULL,updated_at=$1 WHERE status='verification' AND verify_until <= $1`, now); err != nil {
			return fmt.Errorf("retiring verification keys: %w", err)
		}
		var kid string
		var started time.Time
		err := tx.QueryRow(ctx, `SELECT kid,signing_started_at FROM jwk_keys WHERE status='signing' FOR UPDATE`).Scan(&kid, &started)
		if err == nil && !force && now.Before(started.Add(m.rotation)) {
			return nil
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("locking signing key: %w", err)
		}
		if err == nil {
			if _, err := tx.Exec(ctx, `UPDATE jwk_keys SET status='verification',encrypted_private_key=NULL,verify_until=$2,updated_at=$1 WHERE kid=$3`, now, now.Add(m.verificationRetention), kid); err != nil {
				return fmt.Errorf("moving signing key to verification: %w", err)
			}
		}
		_, err = m.generateKey(ctx, tx, now)
		return err
	})
}

func (m *JWKManager) generateKey(ctx context.Context, tx pgx.Tx, now time.Time) (*models.JWK, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, m.keySize)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}
	if err := privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("validating RSA key: %w", err)
	}
	kid := uuid.NewString()
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}
	encrypted, err := internalcrypto.EncryptEnvelope(m.derivedKey, jwkEnvelopeKeyID, jwkEnvelopePurpose, privatePEM, []byte(kid))
	if err != nil {
		return nil, fmt.Errorf("encrypting private key: %w", err)
	}
	jwk := &models.JWK{
		Kid: kid, KeyType: "RSA", Usage: "sig", Algorithm: "RS256",
		EncryptedPrivateKey: &encrypted,
		PublicKey:           string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
		Status:              models.JWKStatusSigning, SigningStartedAt: now,
		VerifyUntil: now.Add(m.rotation + m.verificationRetention), CreatedAt: now, UpdatedAt: now,
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO jwk_keys
		(kid,key_type,usage,algorithm,encrypted_private_key,public_key,status,signing_started_at,verify_until,created_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, jwk.Kid, jwk.KeyType, jwk.Usage, jwk.Algorithm, jwk.EncryptedPrivateKey, jwk.PublicKey,
		jwk.Status, jwk.SigningStartedAt, jwk.VerifyUntil, jwk.CreatedAt, jwk.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("storing signing key: %w", err)
	}
	return jwk, nil
}

func (m *JWKManager) withRotationLock(ctx context.Context, fn func(pgx.Tx, time.Time) error) error {
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning JWK transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, jwkRotationLockID); err != nil {
		return fmt.Errorf("locking JWK rotation: %w", err)
	}
	if err := fn(tx, time.Now().UTC()); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing JWK transaction: %w", err)
	}
	return nil
}

func (m *JWKManager) requireConfigured() error {
	if len(m.derivedKey) != 32 {
		return errors.New("JWK encryption is not configured")
	}
	if m.keySize < 2048 || m.rotation <= 0 {
		return errors.New("invalid JWK key size or rotation interval")
	}
	return nil
}
