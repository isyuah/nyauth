package trusteddevice

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	internalcrypto "github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

const MaxActivePerUser = 20

var (
	ErrNotFound     = errors.New("trusted device not found")
	ErrInvalidToken = errors.New("invalid trusted device token")
)

type Store struct{ db *pgxpool.Pool }

func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

type Token struct {
	ID     uuid.UUID
	Secret string
}

func NewToken() (Token, error) {
	secret, err := internalcrypto.GenerateRandomString(32)
	if err != nil {
		return Token{}, fmt.Errorf("generating trusted device secret: %w", err)
	}
	return Token{ID: uuid.New(), Secret: secret}, nil
}

func ParseToken(value string) (Token, error) {
	idText, secret, ok := strings.Cut(strings.TrimSpace(value), ".")
	if !ok || idText == "" || secret == "" || strings.Contains(secret, ".") {
		return Token{}, ErrInvalidToken
	}
	id, err := uuid.Parse(idText)
	if err != nil {
		return Token{}, ErrInvalidToken
	}
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != 32 {
		return Token{}, ErrInvalidToken
	}
	return Token{ID: id, Secret: secret}, nil
}

func (t Token) String() string { return t.ID.String() + "." + t.Secret }

func tokenHash(secret string) [32]byte { return sha256.Sum256([]byte(secret)) }

func (s *Store) Issue(
	ctx context.Context,
	user *models.User,
	ip, userAgent string,
	ttl time.Duration,
	replaceID uuid.UUID,
	mutation audit.MutationAudit,
) (*models.TrustedDevice, Token, error) {
	if s == nil || s.db == nil || user == nil || user.ID == uuid.Nil || ttl <= 0 {
		return nil, Token{}, fmt.Errorf("valid trusted device issuance parameters are required")
	}
	if err := mutation.ValidateEvent(models.AuditTrustedDeviceCreated); err != nil {
		return nil, Token{}, fmt.Errorf("validating trusted device audit: %w", err)
	}
	token, err := NewToken()
	if err != nil {
		return nil, Token{}, err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	hash := tokenHash(token.Secret)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, Token{}, fmt.Errorf("starting trusted device issuance: %w", err)
	}
	defer tx.Rollback(ctx)
	if replaceID != uuid.Nil {
		if _, err := tx.Exec(ctx, `
			UPDATE user_trusted_devices SET revoked_at=$3
			WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL
		`, replaceID, user.ID, now); err != nil {
			return nil, Token{}, fmt.Errorf("replacing trusted device: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_trusted_devices (
			id,user_id,token_hash,auth_version,session_version,initial_ip,last_used_ip,
			user_agent,created_at,last_used_at,expires_at
		) VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($6,''),NULLIF($7,''),$8,$8,$9)
	`, token.ID, user.ID, hash[:], user.AuthVersion, user.SessionVersion, ip, userAgent, now, expiresAt); err != nil {
		return nil, Token{}, fmt.Errorf("inserting trusted device: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		WITH overflow AS (
			SELECT id FROM user_trusted_devices
			WHERE user_id=$1 AND auth_version=$4 AND session_version=$5
			  AND revoked_at IS NULL AND expires_at>$2
			ORDER BY last_used_at DESC,id DESC
			OFFSET $3
		)
		UPDATE user_trusted_devices AS device SET revoked_at=$2
		FROM overflow WHERE device.id=overflow.id
	`, user.ID, now, MaxActivePerUser, user.AuthVersion, user.SessionVersion); err != nil {
		return nil, Token{}, fmt.Errorf("enforcing trusted device limit: %w", err)
	}
	mutation = mutation.WithTarget("trusted_device", token.ID.String()).WithDetails(map[string]any{
		"expires_at": expiresAt,
	})
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return nil, Token{}, fmt.Errorf("auditing trusted device issuance: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, Token{}, fmt.Errorf("committing trusted device issuance: %w", err)
	}
	return &models.TrustedDevice{
		ID: token.ID, IPAddress: ip, UserAgent: userAgent,
		CreatedAt: now, LastUsedAt: now, ExpiresAt: expiresAt, Current: true,
	}, token, nil
}

// ValidateAndTouch verifies a browser-held bearer token against the current
// account security generations. A shorter runtime TTL takes effect
// immediately; extending it never revives or prolongs an existing token.
func (s *Store) ValidateAndTouch(
	ctx context.Context,
	token Token,
	user *models.User,
	maxTTL time.Duration,
	ip, userAgent string,
	now time.Time,
) (bool, error) {
	if s == nil || s.db == nil || token.ID == uuid.Nil || user == nil || maxTTL <= 0 {
		return false, ErrInvalidToken
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("starting trusted device validation: %w", err)
	}
	defer tx.Rollback(ctx)
	var storedHash []byte
	var userID uuid.UUID
	var authVersion, sessionVersion int64
	var createdAt, expiresAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT user_id,token_hash,auth_version,session_version,created_at,expires_at
		FROM user_trusted_devices
		WHERE id=$1 AND revoked_at IS NULL
		FOR UPDATE
	`, token.ID).Scan(&userID, &storedHash, &authVersion, &sessionVersion, &createdAt, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("loading trusted device: %w", err)
	}
	presentedHash := tokenHash(token.Secret)
	effectiveExpiry := expiresAt
	if policyExpiry := createdAt.Add(maxTTL); policyExpiry.Before(effectiveExpiry) {
		effectiveExpiry = policyExpiry
	}
	valid := userID == user.ID && authVersion == user.AuthVersion && sessionVersion == user.SessionVersion &&
		now.UTC().Before(effectiveExpiry) && len(storedHash) == len(presentedHash) &&
		subtle.ConstantTimeCompare(storedHash, presentedHash[:]) == 1
	if !valid {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE user_trusted_devices
		SET last_used_at=$2,last_used_ip=NULLIF($3,''),user_agent=NULLIF($4,'')
		WHERE id=$1
	`, token.ID, now.UTC(), ip, userAgent); err != nil {
		return false, fmt.Errorf("touching trusted device: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("committing trusted device use: %w", err)
	}
	return true, nil
}

func (s *Store) List(ctx context.Context, user *models.User, maxTTL time.Duration, currentID uuid.UUID) ([]models.TrustedDevice, error) {
	if maxTTL <= 0 {
		return []models.TrustedDevice{}, nil
	}
	if user == nil || user.ID == uuid.Nil {
		return nil, fmt.Errorf("valid trusted device owner is required")
	}
	now := time.Now().UTC()
	rows, err := s.db.Query(ctx, `
		SELECT id,COALESCE(last_used_ip,''),COALESCE(user_agent,''),created_at,last_used_at,
		       LEAST(expires_at,created_at+make_interval(secs=>$2))
		FROM user_trusted_devices
		WHERE user_id=$1 AND auth_version=$3 AND session_version=$4 AND revoked_at IS NULL
		  AND LEAST(expires_at,created_at+make_interval(secs=>$2))>$5
		ORDER BY last_used_at DESC,id DESC
	`, user.ID, maxTTL.Seconds(), user.AuthVersion, user.SessionVersion, now)
	if err != nil {
		return nil, fmt.Errorf("listing trusted devices: %w", err)
	}
	defer rows.Close()
	result := make([]models.TrustedDevice, 0)
	for rows.Next() {
		var item models.TrustedDevice
		if err := rows.Scan(&item.ID, &item.IPAddress, &item.UserAgent, &item.CreatedAt, &item.LastUsedAt, &item.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scanning trusted device: %w", err)
		}
		item.Current = item.ID == currentID
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating trusted devices: %w", err)
	}
	return result, nil
}

func (s *Store) Revoke(ctx context.Context, userID, id uuid.UUID, mutation audit.MutationAudit) error {
	if err := mutation.ValidateEvent(models.AuditTrustedDeviceRevoked); err != nil {
		return err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting trusted device revocation: %w", err)
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
		UPDATE user_trusted_devices SET revoked_at=NOW()
		WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL
	`, id, userID)
	if err != nil {
		return fmt.Errorf("revoking trusted device: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("trusted_device", id.String())); err != nil {
		return fmt.Errorf("auditing trusted device revocation: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *Store) RevokeOthers(ctx context.Context, userID, keepID uuid.UUID, mutation audit.MutationAudit) (int64, error) {
	if err := mutation.ValidateEvent(models.AuditTrustedDeviceOthersRevoked); err != nil {
		return 0, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("starting trusted device revocation: %w", err)
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
		UPDATE user_trusted_devices SET revoked_at=NOW()
		WHERE user_id=$1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR id<>$2)
	`, userID, nullableUUID(keepID))
	if err != nil {
		return 0, fmt.Errorf("revoking other trusted devices: %w", err)
	}
	count := tag.RowsAffected()
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("user", userID.String()).WithDetails(map[string]any{"revoked_count": count})); err != nil {
		return 0, fmt.Errorf("auditing trusted device revocation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return count, nil
}

func nullableUUID(value uuid.UUID) any {
	if value == uuid.Nil {
		return nil
	}
	return value
}
