// Package invite stores invitation codes for invite-only self-registration.
package invite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

// ErrInviteInvalid covers every unusable-code case (unknown, expired,
// exhausted, revoked) so responses stay indistinguishable.
var ErrInviteInvalid = errors.New("invite code is invalid or no longer usable")

const inviteSelectCols = `
	invite.id,invite.code_hash,invite.created_by,invite.note,invite.max_uses,
	COUNT(registration.id) FILTER (WHERE registration.status='completed')::int AS used_count,
	COUNT(registration.id) FILTER (WHERE registration.status='pending')::int AS reserved_count,
	invite.expires_at,invite.revoked_at,invite.created_at
`

// GenerateCode returns a new plaintext invite code.
func GenerateCode() (string, error) {
	return crypto.GenerateRandomString(24)
}

// HashCode derives the stored lookup hash for a plaintext code.
func HashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

type Store struct{ db *pgxpool.Pool }

func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// Create persists a new invite inside the mutation-audit transaction.
func (s *Store) Create(ctx context.Context, inv *models.Invite, mutation audit.MutationAudit) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting invite creation: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO invites (id, code_hash, created_by, note, max_uses, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, inv.ID, inv.CodeHash, inv.CreatedBy, inv.Note, inv.MaxUses, inv.ExpiresAt, inv.CreatedAt); err != nil {
		return fmt.Errorf("creating invite: %w", err)
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("invite", inv.ID.String())); err != nil {
		return fmt.Errorf("auditing invite creation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing invite creation: %w", err)
	}
	return nil
}

// List returns the most recent invites.
func (s *Store) List(ctx context.Context, limit int) ([]models.Invite, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.Query(ctx, `
		SELECT `+inviteSelectCols+`
		FROM invites AS invite
		LEFT JOIN self_registrations AS registration ON registration.invite_id=invite.id
		GROUP BY invite.id
		ORDER BY invite.created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("listing invites: %w", err)
	}
	defer rows.Close()
	invites := make([]models.Invite, 0)
	for rows.Next() {
		var inv models.Invite
		if err := rows.Scan(&inv.ID, &inv.CodeHash, &inv.CreatedBy, &inv.Note, &inv.MaxUses,
			&inv.UsedCount, &inv.ReservedCount, &inv.ExpiresAt, &inv.RevokedAt, &inv.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning invite: %w", err)
		}
		invites = append(invites, inv)
	}
	return invites, rows.Err()
}

// Revoke marks an invite unusable. Revoking an already-revoked invite is a
// no-op so the operation stays idempotent.
func (s *Store) Revoke(ctx context.Context, id uuid.UUID, mutation audit.MutationAudit) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting invite revocation: %w", err)
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `UPDATE invites SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("revoking invite: %w", err)
	}
	if result.RowsAffected() == 0 {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM invites WHERE id = $1)`, id).Scan(&exists); err != nil {
			return fmt.Errorf("checking invite: %w", err)
		}
		if !exists {
			return pgx.ErrNoRows
		}
		return nil
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("invite", id.String())); err != nil {
		return fmt.Errorf("auditing invite revocation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing invite revocation: %w", err)
	}
	return nil
}
