package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/pkg/models"
)

type Store struct{ db *pgxpool.Pool }

const usersEmailUniqueConstraint = "users_email_unique"

func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

const identityCols = `id,user_id,provider,external_id,external_username,external_email,metadata,created_at,updated_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanIdentity(row rowScanner) (*models.Identity, error) {
	i := &models.Identity{}
	if err := row.Scan(&i.ID, &i.UserID, &i.Provider, &i.ExternalID, &i.ExternalUsername, &i.ExternalEmail, &i.Metadata, &i.CreatedAt, &i.UpdatedAt); err != nil {
		return nil, err
	}
	return i, nil
}

func (s *Store) FindByExternal(ctx context.Context, provider, externalID string) (*models.Identity, error) {
	i, err := scanIdentity(s.db.QueryRow(ctx, `SELECT `+identityCols+` FROM identities WHERE provider=$1 AND external_id=$2`, provider, externalID))
	if err != nil {
		return nil, fmt.Errorf("finding identity: %w", err)
	}
	return i, nil
}
func (s *Store) Create(ctx context.Context, i *models.Identity) error {
	_, err := s.db.Exec(ctx, `INSERT INTO identities (id,user_id,provider,external_id,external_username,external_email,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7)`, i.ID, i.UserID, i.Provider, i.ExternalID, i.ExternalUsername, i.ExternalEmail, i.Metadata)
	if err != nil {
		return fmt.Errorf("creating identity: %w", err)
	}
	return nil
}

// CreateUserAndIdentity makes first-time external account creation atomic.
func (s *Store) CreateUserAndIdentity(ctx context.Context, u *models.User, i *models.Identity) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO users (id,username,email,password_hash,display_name,avatar_url,status,role,auth_version,must_change_password,metadata) VALUES ($1,$2,$3,NULL,$4,$5,$6,$7,$8,FALSE,$9)`, u.ID, u.Username, u.Email, u.DisplayName, u.AvatarURL, u.Status, u.Role, u.AuthVersion, u.Metadata)
	if err != nil {
		return fmt.Errorf("creating external user: %w", err)
	}
	i.UserID = u.ID
	_, err = tx.Exec(ctx, `INSERT INTO identities (id,user_id,provider,external_id,external_username,external_email,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7)`, i.ID, i.UserID, i.Provider, i.ExternalID, i.ExternalUsername, i.ExternalEmail, i.Metadata)
	if err != nil {
		return fmt.Errorf("binding external identity: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *Store) ListByUser(ctx context.Context, userID uuid.UUID) ([]models.Identity, error) {
	rows, err := s.db.Query(ctx, `SELECT `+identityCols+` FROM identities WHERE user_id=$1 ORDER BY created_at,id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]models.Identity, 0)
	for rows.Next() {
		i, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM identities WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
func IsNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// IsUserEmailConflict reports the one uniqueness conflict for which external
// account creation may safely retry with users.email unset. It must never be
// used to select or merge the existing local user.
func IsUserEmailConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == usersEmailUniqueConstraint
}
