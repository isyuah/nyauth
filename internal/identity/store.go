package identity

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/pkg/models"
)

// Store handles identity (external binding) persistence.
type Store struct {
	db *pgxpool.Pool
}

// NewStore creates a new identity store.
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// FindByExternal looks up an identity by provider + external ID.
func (s *Store) FindByExternal(ctx context.Context, provider, externalID string) (*models.Identity, error) {
	identity := &models.Identity{}
	err := s.db.QueryRow(ctx, `
		SELECT id, user_id, provider, external_id, external_username, external_email,
		       access_token, refresh_token, metadata, created_at, updated_at
		FROM identities WHERE provider = $1 AND external_id = $2
	`, provider, externalID).Scan(
		&identity.ID, &identity.UserID, &identity.Provider, &identity.ExternalID,
		&identity.ExternalUsername, &identity.ExternalEmail,
		&identity.AccessToken, &identity.RefreshToken,
		&identity.Metadata, &identity.CreatedAt, &identity.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("finding identity: %w", err)
	}
	return identity, nil
}

// Create creates a new identity binding.
func (s *Store) Create(ctx context.Context, identity *models.Identity) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO identities (id, user_id, provider, external_id, external_username, external_email, access_token, refresh_token, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, identity.ID, identity.UserID, identity.Provider, identity.ExternalID,
		identity.ExternalUsername, identity.ExternalEmail,
		identity.AccessToken, identity.RefreshToken, identity.Metadata)
	return err
}

// ListByUser returns all identities for a user.
func (s *Store) ListByUser(ctx context.Context, userID uuid.UUID) ([]models.Identity, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, user_id, provider, external_id, external_username, external_email,
		       access_token, refresh_token, metadata, created_at, updated_at
		FROM identities WHERE user_id = $1 ORDER BY created_at
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var identities []models.Identity
	for rows.Next() {
		var i models.Identity
		if err := rows.Scan(&i.ID, &i.UserID, &i.Provider, &i.ExternalID,
			&i.ExternalUsername, &i.ExternalEmail,
			&i.AccessToken, &i.RefreshToken,
			&i.Metadata, &i.CreatedAt, &i.UpdatedAt); err != nil {
			return nil, err
		}
		identities = append(identities, i)
	}
	return identities, nil
}

// Delete removes an identity binding.
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Exec(ctx, `DELETE FROM identities WHERE id=$1`, id)
	return err
}
