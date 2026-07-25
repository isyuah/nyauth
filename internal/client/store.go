package client

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

// Store handles client persistence.
type Store struct {
	db *pgxpool.Pool
}

// NewStore creates a new client store.
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// Create inserts a new client.
func (s *Store) Create(ctx context.Context, c *models.OAuthClient) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO oauth_clients (id, secret_hash, name, redirect_uris, grants, scopes, is_public, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, c.ID, c.SecretHash, c.Name, c.RedirectURIs, c.Grants, c.Scopes, c.IsPublic, c.Metadata)
	return err
}

// GetByID retrieves a client by ID.
func (s *Store) GetByID(ctx context.Context, id string) (*models.OAuthClient, error) {
	c := &models.OAuthClient{}
	err := s.db.QueryRow(ctx, `
		SELECT id, secret_hash, name, redirect_uris, grants, scopes, is_public, metadata, created_at, updated_at
		FROM oauth_clients WHERE id = $1
	`, id).Scan(&c.ID, &c.SecretHash, &c.Name, &c.RedirectURIs, &c.Grants, &c.Scopes, &c.IsPublic, &c.Metadata, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("getting client: %w", err)
	}
	return c, nil
}

// Update updates a client.
func (s *Store) Update(ctx context.Context, c *models.OAuthClient) error {
	_, err := s.db.Exec(ctx, `
		UPDATE oauth_clients SET name=$2, redirect_uris=$3, grants=$4, scopes=$5, is_public=$6, metadata=$7, updated_at=NOW()
		WHERE id = $1
	`, c.ID, c.Name, c.RedirectURIs, c.Grants, c.Scopes, c.IsPublic, c.Metadata)
	return err
}

// Delete deletes a client.
func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM oauth_clients WHERE id=$1`, id)
	return err
}

// List retrieves clients with pagination.
func (s *Store) List(ctx context.Context, p models.Pagination) (*models.PaginatedResponse[models.OAuthClient], error) {
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_clients`).Scan(&total); err != nil {
		return nil, err
	}

	rows, err := s.db.Query(ctx, `
		SELECT id, secret_hash, name, redirect_uris, grants, scopes, is_public, metadata, created_at, updated_at
		FROM oauth_clients ORDER BY created_at DESC LIMIT $1 OFFSET $2
	`, p.PageSize, p.Offset())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []models.OAuthClient
	for rows.Next() {
		var c models.OAuthClient
		if err := rows.Scan(&c.ID, &c.SecretHash, &c.Name, &c.RedirectURIs, &c.Grants, &c.Scopes, &c.IsPublic, &c.Metadata, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}

	totalPages := int(total) / p.PageSize
	if int(total)%p.PageSize > 0 {
		totalPages++
	}

	return &models.PaginatedResponse[models.OAuthClient]{
		Items: clients, Total: total, Page: p.Page, PageSize: p.PageSize, TotalPages: totalPages,
	}, nil
}

// AuthenticateClient verifies client credentials.
func (s *Store) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (*models.OAuthClient, error) {
	c, err := s.GetByID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found")
	}

	if c.SecretHash == nil {
		return nil, fmt.Errorf("client has no secret")
	}

	ok, err := crypto.VerifyPassword(clientSecret, *c.SecretHash)
	if err != nil || !ok {
		return nil, fmt.Errorf("invalid client secret")
	}

	return c, nil
}
