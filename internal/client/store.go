package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

var ErrClientQuotaExceeded = errors.New("OAuth client quota exceeded")

type Store struct{ db *pgxpool.Pool }

func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

const clientSelectCols = `id, secret_hash, name, redirect_uris, post_logout_redirect_uris, grants, scopes, is_public, owner_id, metadata, created_at, updated_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanClient(row rowScanner) (*models.OAuthClient, error) {
	c := &models.OAuthClient{}
	if err := row.Scan(&c.ID, &c.SecretHash, &c.Name, &c.RedirectURIs, &c.PostLogoutRedirectURIs, &c.Grants, &c.Scopes, &c.IsPublic, &c.OwnerID, &c.Metadata, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Store) Create(ctx context.Context, c *models.OAuthClient) error {
	_, err := s.db.Exec(ctx, `INSERT INTO oauth_clients (id,secret_hash,name,redirect_uris,post_logout_redirect_uris,grants,scopes,is_public,owner_id,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, c.ID, c.SecretHash, c.Name, c.RedirectURIs, c.PostLogoutRedirectURIs, c.Grants, c.Scopes, c.IsPublic, c.OwnerID, c.Metadata)
	if err != nil {
		return fmt.Errorf("creating OAuth client: %w", err)
	}
	return nil
}

func (s *Store) CreateForOwner(ctx context.Context, c *models.OAuthClient, ownerID string, limit int) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, ownerID); err != nil {
		return fmt.Errorf("locking client owner: %w", err)
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_clients WHERE owner_id=$1`, ownerID).Scan(&count); err != nil {
		return fmt.Errorf("counting owner clients: %w", err)
	}
	if count >= limit {
		return ErrClientQuotaExceeded
	}
	c.OwnerID = &ownerID
	_, err = tx.Exec(ctx, `INSERT INTO oauth_clients (id,secret_hash,name,redirect_uris,post_logout_redirect_uris,grants,scopes,is_public,owner_id,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, c.ID, c.SecretHash, c.Name, c.RedirectURIs, c.PostLogoutRedirectURIs, c.Grants, c.Scopes, c.IsPublic, ownerID, c.Metadata)
	if err != nil {
		return fmt.Errorf("creating owned OAuth client: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *Store) GetByID(ctx context.Context, id string) (*models.OAuthClient, error) {
	c, err := scanClient(s.db.QueryRow(ctx, `SELECT `+clientSelectCols+` FROM oauth_clients WHERE id=$1`, id))
	if err != nil {
		return nil, fmt.Errorf("getting client: %w", err)
	}
	return c, nil
}

func (s *Store) Update(ctx context.Context, c *models.OAuthClient) error {
	result, err := s.db.Exec(ctx, `UPDATE oauth_clients SET name=$2,redirect_uris=$3,post_logout_redirect_uris=$4,grants=$5,scopes=$6,metadata=$7,updated_at=NOW() WHERE id=$1`, c.ID, c.Name, c.RedirectURIs, c.PostLogoutRedirectURIs, c.Grants, c.Scopes, c.Metadata)
	if err != nil {
		return fmt.Errorf("updating client: %w", err)
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
func (s *Store) Delete(ctx context.Context, id string) error {
	result, err := s.db.Exec(ctx, `DELETE FROM oauth_clients WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) List(ctx context.Context, p models.Pagination) (*models.PaginatedResponse[models.OAuthClient], error) {
	return s.list(ctx, p, "", false)
}
func (s *Store) ListByOwner(ctx context.Context, ownerID string, p models.Pagination) (*models.PaginatedResponse[models.OAuthClient], error) {
	return s.list(ctx, p, ownerID, true)
}
func (s *Store) list(ctx context.Context, p models.Pagination, ownerID string, owned bool) (*models.PaginatedResponse[models.OAuthClient], error) {
	countQuery := `SELECT COUNT(*) FROM oauth_clients`
	args := []any{}
	if owned {
		countQuery += ` WHERE owner_id=$1`
		args = append(args, ownerID)
	}
	var total int64
	if err := s.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("counting clients: %w", err)
	}
	query := `SELECT ` + clientSelectCols + ` FROM oauth_clients`
	listArgs := []any{}
	if owned {
		query += ` WHERE owner_id=$1`
		listArgs = append(listArgs, ownerID, p.PageSize, p.Offset())
		query += ` ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3`
	} else {
		listArgs = append(listArgs, p.PageSize, p.Offset())
		query += ` ORDER BY created_at DESC,id DESC LIMIT $1 OFFSET $2`
	}
	rows, err := s.db.Query(ctx, query, listArgs...)
	if err != nil {
		return nil, fmt.Errorf("listing clients: %w", err)
	}
	defer rows.Close()
	items := make([]models.OAuthClient, 0)
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning client: %w", err)
		}
		items = append(items, *c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating clients: %w", err)
	}
	totalPages := (int(total) + p.PageSize - 1) / p.PageSize
	return &models.PaginatedResponse[models.OAuthClient]{Items: items, Total: total, Page: p.Page, PageSize: p.PageSize, TotalPages: totalPages}, nil
}

func (s *Store) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (*models.OAuthClient, error) {
	c, err := s.GetByID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client credentials")
	}
	if c.SecretHash == nil || !crypto.VerifyClientSecret(clientSecret, *c.SecretHash) {
		return nil, fmt.Errorf("invalid client credentials")
	}
	return c, nil
}
func (s *Store) CountByOwner(ctx context.Context, ownerID string) (int64, error) {
	var count int64
	err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_clients WHERE owner_id=$1`, ownerID).Scan(&count)
	return count, err
}
