package authorization

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/pkg/models"
)

var (
	ErrNotFound           = errors.New("OAuth authorization not found")
	ErrAuthorizationNewer = errors.New("OAuth authorization was renewed while revocation was in progress")
)

type Store struct {
	db *pgxpool.Pool
}

func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// Upsert records the exact scope and claim set most recently approved by the
// user. A grant that was previously revoked is reactivated without deleting
// its audit history or any Redis revocation marker.
func (s *Store) Upsert(ctx context.Context, userID uuid.UUID, clientID string, scopes, allowedClaims []string, grantedAt time.Time) error {
	scopes = canonicalScopes(scopes)
	allowedClaims = canonicalScopes(allowedClaims)
	if userID == uuid.Nil || strings.TrimSpace(clientID) == "" {
		return fmt.Errorf("invalid OAuth authorization")
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO oauth_authorizations (
			id,user_id,client_id,scopes,allowed_claims,granted_at,last_used_at,revoked_at,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$6,NULL,$6,$6)
		ON CONFLICT (user_id,client_id) DO UPDATE SET
			scopes=EXCLUDED.scopes,allowed_claims=EXCLUDED.allowed_claims,
			granted_at=EXCLUDED.granted_at,last_used_at=EXCLUDED.last_used_at,
			revoked_at=NULL,updated_at=EXCLUDED.updated_at
		WHERE oauth_authorizations.granted_at <= EXCLUDED.granted_at
		  AND (oauth_authorizations.revoked_at IS NULL OR oauth_authorizations.revoked_at < EXCLUDED.granted_at)
	`, uuid.New(), userID, clientID, scopes, allowedClaims, grantedAt)
	if err != nil {
		return fmt.Errorf("upserting OAuth authorization: %w", err)
	}
	return nil
}

func (s *Store) ListByUser(ctx context.Context, userID uuid.UUID) ([]models.OAuthAuthorization, error) {
	rows, err := s.db.Query(ctx, `
		SELECT grant_record.id,grant_record.user_id,grant_record.client_id,client.name,
		       grant_record.scopes,grant_record.allowed_claims,grant_record.granted_at,grant_record.last_used_at,
		       grant_record.revoked_at,grant_record.created_at,grant_record.updated_at
		FROM oauth_authorizations AS grant_record
		JOIN oauth_clients AS client ON client.id=grant_record.client_id
		WHERE grant_record.user_id=$1 AND grant_record.revoked_at IS NULL
		ORDER BY grant_record.last_used_at DESC NULLS LAST,grant_record.granted_at DESC,grant_record.id DESC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("listing OAuth authorizations: %w", err)
	}
	defer rows.Close()
	items := make([]models.OAuthAuthorization, 0)
	for rows.Next() {
		var item models.OAuthAuthorization
		if err := rows.Scan(
			&item.ID, &item.UserID, &item.ClientID, &item.ClientName, &item.Scopes, &item.AllowedClaims,
			&item.GrantedAt, &item.LastUsedAt, &item.RevokedAt, &item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning OAuth authorization: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating OAuth authorizations: %w", err)
	}
	return items, nil
}

func (s *Store) Revoke(ctx context.Context, userID uuid.UUID, clientID string, revokedAt time.Time) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning OAuth authorization revocation: %w", err)
	}
	defer tx.Rollback(ctx)

	var grantedAt time.Time
	var currentRevokedAt *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT granted_at,revoked_at FROM oauth_authorizations
		WHERE user_id=$1 AND client_id=$2
		FOR UPDATE
	`, userID, clientID).Scan(&grantedAt, &currentRevokedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("locking OAuth authorization for revocation: %w", err)
	}
	if currentRevokedAt != nil {
		return ErrNotFound
	}
	if grantedAt.After(revokedAt) {
		return ErrAuthorizationNewer
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_authorizations SET revoked_at=$3,updated_at=$3
		WHERE user_id=$1 AND client_id=$2
	`, userID, clientID, revokedAt); err != nil {
		return fmt.Errorf("revoking OAuth authorization: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing OAuth authorization revocation: %w", err)
	}
	return nil
}

func canonicalScopes(scopes []string) []string {
	seen := make(map[string]struct{}, len(scopes))
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	sort.Strings(result)
	return result
}

func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, pgx.ErrNoRows)
}
