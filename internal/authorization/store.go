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
	ErrClientChanged      = errors.New("OAuth client changed while consent was in progress")
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
	return s.upsert(ctx, userID, clientID, scopes, allowedClaims, grantedAt, 0, 0)
}

func (s *Store) UpsertExpected(ctx context.Context, userID uuid.UUID, clientID string, scopes, allowedClaims []string, grantedAt time.Time, identityRevision, authorizationRevision int64) error {
	if identityRevision < 1 || authorizationRevision < 1 {
		return fmt.Errorf("invalid OAuth client revision")
	}
	return s.upsert(ctx, userID, clientID, scopes, allowedClaims, grantedAt, identityRevision, authorizationRevision)
}

func (s *Store) upsert(ctx context.Context, userID uuid.UUID, clientID string, scopes, allowedClaims []string, grantedAt time.Time, expectedIdentityRevision, expectedAuthorizationRevision int64) error {
	scopes = canonicalScopes(scopes)
	allowedClaims = canonicalScopes(allowedClaims)
	if userID == uuid.Nil || strings.TrimSpace(clientID) == "" {
		return fmt.Errorf("invalid OAuth authorization")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning OAuth authorization upsert: %w", err)
	}
	defer tx.Rollback(ctx)
	var clientName, homepageURI, privacyPolicyURI, termsOfServiceURI string
	var identityRevision, authorizationRevision int64
	if err := tx.QueryRow(ctx, `
		SELECT name,homepage_uri,privacy_policy_uri,terms_of_service_uri,identity_revision,authorization_revision
		FROM oauth_clients WHERE id=$1 FOR SHARE
	`, clientID).Scan(&clientName, &homepageURI, &privacyPolicyURI, &termsOfServiceURI, &identityRevision, &authorizationRevision); err != nil {
		return fmt.Errorf("locking OAuth client for authorization: %w", err)
	}
	if expectedIdentityRevision > 0 && (identityRevision != expectedIdentityRevision || authorizationRevision != expectedAuthorizationRevision) {
		return ErrClientChanged
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO oauth_authorizations (
			id,user_id,client_id,scopes,allowed_claims,granted_at,last_used_at,revoked_at,created_at,updated_at,
			client_name_snapshot,homepage_uri_snapshot,privacy_policy_uri_snapshot,terms_of_service_uri_snapshot,
			client_identity_revision,client_authorization_revision
		)
		VALUES ($1,$2,$3,$4,$5,$6,NULL,NULL,$6,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (user_id,client_id) DO UPDATE SET
			scopes=EXCLUDED.scopes,allowed_claims=EXCLUDED.allowed_claims,
			client_name_snapshot=EXCLUDED.client_name_snapshot,
			homepage_uri_snapshot=EXCLUDED.homepage_uri_snapshot,
			privacy_policy_uri_snapshot=EXCLUDED.privacy_policy_uri_snapshot,
			terms_of_service_uri_snapshot=EXCLUDED.terms_of_service_uri_snapshot,
			client_identity_revision=EXCLUDED.client_identity_revision,
			client_authorization_revision=EXCLUDED.client_authorization_revision,
			granted_at=EXCLUDED.granted_at,last_used_at=EXCLUDED.last_used_at,
			revoked_at=NULL,updated_at=EXCLUDED.updated_at
		WHERE oauth_authorizations.granted_at <= EXCLUDED.granted_at
		  AND (oauth_authorizations.revoked_at IS NULL OR oauth_authorizations.revoked_at < EXCLUDED.granted_at)
	`, uuid.New(), userID, clientID, scopes, allowedClaims, grantedAt,
		clientName, homepageURI, privacyPolicyURI, termsOfServiceURI, identityRevision, authorizationRevision)
	if err != nil {
		return fmt.Errorf("upserting OAuth authorization: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing OAuth authorization upsert: %w", err)
	}
	return nil
}

// MarkUsed records successful token issuance for an active user grant. It is
// intentionally separate from consent: approving a request does not prove the
// client ever exchanged the authorization code or used a refresh token.
func (s *Store) MarkUsed(ctx context.Context, userID uuid.UUID, clientID string, usedAt time.Time) error {
	if userID == uuid.Nil || strings.TrimSpace(clientID) == "" || usedAt.IsZero() {
		return fmt.Errorf("invalid OAuth authorization use")
	}
	tag, err := s.db.Exec(ctx, `
		UPDATE oauth_authorizations
		SET last_used_at=GREATEST(COALESCE(last_used_at,$3),$3),updated_at=GREATEST(updated_at,$3)
		WHERE user_id=$1 AND client_id=$2 AND revoked_at IS NULL
	`, userID, clientID, usedAt.UTC())
	if err != nil {
		return fmt.Errorf("marking OAuth authorization used: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListByUser(ctx context.Context, userID uuid.UUID) ([]models.OAuthAuthorization, error) {
	rows, err := s.db.Query(ctx, `
		SELECT grant_record.id,grant_record.user_id,grant_record.client_id,client.name,
		       grant_record.client_name_snapshot,client.current_logo_id,
		       client.homepage_uri,client.privacy_policy_uri,client.terms_of_service_uri,
		       grant_record.homepage_uri_snapshot,grant_record.privacy_policy_uri_snapshot,grant_record.terms_of_service_uri_snapshot,
		       grant_record.client_identity_revision,client.identity_revision,
		       grant_record.client_authorization_revision,client.authorization_revision,
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
		item, err := scanAuthorization(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating OAuth authorizations: %w", err)
	}
	return items, nil
}

type ListFilter struct {
	UserID     uuid.UUID
	Query      string
	Status     string
	Pagination models.Pagination
}

func (filter *ListFilter) normalize() error {
	if filter.UserID == uuid.Nil {
		return errors.New("user ID is required")
	}
	filter.Query = strings.TrimSpace(filter.Query)
	if len(filter.Query) > 128 {
		return errors.New("authorization search query is too long")
	}
	switch filter.Status {
	case "", "valid", "changed", "reauthorization_required", "unused":
	default:
		return errors.New("invalid authorization status filter")
	}
	filter.Pagination = models.NewPagination(filter.Pagination.Page, filter.Pagination.PageSize)
	return nil
}

func (s *Store) ListByUserFiltered(ctx context.Context, filter ListFilter) (*models.PaginatedResponse[models.OAuthAuthorization], error) {
	if err := filter.normalize(); err != nil {
		return nil, err
	}
	where := []string{"grant_record.user_id=$1", "grant_record.revoked_at IS NULL"}
	args := []any{filter.UserID}
	if filter.Query != "" {
		args = append(args, filter.Query)
		where = append(where, fmt.Sprintf("(client.name ILIKE '%%' || $%d || '%%' OR grant_record.client_name_snapshot ILIKE '%%' || $%[1]d || '%%' OR grant_record.client_id ILIKE '%%' || $%[1]d || '%%')", len(args)))
	}
	switch filter.Status {
	case "valid":
		where = append(where, "grant_record.client_identity_revision=client.identity_revision", "grant_record.client_authorization_revision=client.authorization_revision")
	case "changed":
		where = append(where, "grant_record.client_identity_revision<>client.identity_revision", "grant_record.client_authorization_revision=client.authorization_revision")
	case "reauthorization_required":
		where = append(where, "grant_record.client_authorization_revision<>client.authorization_revision")
	case "unused":
		where = append(where, "grant_record.last_used_at IS NULL")
	}
	clause := strings.Join(where, " AND ")
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_authorizations grant_record JOIN oauth_clients client ON client.id=grant_record.client_id WHERE `+clause, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("counting OAuth authorizations: %w", err)
	}
	args = append(args, filter.Pagination.PageSize, filter.Pagination.Offset())
	rows, err := s.db.Query(ctx, `
		SELECT grant_record.id,grant_record.user_id,grant_record.client_id,client.name,
		       grant_record.client_name_snapshot,client.current_logo_id,
		       client.homepage_uri,client.privacy_policy_uri,client.terms_of_service_uri,
		       grant_record.homepage_uri_snapshot,grant_record.privacy_policy_uri_snapshot,grant_record.terms_of_service_uri_snapshot,
		       grant_record.client_identity_revision,client.identity_revision,
		       grant_record.client_authorization_revision,client.authorization_revision,
		       grant_record.scopes,grant_record.allowed_claims,grant_record.granted_at,grant_record.last_used_at,
		       grant_record.revoked_at,grant_record.created_at,grant_record.updated_at
		FROM oauth_authorizations AS grant_record
		JOIN oauth_clients AS client ON client.id=grant_record.client_id
		WHERE `+clause+`
		ORDER BY grant_record.last_used_at DESC NULLS LAST,grant_record.granted_at DESC,grant_record.id DESC
		LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("listing OAuth authorizations: %w", err)
	}
	defer rows.Close()
	items := make([]models.OAuthAuthorization, 0, filter.Pagination.PageSize)
	for rows.Next() {
		item, err := scanAuthorization(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating OAuth authorizations: %w", err)
	}
	totalPages := (int(total) + filter.Pagination.PageSize - 1) / filter.Pagination.PageSize
	return &models.PaginatedResponse[models.OAuthAuthorization]{
		Items: items, Total: total, Page: filter.Pagination.Page, PageSize: filter.Pagination.PageSize, TotalPages: totalPages,
	}, nil
}

func scanAuthorization(row interface{ Scan(...any) error }) (models.OAuthAuthorization, error) {
	var item models.OAuthAuthorization
	var logoID *string
	if err := row.Scan(
		&item.ID, &item.UserID, &item.ClientID, &item.ClientName, &item.ClientNameAtGrant, &logoID,
		&item.HomepageURI, &item.PrivacyPolicyURI, &item.TermsOfServiceURI,
		&item.HomepageURIAtGrant, &item.PrivacyPolicyURIAtGrant, &item.TermsOfServiceURIAtGrant,
		&item.ClientIdentityRevision, &item.CurrentIdentityRevision,
		&item.ClientAuthorizationRevision, &item.CurrentAuthorizationRevision,
		&item.Scopes, &item.AllowedClaims, &item.GrantedAt, &item.LastUsedAt, &item.RevokedAt, &item.CreatedAt, &item.UpdatedAt,
	); err != nil {
		return models.OAuthAuthorization{}, fmt.Errorf("scanning OAuth authorization: %w", err)
	}
	if logoID != nil {
		item.LogoURL = "/media/client-logos/" + *logoID + "/128.webp"
	}
	item.ApplicationChanged = item.ClientIdentityRevision != item.CurrentIdentityRevision
	item.ReauthorizationRequired = item.ClientAuthorizationRevision != item.CurrentAuthorizationRevision
	return item, nil
}

// GetActive returns the exact grant that can be compared with a new consent
// request. Revoked records intentionally behave as not found.
func (s *Store) GetActive(ctx context.Context, userID uuid.UUID, clientID string) (*models.OAuthAuthorization, error) {
	var item models.OAuthAuthorization
	if err := s.db.QueryRow(ctx, `
		SELECT id,user_id,client_id,scopes,allowed_claims,granted_at,last_used_at,revoked_at,created_at,updated_at,
		       client_identity_revision,client_authorization_revision
		FROM oauth_authorizations
		WHERE user_id=$1 AND client_id=$2 AND revoked_at IS NULL
	`, userID, clientID).Scan(
		&item.ID, &item.UserID, &item.ClientID, &item.Scopes, &item.AllowedClaims,
		&item.GrantedAt, &item.LastUsedAt, &item.RevokedAt, &item.CreatedAt, &item.UpdatedAt,
		&item.ClientIdentityRevision, &item.ClientAuthorizationRevision,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting OAuth authorization: %w", err)
	}
	return &item, nil
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
