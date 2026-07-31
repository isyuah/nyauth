package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

var (
	ErrClientQuotaExceeded    = errors.New("OAuth client quota exceeded")
	ErrClientOwnerUnavailable = errors.New("OAuth client owner is unavailable")
	ErrInvalidClientQuota     = errors.New("OAuth client quota is invalid")
	ErrAccessUserUnknown      = errors.New("access list contains unknown users")
)

type Store struct{ db *pgxpool.Pool }

func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

const protectionSettingKey = "protection"

// OwnerQuota is the effective client quota for one user. Override is nil when
// the deployment-wide protection setting supplies Limit.
type OwnerQuota struct {
	Used     int64 `json:"quota_used"`
	Limit    int   `json:"quota_limit"`
	Override *int  `json:"quota_override"`
}

const clientSelectCols = `id, secret_hash, secret_hint, secret_version, secret_rotated_at, secret_last_used_at, name, redirect_uris, post_logout_redirect_uris, grants, scopes, optional_scopes, allowed_claims, is_public, access_policy, owner_id, metadata, created_at, updated_at`

type rowScanner interface{ Scan(dest ...any) error }

type clientExecer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func scanClient(row rowScanner) (*models.OAuthClient, error) {
	c := &models.OAuthClient{}
	if err := row.Scan(
		&c.ID, &c.SecretHash, &c.SecretHint, &c.SecretVersion, &c.SecretRotatedAt,
		&c.SecretLastUsedAt, &c.Name, &c.RedirectURIs, &c.PostLogoutRedirectURIs,
		&c.Grants, &c.Scopes, &c.OptionalScopes, &c.AllowedClaims, &c.IsPublic, &c.AccessPolicy, &c.OwnerID, &c.Metadata, &c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Store) Create(ctx context.Context, c *models.OAuthClient) error {
	prepareSecretMetadata(c, time.Now().UTC())
	return insertClient(ctx, s.db, c)
}

func (s *Store) CreateWithOAuthPolicy(ctx context.Context, c *models.OAuthClient, policy settings.Versioned[settings.OAuthPolicy]) error {
	prepareSecretMetadata(c, time.Now().UTC())
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := requireOAuthPolicy(ctx, tx, policy); err != nil {
		return err
	}
	if err := insertClient(ctx, tx, c); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func insertClient(ctx context.Context, execer clientExecer, c *models.OAuthClient) error {
	if c.AccessPolicy == "" {
		c.AccessPolicy = models.ClientAccessOpen
	}
	if c.OptionalScopes == nil {
		c.OptionalScopes = []string{}
	}
	if c.AllowedClaims == nil {
		c.AllowedClaims = []string{}
	}
	_, err := execer.Exec(ctx, `
		INSERT INTO oauth_clients (
			id,secret_hash,secret_hint,secret_version,secret_rotated_at,name,redirect_uris,
			post_logout_redirect_uris,grants,scopes,optional_scopes,allowed_claims,is_public,access_policy,owner_id,metadata
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
	`, c.ID, c.SecretHash, c.SecretHint, c.SecretVersion, c.SecretRotatedAt, c.Name,
		c.RedirectURIs, c.PostLogoutRedirectURIs, c.Grants, c.Scopes, c.OptionalScopes, c.AllowedClaims, c.IsPublic, c.AccessPolicy, c.OwnerID, c.Metadata)
	if err != nil {
		return fmt.Errorf("creating OAuth client: %w", err)
	}
	return nil
}

func (s *Store) CreateForOwner(ctx context.Context, c *models.OAuthClient, ownerID string) error {
	return s.CreateForOwnerWithOAuthPolicy(ctx, c, ownerID, settings.Versioned[settings.OAuthPolicy]{Value: settings.DefaultOAuthPolicy()})
}

func (s *Store) CreateForOwnerWithOAuthPolicy(ctx context.Context, c *models.OAuthClient, ownerID string, policy settings.Versioned[settings.OAuthPolicy]) error {
	prepareSecretMetadata(c, time.Now().UTC())
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockClientQuotaShared(ctx, tx); err != nil {
		return err
	}
	if err := requireOAuthPolicy(ctx, tx, policy); err != nil {
		return err
	}
	quota, err := lockActiveOwnerQuota(ctx, tx, ownerID)
	if err != nil {
		return err
	}
	if quota.Used >= int64(quota.Limit) {
		return ErrClientQuotaExceeded
	}
	c.OwnerID = &ownerID
	if err = insertClient(ctx, tx, c); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CreateWithAudit(ctx context.Context, c *models.OAuthClient, ownerID *string, mutation audit.MutationAudit) error {
	return s.CreateWithAuditAndOAuthPolicy(ctx, c, ownerID, mutation, settings.Versioned[settings.OAuthPolicy]{Value: settings.DefaultOAuthPolicy()})
}

func (s *Store) CreateWithAuditAndOAuthPolicy(ctx context.Context, c *models.OAuthClient, ownerID *string, mutation audit.MutationAudit, policy settings.Versioned[settings.OAuthPolicy]) error {
	prepareSecretMetadata(c, time.Now().UTC())
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting OAuth client creation: %w", err)
	}
	defer tx.Rollback(ctx)
	c.OwnerID = nil
	if ownerID != nil {
		if err := runtimecoord.LockClientQuotaShared(ctx, tx); err != nil {
			return err
		}
	}
	if err := requireOAuthPolicy(ctx, tx, policy); err != nil {
		return err
	}
	if ownerID != nil {
		quota, err := lockActiveOwnerQuota(ctx, tx, *ownerID)
		if err != nil {
			return err
		}
		if quota.Used >= int64(quota.Limit) {
			return ErrClientQuotaExceeded
		}
		c.OwnerID = ownerID
	}
	if err := insertClient(ctx, tx, c); err != nil {
		return err
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("client", c.ID)); err != nil {
		return fmt.Errorf("auditing OAuth client creation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing OAuth client creation: %w", err)
	}
	return nil
}

func (s *Store) GetByID(ctx context.Context, id string) (*models.OAuthClient, error) {
	c, err := scanClient(s.db.QueryRow(ctx, `SELECT `+clientSelectCols+` FROM oauth_clients WHERE id=$1`, id))
	if err != nil {
		return nil, fmt.Errorf("getting client: %w", err)
	}
	return c, nil
}

func (s *Store) Update(ctx context.Context, c *models.OAuthClient, mutation audit.MutationAudit) error {
	name, isPublic, accessPolicy := c.Name, c.IsPublic, c.AccessPolicy
	_, err := s.UpdateRequestWithOAuthPolicy(ctx, c.ID, models.UpdateClientRequest{
		Name: &name, RedirectURIs: c.RedirectURIs, PostLogoutRedirectURIs: c.PostLogoutRedirectURIs,
		Grants: c.Grants, Scopes: c.Scopes, OptionalScopes: c.OptionalScopes, AllowedClaims: c.AllowedClaims, IsPublic: &isPublic, AccessPolicy: &accessPolicy, Metadata: c.Metadata,
	}, mutation, settings.Versioned[settings.OAuthPolicy]{Value: settings.DefaultOAuthPolicy()})
	return err
}

func (s *Store) UpdateRequestWithOAuthPolicy(ctx context.Context, id string, request models.UpdateClientRequest, mutation audit.MutationAudit, policy settings.Versioned[settings.OAuthPolicy]) (*models.OAuthClient, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting client update: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := requireOAuthPolicy(ctx, tx, policy); err != nil {
		return nil, err
	}
	current, err := scanClient(tx.QueryRow(ctx, `SELECT `+clientSelectCols+` FROM oauth_clients WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return nil, err
	}
	updated := *current
	if err := applyClientUpdate(&updated, request); err != nil {
		return nil, err
	}
	if err := validateUpdatedClientPolicy(current, &updated, request, policy.Value); err != nil {
		return nil, err
	}
	result, err := tx.Exec(ctx, `UPDATE oauth_clients SET name=$2,redirect_uris=$3,post_logout_redirect_uris=$4,grants=$5,scopes=$6,optional_scopes=$7,allowed_claims=$8,metadata=$9,access_policy=$10,updated_at=NOW() WHERE id=$1`, updated.ID, updated.Name, updated.RedirectURIs, updated.PostLogoutRedirectURIs, updated.Grants, updated.Scopes, updated.OptionalScopes, updated.AllowedClaims, updated.Metadata, updated.AccessPolicy)
	if err != nil {
		return nil, fmt.Errorf("updating client: %w", err)
	}
	if result.RowsAffected() == 0 {
		return nil, pgx.ErrNoRows
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("client", updated.ID)); err != nil {
		return nil, fmt.Errorf("auditing client update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing client update: %w", err)
	}
	return &updated, nil
}

func requireOAuthPolicy(ctx context.Context, tx pgx.Tx, expected settings.Versioned[settings.OAuthPolicy]) error {
	if err := settings.RequireOAuthPolicyTx(ctx, tx, expected); err != nil {
		if errors.Is(err, settings.ErrRevisionConflict) {
			return ErrOAuthPolicyChanged
		}
		return err
	}
	return nil
}

func (s *Store) UpdateOwner(ctx context.Context, clientID string, ownerID *string, mutation audit.MutationAudit) (*models.OAuthClient, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting client owner update: %w", err)
	}
	defer tx.Rollback(ctx)

	current, err := scanClient(tx.QueryRow(ctx, `SELECT `+clientSelectCols+` FROM oauth_clients WHERE id=$1 FOR UPDATE`, clientID))
	if err != nil {
		return nil, err
	}
	oldOwnerID := current.OwnerID
	oldValue, newValue := ownerIDValue(oldOwnerID), ownerIDValue(ownerID)
	if newValue != "" && newValue != oldValue {
		if err := runtimecoord.LockClientQuotaShared(ctx, tx); err != nil {
			return nil, err
		}
		quota, err := lockActiveOwnerQuota(ctx, tx, newValue)
		if err != nil {
			return nil, err
		}
		if quota.Used >= int64(quota.Limit) {
			return nil, ErrClientQuotaExceeded
		}
	}

	updated := current
	if oldValue != newValue {
		var ownerArgument any
		if ownerID != nil {
			ownerArgument = *ownerID
		}
		updated, err = scanClient(tx.QueryRow(ctx, `
			UPDATE oauth_clients SET owner_id=$2,updated_at=NOW()
			WHERE id=$1 RETURNING `+clientSelectCols,
			clientID, ownerArgument,
		))
		if err != nil {
			return nil, fmt.Errorf("updating client owner: %w", err)
		}
	}
	audited := mutation.WithTarget("client", clientID).WithDetails(map[string]any{
		"old_owner_id": nullableOwnerID(oldOwnerID),
		"new_owner_id": nullableOwnerID(ownerID),
	})
	if err := audit.EnqueueMutationTx(ctx, tx, audited); err != nil {
		return nil, fmt.Errorf("auditing client owner update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing client owner update: %w", err)
	}
	return updated, nil
}

func (s *Store) Delete(ctx context.Context, id string, mutation audit.MutationAudit) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting client deletion: %w", err)
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `DELETE FROM oauth_clients WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("deleting client: %w", err)
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("client", id)); err != nil {
		return fmt.Errorf("auditing client deletion: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing client deletion: %w", err)
	}
	return nil
}

func (s *Store) DeleteForOwner(ctx context.Context, id, ownerID string) error {
	result, err := s.db.Exec(ctx, `DELETE FROM oauth_clients WHERE id=$1 AND owner_id=$2`, id, ownerID)
	if err != nil {
		return fmt.Errorf("deleting owned client: %w", err)
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
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("invalid client credentials")
	}
	defer tx.Rollback(ctx)
	c, err := scanClient(tx.QueryRow(ctx, `SELECT `+clientSelectCols+` FROM oauth_clients WHERE id=$1 FOR UPDATE`, clientID))
	if err != nil {
		return nil, fmt.Errorf("invalid client credentials")
	}
	if c.SecretHash == nil || !crypto.VerifyClientSecret(clientSecret, *c.SecretHash) {
		return nil, fmt.Errorf("invalid client credentials")
	}
	usedAt := time.Now().UTC()
	if _, err := tx.Exec(ctx, `UPDATE oauth_clients SET secret_last_used_at=$2 WHERE id=$1`, clientID, usedAt); err != nil {
		return nil, fmt.Errorf("invalid client credentials")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("invalid client credentials")
	}
	c.SecretLastUsedAt = &usedAt
	return c, nil
}

func (s *Store) RotateSecret(ctx context.Context, clientID, secretHash, secretHint string, rotatedAt time.Time, mutation audit.MutationAudit) (int64, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("starting client secret rotation: %w", err)
	}
	defer tx.Rollback(ctx)
	var version int64
	if err := tx.QueryRow(ctx, `
		UPDATE oauth_clients SET secret_hash=$2,secret_hint=$3,secret_version=secret_version+1,
		       secret_rotated_at=$4,secret_last_used_at=NULL,updated_at=$4
		WHERE id=$1 AND is_public=FALSE
		RETURNING secret_version
	`, clientID, secretHash, secretHint, rotatedAt).Scan(&version); err != nil {
		return 0, err
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("client", clientID)); err != nil {
		return 0, fmt.Errorf("auditing client secret rotation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("committing client secret rotation: %w", err)
	}
	return version, nil
}

func (s *Store) RotateSecretForOwner(ctx context.Context, clientID, ownerID, secretHash, secretHint string, rotatedAt time.Time) (int64, error) {
	return s.rotateSecret(ctx, clientID, ownerID, true, secretHash, secretHint, rotatedAt)
}

func (s *Store) rotateSecret(ctx context.Context, clientID, ownerID string, owned bool, secretHash, secretHint string, rotatedAt time.Time) (int64, error) {
	query := `
		UPDATE oauth_clients SET secret_hash=$2,secret_hint=$3,secret_version=secret_version+1,
		       secret_rotated_at=$4,secret_last_used_at=NULL,updated_at=$4
		WHERE id=$1 AND is_public=FALSE`
	args := []any{clientID, secretHash, secretHint, rotatedAt}
	if owned {
		query += ` AND owner_id=$5`
		args = append(args, ownerID)
	}
	query += ` RETURNING secret_version`
	var version int64
	if err := s.db.QueryRow(ctx, query, args...).Scan(&version); err != nil {
		return 0, err
	}
	return version, nil
}

func prepareSecretMetadata(c *models.OAuthClient, now time.Time) {
	if c.IsPublic {
		c.SecretHash = nil
		c.SecretHint = nil
		c.SecretVersion = 0
		c.SecretRotatedAt = nil
		c.SecretLastUsedAt = nil
		return
	}
	if c.SecretVersion <= 0 {
		c.SecretVersion = 1
	}
	if c.SecretRotatedAt == nil {
		c.SecretRotatedAt = &now
	}
}

func lockActiveOwnerQuota(ctx context.Context, tx pgx.Tx, ownerID string) (*OwnerQuota, error) {
	quota := &OwnerQuota{}
	var status string
	if err := tx.QueryRow(ctx, `
		SELECT u.status,
		       u.owned_client_limit_override,
		       COALESCE(
		           u.owned_client_limit_override,
		           (SELECT NULLIF(value->>'owned_client_default_limit', '')::integer
		            FROM runtime_settings WHERE key=$2),
		           $3
		       )
		FROM users u
		WHERE u.id=$1
		FOR UPDATE OF u
	`, ownerID, protectionSettingKey, settings.DefaultOwnedClientLimit).Scan(&status, &quota.Override, &quota.Limit); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrClientOwnerUnavailable
		}
		return nil, fmt.Errorf("locking client owner quota: %w", err)
	}
	if status != "active" {
		return nil, ErrClientOwnerUnavailable
	}
	if err := validateOwnerQuota(quota.Limit); err != nil {
		return nil, err
	}
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_clients WHERE owner_id=$1`, ownerID).Scan(&quota.Used); err != nil {
		return nil, fmt.Errorf("counting owner clients: %w", err)
	}
	return quota, nil
}

func ownerIDValue(ownerID *string) string {
	if ownerID == nil {
		return ""
	}
	return *ownerID
}

func nullableOwnerID(ownerID *string) any {
	if ownerID == nil {
		return nil
	}
	return *ownerID
}

func (s *Store) CountByOwner(ctx context.Context, ownerID string) (int64, error) {
	var count int64
	err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_clients WHERE owner_id=$1`, ownerID).Scan(&count)
	return count, err
}

func (s *Store) GetOwnerQuota(ctx context.Context, ownerID string) (*OwnerQuota, error) {
	quota := &OwnerQuota{}
	err := s.db.QueryRow(ctx, `
		SELECT (SELECT COUNT(*) FROM oauth_clients WHERE owner_id=u.id),
		       COALESCE(
		           u.owned_client_limit_override,
		           (SELECT NULLIF(value->>'owned_client_default_limit', '')::integer
		            FROM runtime_settings WHERE key=$2),
		           $3
		       ),
		       u.owned_client_limit_override
		FROM users u
		WHERE u.id=$1
	`, ownerID, protectionSettingKey, settings.DefaultOwnedClientLimit).Scan(&quota.Used, &quota.Limit, &quota.Override)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientOwnerUnavailable
	}
	if err != nil {
		return nil, fmt.Errorf("getting client owner quota: %w", err)
	}
	if err := validateOwnerQuota(quota.Limit); err != nil {
		return nil, err
	}
	return quota, nil
}

func (s *Store) UpdateOwnerQuota(
	ctx context.Context,
	ownerID string,
	override *int,
	mutation audit.MutationAudit,
) (*OwnerQuota, error) {
	if override != nil {
		if err := validateOwnerQuota(*override); err != nil {
			return nil, err
		}
	}
	if err := mutation.ValidateEvent(models.AuditUserClientQuotaUpdated); err != nil {
		return nil, fmt.Errorf("validating client quota audit: %w", err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting client quota update: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockClientQuotaShared(ctx, tx); err != nil {
		return nil, err
	}
	var previousOverride *int
	if err := tx.QueryRow(ctx, `
		SELECT owned_client_limit_override
		FROM users
		WHERE id=$1
		FOR UPDATE
	`, ownerID).Scan(&previousOverride); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrClientOwnerUnavailable
		}
		return nil, fmt.Errorf("locking client owner quota: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users
		SET owned_client_limit_override=$2,updated_at=now()
		WHERE id=$1
	`, ownerID, override); err != nil {
		return nil, fmt.Errorf("updating client owner quota: %w", err)
	}
	quota := &OwnerQuota{Override: override}
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*),
		       COALESCE(
		           $2::integer,
		           (SELECT NULLIF(value->>'owned_client_default_limit', '')::integer
		            FROM runtime_settings WHERE key=$3),
		           $4
		       )
		FROM oauth_clients
		WHERE owner_id=$1
	`, ownerID, override, protectionSettingKey, settings.DefaultOwnedClientLimit).Scan(&quota.Used, &quota.Limit); err != nil {
		return nil, fmt.Errorf("reading updated client owner quota: %w", err)
	}
	mutation = mutation.WithTarget("user", ownerID).WithDetails(map[string]any{
		"previous_override": previousOverride,
		"quota_override":    override,
		"quota_limit":       quota.Limit,
		"quota_used":        quota.Used,
	})
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return nil, fmt.Errorf("auditing client owner quota: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing client owner quota: %w", err)
	}
	return quota, nil
}

func validateOwnerQuota(limit int) error {
	if limit < settings.MinOwnedClientLimit || limit > settings.MaxOwnedClientLimit {
		return fmt.Errorf("%w: %d is outside the supported range", ErrInvalidClientQuota, limit)
	}
	return nil
}

// UserMayAccess evaluates the client's access policy for a user. Unknown
// clients deny access; the caller distinguishes that case earlier if needed.
func (s *Store) UserMayAccess(ctx context.Context, clientID string, userID string) (bool, error) {
	var policy string
	var allowlisted bool
	var role *string
	err := s.db.QueryRow(ctx, `
		SELECT c.access_policy,
		       EXISTS(SELECT 1 FROM client_access_users a WHERE a.client_id = c.id AND a.user_id = $2::uuid),
		       (SELECT u.role FROM users u WHERE u.id = $2::uuid)
		FROM oauth_clients c WHERE c.id = $1
	`, clientID, userID).Scan(&policy, &allowlisted, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("evaluating client access policy: %w", err)
	}
	switch policy {
	case models.ClientAccessAdminsOnly:
		return role != nil && *role == "admin", nil
	case models.ClientAccessAllowlist:
		return allowlisted, nil
	default:
		return true, nil
	}
}

// ListAccessUsers returns the allowlisted users for a client.
func (s *Store) ListAccessUsers(ctx context.Context, clientID string) ([]models.ClientAccessUser, error) {
	rows, err := s.db.Query(ctx, `
		SELECT a.user_id, u.username, COALESCE(u.display_name, ''), u.status, a.created_at
		FROM client_access_users a
		JOIN users u ON u.id = a.user_id
		WHERE a.client_id = $1
		ORDER BY u.username
	`, clientID)
	if err != nil {
		return nil, fmt.Errorf("listing client access users: %w", err)
	}
	defer rows.Close()
	users := make([]models.ClientAccessUser, 0)
	for rows.Next() {
		var entry models.ClientAccessUser
		if err := rows.Scan(&entry.UserID, &entry.Username, &entry.DisplayName, &entry.Status, &entry.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning client access user: %w", err)
		}
		users = append(users, entry)
	}
	return users, rows.Err()
}

// ReplaceAccessUsers replaces the client's allowlist atomically. Unknown user
// IDs fail the whole request so the admin sees an explicit error instead of a
// silently shorter list.
func (s *Store) ReplaceAccessUsers(ctx context.Context, clientID string, userIDs []string, mutation audit.MutationAudit) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting access user update: %w", err)
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oauth_clients WHERE id=$1)`, clientID).Scan(&exists); err != nil {
		return fmt.Errorf("checking client: %w", err)
	}
	if !exists {
		return pgx.ErrNoRows
	}
	if _, err := tx.Exec(ctx, `DELETE FROM client_access_users WHERE client_id=$1`, clientID); err != nil {
		return fmt.Errorf("clearing client access users: %w", err)
	}
	if len(userIDs) > 0 {
		result, err := tx.Exec(ctx, `
			INSERT INTO client_access_users (client_id, user_id)
			SELECT $1, u.id FROM users u WHERE u.id = ANY($2::uuid[])
		`, clientID, userIDs)
		if err != nil {
			return fmt.Errorf("storing client access users: %w", err)
		}
		if result.RowsAffected() != int64(len(userIDs)) {
			return ErrAccessUserUnknown
		}
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("client", clientID)); err != nil {
		return fmt.Errorf("auditing client access update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing client access update: %w", err)
	}
	return nil
}
