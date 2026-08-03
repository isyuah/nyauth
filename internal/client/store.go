package client

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
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

const clientSelectCols = `id, secret_hash, secret_hint, secret_version, secret_rotated_at, secret_last_used_at, name, homepage_uri, privacy_policy_uri, terms_of_service_uri, current_logo_id, identity_revision, authorization_revision, redirect_uris, post_logout_redirect_uris, grants, scopes, optional_scopes, allowed_claims, is_public, access_policy, owner_id, publisher_type, publisher_verification_status, publisher_verified_at, publisher_verified_by, metadata, created_at, updated_at`

type rowScanner interface{ Scan(dest ...any) error }

type clientExecer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func scanClient(row rowScanner) (*models.OAuthClient, error) {
	c := &models.OAuthClient{}
	if err := row.Scan(clientScanDestinations(c)...); err != nil {
		return nil, err
	}
	setClientLogoURL(c)
	return c, nil
}

func clientScanDestinations(c *models.OAuthClient) []any {
	return []any{
		&c.ID, &c.SecretHash, &c.SecretHint, &c.SecretVersion, &c.SecretRotatedAt,
		&c.SecretLastUsedAt, &c.Name, &c.HomepageURI, &c.PrivacyPolicyURI, &c.TermsOfServiceURI,
		&c.CurrentLogoID, &c.IdentityRevision, &c.AuthorizationRevision, &c.RedirectURIs, &c.PostLogoutRedirectURIs,
		&c.Grants, &c.Scopes, &c.OptionalScopes, &c.AllowedClaims, &c.IsPublic, &c.AccessPolicy, &c.OwnerID,
		&c.PublisherType, &c.PublisherVerification, &c.PublisherVerifiedAt, &c.PublisherVerifiedBy,
		&c.Metadata, &c.CreatedAt, &c.UpdatedAt,
	}
}

func setClientLogoURL(c *models.OAuthClient) {
	if c.CurrentLogoID != nil {
		c.LogoURL = "/media/client-logos/" + *c.CurrentLogoID + "/128.webp"
	}
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
	if c.IdentityRevision < 1 {
		c.IdentityRevision = 1
	}
	if c.AuthorizationRevision < 1 {
		c.AuthorizationRevision = 1
	}
	if c.AccessPolicy == "" {
		c.AccessPolicy = models.ClientAccessOpen
	}
	if c.OptionalScopes == nil {
		c.OptionalScopes = []string{}
	}
	if c.AllowedClaims == nil {
		c.AllowedClaims = []string{}
	}
	if c.PublisherType == "" {
		c.PublisherType = models.PublisherTypeSystemManaged
	}
	if c.PublisherVerification == "" {
		if c.PublisherType == models.PublisherTypeUserRegistered {
			c.PublisherVerification = models.PublisherVerificationUnverified
		} else {
			c.PublisherVerification = models.PublisherVerificationNotApplicable
		}
	}
	_, err := execer.Exec(ctx, `
		INSERT INTO oauth_clients (
			id,secret_hash,secret_hint,secret_version,secret_rotated_at,name,homepage_uri,privacy_policy_uri,terms_of_service_uri,redirect_uris,
			post_logout_redirect_uris,grants,scopes,optional_scopes,allowed_claims,is_public,access_policy,owner_id,
			publisher_type,publisher_verification_status,publisher_verified_at,publisher_verified_by,metadata
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
	`, c.ID, c.SecretHash, c.SecretHint, c.SecretVersion, c.SecretRotatedAt, c.Name,
		c.HomepageURI, c.PrivacyPolicyURI, c.TermsOfServiceURI, c.RedirectURIs, c.PostLogoutRedirectURIs, c.Grants, c.Scopes, c.OptionalScopes, c.AllowedClaims, c.IsPublic, c.AccessPolicy, c.OwnerID,
		c.PublisherType, c.PublisherVerification, c.PublisherVerifiedAt, c.PublisherVerifiedBy, c.Metadata)
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

func (s *Store) ClientAuthorizationRevision(ctx context.Context, clientID string) (int64, error) {
	var revision int64
	if err := s.db.QueryRow(ctx, `SELECT authorization_revision FROM oauth_clients WHERE id=$1`, clientID).Scan(&revision); err != nil {
		return 0, fmt.Errorf("getting client authorization revision: %w", err)
	}
	return revision, nil
}

func (s *Store) Update(ctx context.Context, c *models.OAuthClient, mutation audit.MutationAudit) error {
	name, isPublic, accessPolicy := c.Name, c.IsPublic, c.AccessPolicy
	_, err := s.UpdateRequestWithOAuthPolicy(ctx, c.ID, models.UpdateClientRequest{
		Name: &name, HomepageURI: &c.HomepageURI, PrivacyPolicyURI: &c.PrivacyPolicyURI, TermsOfServiceURI: &c.TermsOfServiceURI,
		RedirectURIs: c.RedirectURIs, PostLogoutRedirectURIs: c.PostLogoutRedirectURIs,
		Grants: c.Grants, Scopes: c.Scopes, OptionalScopes: c.OptionalScopes, AllowedClaims: c.AllowedClaims, IsPublic: &isPublic, AccessPolicy: &accessPolicy, Metadata: c.Metadata,
	}, mutation, settings.Versioned[settings.OAuthPolicy]{Value: settings.DefaultOAuthPolicy()})
	return err
}

func (s *Store) UpdateRequestWithOAuthPolicy(ctx context.Context, id string, request models.UpdateClientRequest, mutation audit.MutationAudit, policy settings.Versioned[settings.OAuthPolicy]) (*models.OAuthClient, error) {
	return s.updateRequestWithOAuthPolicy(ctx, id, "", true, request, mutation, policy)
}

func (s *Store) UpdateOwnedRequestWithOAuthPolicy(ctx context.Context, id, ownerID string, request models.UpdateClientRequest, mutation audit.MutationAudit, policy settings.Versioned[settings.OAuthPolicy]) (*models.OAuthClient, error) {
	return s.updateRequestWithOAuthPolicy(ctx, id, ownerID, false, request, mutation, policy)
}

func (s *Store) updateRequestWithOAuthPolicy(ctx context.Context, id, ownerID string, administrator bool, request models.UpdateClientRequest, mutation audit.MutationAudit, policy settings.Versioned[settings.OAuthPolicy]) (*models.OAuthClient, error) {
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
	if !administrator && (current.OwnerID == nil || *current.OwnerID != ownerID) {
		return nil, ErrClientOwnerUnavailable
	}
	updated := *current
	if err := applyClientUpdate(&updated, request); err != nil {
		return nil, err
	}
	if err := validateUpdatedClientPolicyForActor(current, &updated, request, policy.Value, administrator); err != nil {
		return nil, err
	}
	identityChanged := current.Name != updated.Name || current.HomepageURI != updated.HomepageURI || current.PrivacyPolicyURI != updated.PrivacyPolicyURI || current.TermsOfServiceURI != updated.TermsOfServiceURI
	authorizationChanged := !sameStringSet(current.RedirectURIs, updated.RedirectURIs) || !isSubset(current.Grants, updated.Grants) || current.AccessPolicy != updated.AccessPolicy || !isSubset(current.Scopes, updated.Scopes) || !isSubset(current.AllowedClaims, updated.AllowedClaims)
	updated.IdentityRevision = current.IdentityRevision
	if identityChanged {
		updated.IdentityRevision++
	}
	updated.AuthorizationRevision = current.AuthorizationRevision
	if authorizationChanged {
		updated.AuthorizationRevision++
	}
	result, err := tx.Exec(ctx, `UPDATE oauth_clients SET name=$2,homepage_uri=$3,privacy_policy_uri=$4,terms_of_service_uri=$5,redirect_uris=$6,post_logout_redirect_uris=$7,grants=$8,scopes=$9,optional_scopes=$10,allowed_claims=$11,metadata=$12,access_policy=$13,identity_revision=$14,authorization_revision=$15,updated_at=NOW() WHERE id=$1`, updated.ID, updated.Name, updated.HomepageURI, updated.PrivacyPolicyURI, updated.TermsOfServiceURI, updated.RedirectURIs, updated.PostLogoutRedirectURIs, updated.Grants, updated.Scopes, updated.OptionalScopes, updated.AllowedClaims, updated.Metadata, updated.AccessPolicy, updated.IdentityRevision, updated.AuthorizationRevision)
	if err != nil {
		return nil, fmt.Errorf("updating client: %w", err)
	}
	if result.RowsAffected() == 0 {
		return nil, pgx.ErrNoRows
	}
	audited := mutation.WithTarget("client", updated.ID).WithDetails(map[string]any{
		"identity_changed":         identityChanged,
		"reauthorization_required": authorizationChanged,
		"identity_revision":        updated.IdentityRevision,
		"authorization_revision":   updated.AuthorizationRevision,
	})
	if err := audit.EnqueueMutationTx(ctx, tx, audited); err != nil {
		return nil, fmt.Errorf("auditing client update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing client update: %w", err)
	}
	return &updated, nil
}

func isSubset(candidate, allowed []string) bool {
	for _, value := range candidate {
		if !slices.Contains(allowed, value) {
			return false
		}
	}
	return true
}

func sameStringSet(left, right []string) bool {
	return len(left) == len(right) && isSubset(left, right) && isSubset(right, left)
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

func (s *Store) UpdatePublisherVerification(ctx context.Context, clientID, status, reviewerID string, reviewedAt time.Time, mutation audit.MutationAudit) (*models.OAuthClient, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting publisher verification update: %w", err)
	}
	defer tx.Rollback(ctx)

	current, err := scanClient(tx.QueryRow(ctx, `SELECT `+clientSelectCols+` FROM oauth_clients WHERE id=$1 FOR UPDATE`, clientID))
	if err != nil {
		return nil, err
	}
	if current.PublisherType != models.PublisherTypeUserRegistered {
		return nil, ErrPublisherVerificationNotApplicable
	}
	if current.PublisherVerification == status {
		return nil, ErrPublisherVerificationUnchanged
	}

	var verifiedAt any
	var verifiedBy any
	if status == models.PublisherVerificationVerified {
		verifiedAt = reviewedAt
		verifiedBy = reviewerID
	}
	updated, err := scanClient(tx.QueryRow(ctx, `
		UPDATE oauth_clients
		SET publisher_verification_status=$2,publisher_verified_at=$3,publisher_verified_by=$4,
		    identity_revision=identity_revision+1,updated_at=$5
		WHERE id=$1
		RETURNING `+clientSelectCols,
		clientID, status, verifiedAt, verifiedBy, reviewedAt,
	))
	if err != nil {
		return nil, fmt.Errorf("updating publisher verification: %w", err)
	}
	audited := mutation.WithTarget("client", clientID).WithDetails(map[string]any{
		"old_status": current.PublisherVerification,
		"new_status": status,
	})
	if err := audit.EnqueueMutationTx(ctx, tx, audited); err != nil {
		return nil, fmt.Errorf("auditing publisher verification update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing publisher verification update: %w", err)
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

type ListFilter struct {
	Pagination            models.Pagination
	Query                 string
	ClientType            string
	Grant                 string
	AccessPolicy          string
	PublisherVerification string
	Ownership             string
	Sort                  string
}

func (filter *ListFilter) normalize() error {
	filter.Query = strings.TrimSpace(filter.Query)
	if len(filter.Query) > 128 {
		return errors.New("client search query is too long")
	}
	if filter.ClientType != "" && filter.ClientType != "public" && filter.ClientType != "confidential" {
		return errors.New("invalid client type filter")
	}
	if filter.Grant != "" && !slices.Contains([]string{models.GrantAuthorizationCode, models.GrantClientCredentials, models.GrantRefreshToken, models.GrantDeviceCode}, filter.Grant) {
		return errors.New("invalid grant filter")
	}
	if filter.AccessPolicy != "" && !models.ValidClientAccessPolicy(filter.AccessPolicy) {
		return errors.New("invalid access policy filter")
	}
	if filter.PublisherVerification != "" && !slices.Contains([]string{models.PublisherVerificationNotApplicable, models.PublisherVerificationUnverified, models.PublisherVerificationVerified}, filter.PublisherVerification) {
		return errors.New("invalid publisher verification filter")
	}
	if filter.Ownership != "" && filter.Ownership != "owned" && filter.Ownership != "unowned" {
		return errors.New("invalid ownership filter")
	}
	if filter.Sort == "" {
		filter.Sort = "created_desc"
	}
	if !slices.Contains([]string{"created_desc", "updated_desc", "name_asc", "activity_desc"}, filter.Sort) {
		return errors.New("invalid client sort")
	}
	return nil
}

func (s *Store) List(ctx context.Context, p models.Pagination) (*models.PaginatedResponse[models.OAuthClient], error) {
	return s.ListFiltered(ctx, ListFilter{Pagination: p})
}

func (s *Store) ListFiltered(ctx context.Context, filter ListFilter) (*models.PaginatedResponse[models.OAuthClient], error) {
	if err := filter.normalize(); err != nil {
		return nil, err
	}
	return s.list(ctx, filter, "")
}

func (s *Store) ListByOwner(ctx context.Context, ownerID string, p models.Pagination) (*models.PaginatedResponse[models.OAuthClient], error) {
	return s.list(ctx, ListFilter{Pagination: p, Sort: "created_desc"}, ownerID)
}

const clientListSelectCols = `c.id,c.secret_hash,c.secret_hint,c.secret_version,c.secret_rotated_at,c.secret_last_used_at,c.name,c.homepage_uri,c.privacy_policy_uri,c.terms_of_service_uri,c.current_logo_id,c.identity_revision,c.authorization_revision,c.redirect_uris,c.post_logout_redirect_uris,c.grants,c.scopes,c.optional_scopes,c.allowed_claims,c.is_public,c.access_policy,c.owner_id,c.publisher_type,c.publisher_verification_status,c.publisher_verified_at,c.publisher_verified_by,c.metadata,c.created_at,c.updated_at`

func (s *Store) list(ctx context.Context, filter ListFilter, ownerID string) (*models.PaginatedResponse[models.OAuthClient], error) {
	where := make([]string, 0, 8)
	args := make([]any, 0, 10)
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if ownerID != "" {
		add("c.owner_id=$%d", ownerID)
	} else {
		if filter.Query != "" {
			add("(c.name ILIKE '%%' || $%d || '%%' OR c.id ILIKE '%%' || $%[1]d || '%%' OR owner.username ILIKE '%%' || $%[1]d || '%%')", filter.Query)
		}
		switch filter.ClientType {
		case "public":
			where = append(where, "c.is_public=TRUE")
		case "confidential":
			where = append(where, "c.is_public=FALSE")
		}
		if filter.Grant != "" {
			add("$%d=ANY(c.grants)", filter.Grant)
		}
		if filter.AccessPolicy != "" {
			add("c.access_policy=$%d", filter.AccessPolicy)
		}
		if filter.PublisherVerification != "" {
			add("c.publisher_verification_status=$%d", filter.PublisherVerification)
		}
		switch filter.Ownership {
		case "owned":
			where = append(where, "c.owner_id IS NOT NULL")
		case "unowned":
			where = append(where, "c.owner_id IS NULL")
		}
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_clients c LEFT JOIN users owner ON owner.id=c.owner_id`+clause, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("counting clients: %w", err)
	}
	order := map[string]string{
		"created_desc":  "c.created_at DESC,c.id DESC",
		"updated_desc":  "c.updated_at DESC,c.id DESC",
		"name_asc":      "LOWER(c.name),c.id",
		"activity_desc": "activity.last_activity_at DESC NULLS LAST,c.updated_at DESC,c.id DESC",
	}[filter.Sort]
	args = append(args, filter.Pagination.PageSize, filter.Pagination.Offset())
	query := `SELECT ` + clientListSelectCols + `,owner.username,
		COALESCE(authorizations.authorization_count,0),COALESCE(activity.success_count,0),COALESCE(activity.failure_count,0),activity.last_activity_at
		FROM oauth_clients c
		LEFT JOIN users owner ON owner.id=c.owner_id
		LEFT JOIN LATERAL (
			SELECT COUNT(*) AS authorization_count FROM oauth_authorizations a
			WHERE a.client_id=c.id AND a.revoked_at IS NULL AND a.client_authorization_revision=c.authorization_revision
		) authorizations ON TRUE
		LEFT JOIN LATERAL (
			SELECT COALESCE(SUM(success_count),0) AS success_count,COALESCE(SUM(failure_count),0) AS failure_count,
			       GREATEST(MAX(last_success_at),MAX(last_failure_at)) AS last_activity_at
			FROM oauth_client_stats_daily s WHERE s.client_id=c.id AND s.day >= CURRENT_DATE-6
		) activity ON TRUE` + clause + ` ORDER BY ` + order + ` LIMIT $` + fmt.Sprint(len(args)-1) + ` OFFSET $` + fmt.Sprint(len(args))
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing clients: %w", err)
	}
	defer rows.Close()
	items := make([]models.OAuthClient, 0)
	for rows.Next() {
		c := &models.OAuthClient{}
		destinations := append(clientScanDestinations(c), &c.OwnerUsername, &c.AuthorizationCount, &c.SuccessCount7d, &c.FailureCount7d, &c.LastActivityAt)
		if err := rows.Scan(destinations...); err != nil {
			return nil, fmt.Errorf("scanning client: %w", err)
		}
		setClientLogoURL(c)
		items = append(items, *c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating clients: %w", err)
	}
	totalPages := (int(total) + filter.Pagination.PageSize - 1) / filter.Pagination.PageSize
	return &models.PaginatedResponse[models.OAuthClient]{Items: items, Total: total, Page: filter.Pagination.Page, PageSize: filter.Pagination.PageSize, TotalPages: totalPages}, nil
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
