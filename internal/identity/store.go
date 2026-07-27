package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/pkg/models"
)

type Store struct {
	db                  *pgxpool.Pool
	passkeyRPID         string
	notificationBuilder account.SecurityNotificationBuilder
}

const usersEmailUniqueConstraint = "idx_users_email_normalized"

var ErrLastAuthenticationMethod = errors.New("cannot remove the last authentication method")

func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// NewStoreForRP scopes Passkey-based authentication invariants to the RP that
// can actually authenticate this deployment. Credentials registered for a
// previous issuer host must not keep an otherwise unreachable account alive.
func NewStoreForRP(db *pgxpool.Pool, passkeyRPID string) *Store {
	return &Store{db: db, passkeyRPID: strings.ToLower(strings.TrimSpace(passkeyRPID))}
}

func (s *Store) SetSecurityNotificationBuilder(builder account.SecurityNotificationBuilder) {
	s.notificationBuilder = builder
}

const identityCols = `id,user_id,provider,external_id,external_username,external_email,metadata,created_at,updated_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanIdentity(row rowScanner) (*models.Identity, error) {
	i := &models.Identity{}
	if err := row.Scan(&i.ID, &i.UserID, &i.Provider, &i.ExternalID, &i.ExternalUsername, &i.ExternalEmail, &i.Metadata, &i.CreatedAt, &i.UpdatedAt); err != nil {
		return nil, err
	}
	return i, nil
}

func lockIdentityNotificationUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (*models.User, error) {
	user := &models.User{ID: userID}
	if err := tx.QueryRow(ctx, `
		SELECT username,email,email_verified_at FROM users WHERE id=$1 FOR UPDATE
	`, userID).Scan(&user.Username, &user.Email, &user.EmailVerifiedAt); err != nil {
		return nil, fmt.Errorf("locking identity owner: %w", err)
	}
	return user, nil
}

func (s *Store) enqueueSecurityNotification(ctx context.Context, tx pgx.Tx, user *models.User, notice account.SecurityNotice) error {
	if s.notificationBuilder == nil {
		return nil
	}
	email, err := s.notificationBuilder.BuildSecurityNotification(user, notice)
	if err != nil {
		return fmt.Errorf("building identity security notification: %w", err)
	}
	if err := account.EnqueueEmailTx(ctx, tx, email); err != nil {
		return fmt.Errorf("queueing identity security notification: %w", err)
	}
	return nil
}

func (s *Store) FindByExternal(ctx context.Context, provider, externalID string) (*models.Identity, error) {
	i, err := scanIdentity(s.db.QueryRow(ctx, `SELECT `+identityCols+` FROM identities WHERE provider=$1 AND external_id=$2`, provider, externalID))
	if err != nil {
		return nil, fmt.Errorf("finding identity: %w", err)
	}
	return i, nil
}
func (s *Store) Create(ctx context.Context, i *models.Identity, mutation audit.MutationAudit) error {
	if i == nil {
		return fmt.Errorf("identity is required")
	}
	if err := mutation.ValidateEvent(models.AuditIdentityBound); err != nil {
		return fmt.Errorf("invalid identity binding audit context: %w", err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting identity binding: %w", err)
	}
	defer tx.Rollback(ctx)
	owner, err := lockIdentityNotificationUser(ctx, tx, i.UserID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO identities (id,user_id,provider,external_id,external_username,external_email,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7)`, i.ID, i.UserID, i.Provider, i.ExternalID, i.ExternalUsername, i.ExternalEmail, i.Metadata)
	if err != nil {
		return fmt.Errorf("creating identity: %w", err)
	}
	mutation = mutation.WithTarget("identity", i.ID.String()).WithDetails(map[string]any{"provider": i.Provider})
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return fmt.Errorf("auditing identity binding: %w", err)
	}
	if err := s.enqueueSecurityNotification(ctx, tx, owner, account.SecurityNotice{MessageType: account.MessageIdentityBound, Provider: i.Provider}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing identity binding: %w", err)
	}
	return nil
}

// CreateUserAndIdentity makes first-time external account creation atomic.
func (s *Store) CreateUserAndIdentity(ctx context.Context, u *models.User, i *models.Identity, options ...CreateUserAndIdentityOptions) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `
		INSERT INTO users (
			id,username,email,email_verified_at,password_hash,display_name,
			status,role,auth_version,session_version,must_change_password,metadata,
			creation_source,created_by
		) VALUES ($1,$2,$3::text,CASE WHEN $3::text IS NULL THEN NULL ELSE NOW() END,NULL,$4,$5,$6,$7,$8,FALSE,$9,'provider',NULL)
	`, u.ID, u.Username, u.Email, u.DisplayName, u.Status, u.Role, u.AuthVersion, u.SessionVersion, u.Metadata)
	if err != nil {
		return fmt.Errorf("creating external user: %w", err)
	}
	i.UserID = u.ID
	_, err = tx.Exec(ctx, `INSERT INTO identities (id,user_id,provider,external_id,external_username,external_email,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7)`, i.ID, i.UserID, i.Provider, i.ExternalID, i.ExternalUsername, i.ExternalEmail, i.Metadata)
	if err != nil {
		return fmt.Errorf("binding external identity: %w", err)
	}
	if len(options) > 0 && options[0].AvatarImportJob != nil {
		job := options[0].AvatarImportJob
		_, err = tx.Exec(ctx, `
			INSERT INTO provider_avatar_import_jobs (
				id,provider_id,user_id,encrypted_avatar_url,status,available_at,created_at,updated_at
			) VALUES ($1,$2,$3,$4,'pending',$5,$5,$5)
		`, job.ID, job.ProviderID, u.ID, job.EncryptedAvatarURL, job.AvailableAt.UTC())
		if err != nil {
			return fmt.Errorf("queueing provider avatar import: %w", err)
		}
	}
	return tx.Commit(ctx)
}

type CreateUserAndIdentityOptions struct {
	AvatarImportJob *models.ProviderAvatarImportJob
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

// DeleteOwned removes an identity and increments auth_version in the same
// transaction. An external-only account must always retain at least one
// identity so the operation cannot lock the owner out.
func (s *Store) DeleteOwned(ctx context.Context, userID, identityID uuid.UUID, mutation audit.MutationAudit) error {
	if err := mutation.ValidateEvent(models.AuditIdentityUnbound); err != nil {
		return fmt.Errorf("invalid identity removal audit context: %w", err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	owner, err := lockIdentityNotificationUser(ctx, tx, userID)
	if err != nil {
		return err
	}
	var hasPassword bool
	if err := tx.QueryRow(ctx, `SELECT password_hash IS NOT NULL FROM users WHERE id=$1`, userID).Scan(&hasPassword); err != nil {
		return err
	}
	var hasPasskey bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM user_passkey_credentials
			WHERE user_id=$1 AND ($2='' OR rp_id=$2)
		)
	`, userID, s.passkeyRPID).Scan(&hasPasskey); err != nil {
		return err
	}
	var identityCount int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM identities WHERE user_id=$1`, userID).Scan(&identityCount); err != nil {
		return err
	}
	var providerName string
	if err := tx.QueryRow(ctx, `SELECT provider FROM identities WHERE id=$1 AND user_id=$2 FOR UPDATE`, identityID, userID).Scan(&providerName); err != nil {
		return err
	}
	if !hasPassword && !hasPasskey && identityCount <= 1 {
		return ErrLastAuthenticationMethod
	}
	if _, err := tx.Exec(ctx, `DELETE FROM identities WHERE id=$1 AND user_id=$2`, identityID, userID); err != nil {
		return fmt.Errorf("deleting owned identity: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET auth_version=auth_version+1,updated_at=NOW() WHERE id=$1`, userID); err != nil {
		return fmt.Errorf("invalidating credentials after identity removal: %w", err)
	}
	mutation = mutation.WithTarget("identity", identityID.String()).WithDetails(map[string]any{"provider": providerName})
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return fmt.Errorf("auditing identity removal: %w", err)
	}
	if err := s.enqueueSecurityNotification(ctx, tx, owner, account.SecurityNotice{MessageType: account.MessageIdentityUnbound, Provider: providerName}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func IsNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// IsUserEmailConflict reports the one uniqueness conflict for which external
// account creation may safely retry with users.email unset. It must never be
// used to select or merge the existing local user.
func IsUserEmailConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == usersEmailUniqueConstraint
}
