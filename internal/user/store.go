package user

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/registration"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

var (
	ErrLastActiveAdmin  = errors.New("cannot remove the last active administrator")
	ErrAdminMFARequired = errors.New("the user must enroll MFA before becoming an active administrator")
)

// Store handles user persistence.
type Store struct {
	db                  *pgxpool.Pool
	notificationBuilder account.SecurityNotificationBuilder
}

func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

func (s *Store) SetSecurityNotificationBuilder(builder account.SecurityNotificationBuilder) {
	s.notificationBuilder = builder
}

const userSelectCols = `id, username, email, email_verified_at, password_hash, password_changed_at, display_name, avatar_url, status, role, auth_version, session_version, must_change_password, last_authenticated_at, last_login_at, last_login_ip, metadata, created_at, updated_at`

type rowScanner interface {
	Scan(dest ...any) error
}

type userExecer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func scanUser(row rowScanner) (*models.User, error) {
	u := &models.User{}
	if err := row.Scan(
		&u.ID, &u.Username, &u.Email, &u.EmailVerifiedAt, &u.PasswordHash, &u.PasswordChangedAt,
		&u.DisplayName, &u.AvatarURL, &u.Status, &u.Role, &u.AuthVersion, &u.SessionVersion,
		&u.MustChangePassword, &u.LastAuthenticatedAt, &u.LastLoginAt,
		&u.LastLoginIP, &u.Metadata, &u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) enqueueSecurityNotification(ctx context.Context, tx pgx.Tx, user *models.User, notice account.SecurityNotice) error {
	if s.notificationBuilder == nil {
		return nil
	}
	email, err := s.notificationBuilder.BuildSecurityNotification(user, notice)
	if err != nil {
		return fmt.Errorf("building security notification: %w", err)
	}
	if err := account.EnqueueEmailTx(ctx, tx, email); err != nil {
		return fmt.Errorf("queueing security notification: %w", err)
	}
	return nil
}

func (s *Store) Create(ctx context.Context, u *models.User) error {
	return insertUser(ctx, s.db, u)
}

func insertUser(ctx context.Context, execer userExecer, u *models.User) error {
	_, err := execer.Exec(ctx, `
		INSERT INTO users (
			id, username, email, password_hash, password_changed_at, display_name, avatar_url,
			status, role, auth_version, session_version, must_change_password, metadata
		) VALUES ($1,$2,$3,$4,NOW(),$5,$6,$7,$8,$9,$10,$11,$12)
	`, u.ID, u.Username, u.Email, u.PasswordHash, u.DisplayName, u.AvatarURL,
		u.Status, u.Role, u.AuthVersion, u.SessionVersion, u.MustChangePassword, u.Metadata)
	if err != nil {
		return fmt.Errorf("inserting user: %w", err)
	}
	return nil
}

// CreateRegistration atomically writes the user, durable lifecycle record,
// optional invite reservation, verification artifacts, and audit events.
func (s *Store) CreateRegistration(ctx context.Context, u *models.User, options RegistrationCommitOptions) (*uuid.UUID, error) {
	now := options.Now.UTC()
	if u == nil || u.ID == uuid.Nil || now.IsZero() || !options.ExpiresAt.After(now) {
		return nil, fmt.Errorf("invalid registration commit options")
	}
	if u.Status == models.UserStatusPending && options.Verification == nil {
		return nil, fmt.Errorf("pending registration verification artifacts are required")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting registration: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockRegistrationShared(ctx, tx); err != nil {
		return nil, err
	}
	if err := settings.RequireRegistrationTx(ctx, tx, options.Registration); err != nil {
		return nil, err
	}
	if err := runtimecoord.RequireMailDeliveryGate(ctx, tx, options.MailGate); err != nil {
		return nil, err
	}

	var inviteID *uuid.UUID
	if options.InviteCodeHash != nil {
		inviteID, err = registration.ReserveInviteTx(ctx, tx, *options.InviteCodeHash, now)
		if err != nil {
			return nil, err
		}
	}
	if err := insertUser(ctx, tx, u); err != nil {
		return nil, err
	}
	registrationID := uuid.New()
	registrationStatus := registration.StatusCompleted
	if u.Status == models.UserStatusPending {
		registrationStatus = registration.StatusPending
	}
	if err := registration.InsertTx(
		ctx, tx, registrationID, u.ID, inviteID, registrationStatus, options.ExpiresAt, now,
	); err != nil {
		return nil, err
	}
	if options.Verification != nil {
		if err := account.ReplaceActionAndQueueEmailTx(ctx, tx, options.Verification.Action, options.Verification.Email); err != nil {
			return nil, fmt.Errorf("persisting registration verification: %w", err)
		}
	}

	actorID := u.ID
	details := map[string]any{
		"mode":                  options.Registration.Mode,
		"registration_id":       registrationID.String(),
		"verification_required": u.Status == models.UserStatusPending,
	}
	if inviteID != nil {
		details["invite_id"] = inviteID.String()
	}
	if err := audit.EnqueueTargetResultTx(
		ctx, tx, models.AuditUserRegistered, &actorID, u.Username, "user", u.ID.String(),
		"success", "low", options.Audit.IPAddress, options.Audit.UserAgent, details, now,
	); err != nil {
		return nil, fmt.Errorf("auditing user registration: %w", err)
	}
	if inviteID != nil {
		event := models.AuditInviteConsumed
		if registrationStatus == registration.StatusPending {
			event = models.AuditInviteReserved
		}
		if err := audit.EnqueueTargetResultTx(
			ctx, tx, event, &actorID, u.Username, "invite", inviteID.String(),
			"success", "low", options.Audit.IPAddress, options.Audit.UserAgent,
			map[string]any{"registration_id": registrationID.String(), "user_id": u.ID.String()}, now,
		); err != nil {
			return nil, fmt.Errorf("auditing invite reservation: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing registration: %w", err)
	}
	return inviteID, nil
}

func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	u, err := scanUser(s.db.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE id=$1`, id))
	if err != nil {
		return nil, fmt.Errorf("getting user by ID: %w", err)
	}
	return u, nil
}

func (s *Store) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	u, err := scanUser(s.db.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE username=$1`, username))
	if err != nil {
		return nil, fmt.Errorf("getting user by username: %w", err)
	}
	return u, nil
}

func (s *Store) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	u, err := scanUser(s.db.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE LOWER(BTRIM(email))=LOWER(BTRIM($1))`, email))
	if err != nil {
		return nil, fmt.Errorf("getting user by email: %w", err)
	}
	return u, nil
}

// UpdateSelf only updates fields owned by the user. The boolean arguments
// distinguish an omitted JSON field from a request that clears the value.
func (s *Store) UpdateSelf(ctx context.Context, id uuid.UUID, req models.UpdateUserRequest) (*models.User, error) {
	var email any
	if req.Email != nil && *req.Email != "" {
		email = *req.Email
	}
	var displayName any
	if req.DisplayName != nil && *req.DisplayName != "" {
		displayName = *req.DisplayName
	}
	var avatarURL any
	if req.AvatarURL != nil && *req.AvatarURL != "" {
		avatarURL = *req.AvatarURL
	}

	u, err := scanUser(s.db.QueryRow(ctx, `
		UPDATE users SET
			email=CASE WHEN $2 THEN $3::text ELSE email END,
			email_verified_at=CASE WHEN $2 AND LOWER(COALESCE($3::text, '')) <> LOWER(COALESCE(email, '')) THEN NULL ELSE email_verified_at END,
			display_name=CASE WHEN $4 THEN $5::text ELSE display_name END,
			avatar_url=CASE WHEN $6 THEN $7::text ELSE avatar_url END,
			updated_at=NOW()
		WHERE id=$1
		RETURNING `+userSelectCols,
		id, req.Email != nil, email, req.DisplayName != nil, displayName,
		req.AvatarURL != nil, avatarURL,
	))
	if err != nil {
		return nil, fmt.Errorf("updating profile: %w", err)
	}
	return u, nil
}

func (s *Store) UpdateAdmin(ctx context.Context, id uuid.UUID, req models.AdminUpdateUserRequest, mutation audit.MutationAudit) (*models.User, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var securityPolicy settings.Security
	if req.Role != nil || req.Status != nil {
		if err := runtimecoord.LockSecurityShared(ctx, tx); err != nil {
			return nil, err
		}
		securityPolicy, err = settings.LoadSecurityTx(ctx, tx)
		if err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return nil, err
	}
	var currentStatus models.UserStatus
	var currentRole string
	if err := tx.QueryRow(ctx, `SELECT status, role FROM users WHERE id=$1 FOR UPDATE`, id).Scan(&currentStatus, &currentRole); err != nil {
		return nil, err
	}
	removesActiveAdmin := currentStatus == models.UserStatusActive && currentRole == "admin" &&
		((req.Status != nil && *req.Status != models.UserStatusActive) || (req.Role != nil && *req.Role != "admin"))
	if removesActiveAdmin {
		var count int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE status='active' AND role='admin'`).Scan(&count); err != nil {
			return nil, err
		}
		if count <= 1 {
			return nil, ErrLastActiveAdmin
		}
	}
	targetStatus := currentStatus
	if req.Status != nil {
		targetStatus = *req.Status
	}
	targetRole := currentRole
	if req.Role != nil {
		targetRole = *req.Role
	}
	if securityPolicy.RequireMFAForAdmins && targetStatus == models.UserStatusActive && targetRole == "admin" {
		var enrolled bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM user_totp_credentials
				WHERE user_id=$1 AND confirmed_at IS NOT NULL
			)
		`, id).Scan(&enrolled); err != nil {
			return nil, err
		}
		if !enrolled {
			return nil, ErrAdminMFARequired
		}
	}
	if currentStatus == models.UserStatusPending && req.Status != nil && *req.Status == models.UserStatusActive {
		actorID := mutation.ActorID
		if _, err := registration.CompleteForUserTx(
			ctx, tx, id, time.Now().UTC(), true, "admin_activation",
			registration.AuditContext{
				ActorID: &actorID, ActorName: mutation.ActorName,
				IPAddress: mutation.IPAddress, UserAgent: mutation.UserAgent,
			},
		); err != nil {
			return nil, err
		}
	}
	var email, displayName, avatarURL any
	if req.Email != nil && *req.Email != "" {
		email = *req.Email
	}
	if req.DisplayName != nil && *req.DisplayName != "" {
		displayName = *req.DisplayName
	}
	if req.AvatarURL != nil && *req.AvatarURL != "" {
		avatarURL = *req.AvatarURL
	}
	u, err := scanUser(tx.QueryRow(ctx, `
		UPDATE users SET
			email=CASE WHEN $2 THEN $3::text ELSE email END,
			email_verified_at=CASE WHEN $2 AND LOWER(COALESCE($3::text, '')) <> LOWER(COALESCE(email, '')) THEN NULL ELSE email_verified_at END,
			display_name=CASE WHEN $4 THEN $5::text ELSE display_name END,
			avatar_url=CASE WHEN $6 THEN $7::text ELSE avatar_url END,
			auth_version=CASE WHEN
				($2 AND LOWER(COALESCE($3::text, '')) <> LOWER(COALESCE(email, '')))
				OR ($8 AND $9::text <> status)
				OR ($10 AND $11::text <> role)
				THEN auth_version+1 ELSE auth_version END,
			status=CASE WHEN $8 THEN $9::text ELSE status END,
			role=CASE WHEN $10 THEN $11::text ELSE role END,
			metadata=CASE WHEN $12 THEN $13::jsonb ELSE metadata END,
			updated_at=NOW()
		WHERE id=$1 RETURNING `+userSelectCols,
		id, req.Email != nil, email, req.DisplayName != nil, displayName,
		req.AvatarURL != nil, avatarURL, req.Status != nil, req.Status,
		req.Role != nil, req.Role, req.Metadata != nil, req.Metadata,
	))
	if err != nil {
		return nil, fmt.Errorf("updating user: %w", err)
	}
	var notice *account.SecurityNotice
	switch mutation.Event {
	case models.AuditUserRoleChanged:
		notice = &account.SecurityNotice{MessageType: account.MessageRoleChanged, Role: u.Role}
	case models.AuditUserSuspended, models.AuditUserActivated:
		notice = &account.SecurityNotice{MessageType: account.MessageStatusChanged, Status: string(u.Status)}
	}
	if notice != nil {
		if err := s.enqueueSecurityNotification(ctx, tx, u, *notice); err != nil {
			return nil, err
		}
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("user", id.String())); err != nil {
		return nil, fmt.Errorf("auditing user update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return u, nil
}

// UpdatePassword changes the password, invalidates prior credentials, and sets
// whether the user must change it again at the next login.
func (s *Store) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string, mustChange bool, mutation audit.MutationAudit) (*models.User, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting password change: %w", err)
	}
	defer tx.Rollback(ctx)
	u, err := scanUser(tx.QueryRow(ctx, `
		UPDATE users SET password_hash=$2, auth_version=auth_version+1,
			password_changed_at=NOW(), must_change_password=$3, updated_at=NOW()
		WHERE id=$1 RETURNING `+userSelectCols, id, passwordHash, mustChange))
	if err != nil {
		return nil, fmt.Errorf("updating password: %w", err)
	}
	if err := s.enqueueSecurityNotification(ctx, tx, u, account.SecurityNotice{MessageType: account.MessagePasswordChanged}); err != nil {
		return nil, err
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("user", id.String())); err != nil {
		return nil, fmt.Errorf("auditing password change: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing password change: %w", err)
	}
	return u, nil
}

// ResetPassword changes an administrator-selected password and queues the
// successful high-risk audit event in the same transaction.
func (s *Store) ResetPassword(ctx context.Context, id uuid.UUID, passwordHash string, mutation audit.MutationAudit) (*models.User, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting password reset: %w", err)
	}
	defer tx.Rollback(ctx)
	u, err := scanUser(tx.QueryRow(ctx, `
		UPDATE users SET password_hash=$2, auth_version=auth_version+1,
			password_changed_at=NOW(), must_change_password=TRUE, updated_at=NOW()
		WHERE id=$1 RETURNING `+userSelectCols, id, passwordHash))
	if err != nil {
		return nil, fmt.Errorf("resetting password: %w", err)
	}
	if err := s.enqueueSecurityNotification(ctx, tx, u, account.SecurityNotice{MessageType: account.MessagePasswordResetAdmin}); err != nil {
		return nil, err
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("user", id.String())); err != nil {
		return nil, fmt.Errorf("auditing password reset: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing password reset: %w", err)
	}
	return u, nil
}

func (s *Store) SetPasswordIfMissing(ctx context.Context, id uuid.UUID, passwordHash string, mutation audit.MutationAudit) (*models.User, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting password configuration: %w", err)
	}
	defer tx.Rollback(ctx)
	u, err := scanUser(tx.QueryRow(ctx, `
		UPDATE users SET password_hash=$2,auth_version=auth_version+1,
			password_changed_at=NOW(),must_change_password=FALSE,updated_at=NOW()
		WHERE id=$1 AND password_hash IS NULL RETURNING `+userSelectCols, id, passwordHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPasswordConfigured
	}
	if err != nil {
		return nil, fmt.Errorf("setting password: %w", err)
	}
	if err := s.enqueueSecurityNotification(ctx, tx, u, account.SecurityNotice{MessageType: account.MessagePasswordConfigured}); err != nil {
		return nil, err
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("user", id.String())); err != nil {
		return nil, fmt.Errorf("auditing password configuration: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing password configuration: %w", err)
	}
	return u, nil
}

// RevokeSessions advances the authoritative browser-session generation and
// records the successful management mutation in the same transaction.
func (s *Store) RevokeSessions(ctx context.Context, id uuid.UUID, mutation audit.MutationAudit) (int64, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("starting session revocation: %w", err)
	}
	defer tx.Rollback(ctx)

	var sessionVersion int64
	if err := tx.QueryRow(ctx, `
		UPDATE users SET session_version=session_version+1,updated_at=NOW()
		WHERE id=$1 RETURNING session_version
	`, id).Scan(&sessionVersion); err != nil {
		return 0, fmt.Errorf("advancing session version: %w", err)
	}
	mutation = mutation.WithTarget("user", id.String()).WithDetails(map[string]any{
		"session_version": sessionVersion,
	})
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return 0, fmt.Errorf("auditing session revocation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("committing session revocation: %w", err)
	}
	return sessionVersion, nil
}

func (s *Store) Delete(ctx context.Context, id uuid.UUID, mutation audit.MutationAudit) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return err
	}
	var status models.UserStatus
	var role string
	if err := tx.QueryRow(ctx, `SELECT status, role FROM users WHERE id=$1 FOR UPDATE`, id).Scan(&status, &role); err != nil {
		return err
	}
	if status == models.UserStatusActive && role == "admin" {
		var count int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE status='active' AND role='admin'`).Scan(&count); err != nil {
			return err
		}
		if count <= 1 {
			return ErrLastActiveAdmin
		}
	}
	actorID := mutation.ActorID
	if _, err := registration.ReleaseForUserTx(
		ctx, tx, id, time.Now().UTC(), registration.ReleaseReasonAdminDeleted, "admin_deletion",
		registration.AuditContext{
			ActorID: &actorID, ActorName: mutation.ActorName,
			IPAddress: mutation.IPAddress, UserAgent: mutation.UserAgent,
		},
	); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation.WithTarget("user", id.String())); err != nil {
		return fmt.Errorf("auditing user deletion: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *Store) Count(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

// BootstrapAdmin creates the first user while holding a database table lock.
func (s *Store) BootstrapAdmin(ctx context.Context, u *models.User) (bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return false, err
	}
	var count int64
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return false, err
	}
	if count != 0 {
		return false, tx.Commit(ctx)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id,username,email,password_hash,password_changed_at,display_name,status,role,auth_version,must_change_password,metadata)
		VALUES ($1,$2,$3,$4,NOW(),$5,'active','admin',1,TRUE,$6)
	`, u.ID, u.Username, u.Email, u.PasswordHash, u.DisplayName, u.Metadata)
	if err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func (s *Store) List(ctx context.Context, p models.Pagination, search string, status models.UserStatus) (*models.PaginatedResponse[models.User], error) {
	var total int64
	if err := s.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM users
		WHERE ($1::text='' OR status=$1)
		  AND ($2::text='' OR username ILIKE '%' || $2 || '%'
		       OR COALESCE(email,'') ILIKE '%' || $2 || '%'
		       OR COALESCE(display_name,'') ILIKE '%' || $2 || '%')
	`, status, search).Scan(&total); err != nil {
		return nil, fmt.Errorf("counting users: %w", err)
	}
	rows, err := s.db.Query(ctx, `SELECT `+userSelectCols+` FROM users
		WHERE ($1::text='' OR status=$1)
		  AND ($2::text='' OR username ILIKE '%' || $2 || '%'
		       OR COALESCE(email,'') ILIKE '%' || $2 || '%'
		       OR COALESCE(display_name,'') ILIKE '%' || $2 || '%')
		ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4
	`, status, search, p.PageSize, p.Offset())
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close()
	users := make([]models.User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}
		users = append(users, *u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating users: %w", err)
	}
	totalPages := (int(total) + p.PageSize - 1) / p.PageSize
	return &models.PaginatedResponse[models.User]{Items: users, Total: total, Page: p.Page, PageSize: p.PageSize, TotalPages: totalPages}, nil
}

func (s *Store) RecordLogin(ctx context.Context, id uuid.UUID, ip string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET last_authenticated_at=NOW(), last_login_at=NOW(), last_login_ip=$2, updated_at=NOW() WHERE id=$1`, id, ip)
	return err
}

func (s *Store) RecordAuthentication(ctx context.Context, id uuid.UUID, authVersion, sessionVersion int64) (*models.User, error) {
	u, err := scanUser(s.db.QueryRow(ctx, `
		UPDATE users SET last_authenticated_at=NOW(),updated_at=NOW()
		WHERE id=$1 AND status='active' AND auth_version=$2 AND session_version=$3
		RETURNING `+userSelectCols, id, authVersion, sessionVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAuthStateChanged
	}
	if err != nil {
		return nil, fmt.Errorf("recording authentication: %w", err)
	}
	return u, nil
}

// IsNotFound reports whether a store error was caused by a missing row.
func IsNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
