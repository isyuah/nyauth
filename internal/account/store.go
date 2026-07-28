package account

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/registration"
	accountstats "github.com/nyasharp/nyauth/internal/stats"
	"github.com/nyasharp/nyauth/pkg/models"
)

const accountUserSelectCols = `id, username, email, email_verified_at, password_hash, password_changed_at, display_name, CASE WHEN current_avatar_id IS NULL THEN NULL ELSE '/media/avatars/' || current_avatar_id::text || '/256.webp' END AS avatar_url, status, role, auth_version, session_version, must_change_password, last_authenticated_at, last_login_at, last_login_ip, metadata, created_at, updated_at`
const qualifiedAccountUserSelectCols = `users.id, users.username, users.email, users.email_verified_at, users.password_hash, users.password_changed_at, users.display_name, CASE WHEN users.current_avatar_id IS NULL THEN NULL ELSE '/media/avatars/' || users.current_avatar_id::text || '/256.webp' END AS avatar_url, users.status, users.role, users.auth_version, users.session_version, users.must_change_password, users.last_authenticated_at, users.last_login_at, users.last_login_ip, users.metadata, users.created_at, users.updated_at`

type Store struct {
	db *pgxpool.Pool
}

func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanAccountUser(row rowScanner, extra ...any) (*models.User, error) {
	accountUser := &models.User{}
	destinations := []any{
		&accountUser.ID, &accountUser.Username, &accountUser.Email, &accountUser.EmailVerifiedAt,
		&accountUser.PasswordHash, &accountUser.PasswordChangedAt, &accountUser.DisplayName,
		&accountUser.AvatarURL, &accountUser.Status, &accountUser.Role, &accountUser.AuthVersion, &accountUser.SessionVersion,
		&accountUser.MustChangePassword, &accountUser.LastAuthenticatedAt, &accountUser.LastLoginAt,
		&accountUser.LastLoginIP, &accountUser.Metadata, &accountUser.CreatedAt, &accountUser.UpdatedAt,
	}
	destinations = append(destinations, extra...)
	if err := row.Scan(destinations...); err != nil {
		return nil, err
	}
	return accountUser, nil
}

func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	accountUser, err := scanAccountUser(s.db.QueryRow(ctx, `SELECT `+accountUserSelectCols+` FROM users WHERE id=$1`, id))
	if err != nil {
		return nil, fmt.Errorf("getting account user by ID: %w", err)
	}
	return accountUser, nil
}

func (s *Store) GetUserByEmail(ctx context.Context, normalizedEmail string) (*models.User, error) {
	accountUser, err := scanAccountUser(s.db.QueryRow(ctx, `
		SELECT `+accountUserSelectCols+` FROM users WHERE LOWER(BTRIM(email))=$1
	`, normalizedEmail))
	if err != nil {
		return nil, fmt.Errorf("getting account user by email: %w", err)
	}
	return accountUser, nil
}

func (s *Store) GetPendingRegistrationByEmail(ctx context.Context, normalizedEmail string, now time.Time) (*models.User, time.Time, error) {
	var expiresAt time.Time
	accountUser, err := scanAccountUser(s.db.QueryRow(ctx, `
		SELECT `+qualifiedAccountUserSelectCols+`,registration.expires_at
		FROM users
		JOIN self_registrations AS registration ON registration.user_id=users.id
		WHERE LOWER(BTRIM(users.email))=$1
		  AND users.status='pending' AND users.email_verified_at IS NULL
		  AND registration.status='pending' AND registration.expires_at>$2
	`, normalizedEmail, now.UTC()), &expiresAt)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("getting pending registration by email: %w", err)
	}
	return accountUser, expiresAt, nil
}

func (s *Store) EmailInUse(ctx context.Context, normalizedEmail string, exceptUserID uuid.UUID) (bool, error) {
	var inUse bool
	err := s.db.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(BTRIM(email))=$1 AND id<>$2)
	`, normalizedEmail, exceptUserID).Scan(&inUse)
	if err != nil {
		return false, fmt.Errorf("checking account email: %w", err)
	}
	return inUse, nil
}

func (s *Store) ReplaceActionAndQueueEmail(ctx context.Context, action *ActionToken, email *OutboxEmail) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := ReplaceActionAndQueueEmailTx(ctx, tx, action, email); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ReplaceActionAndQueueEmailTx persists a prepared action, its encrypted email,
// and the action-requested audit event in the caller's transaction.
func ReplaceActionAndQueueEmailTx(ctx context.Context, tx pgx.Tx, action *ActionToken, email *OutboxEmail) error {
	if tx == nil || action == nil || email == nil {
		return fmt.Errorf("prepared account action and transaction are required")
	}
	if action.UserID == uuid.Nil || email.UserID == nil || *email.UserID != action.UserID {
		return fmt.Errorf("prepared account action user does not match email user")
	}
	if _, err := tx.Exec(ctx, `
		UPDATE account_action_tokens
		SET revoked_at=$3, revoked_reason='superseded', payload_ciphertext=''
		WHERE user_id=$1 AND action=$2 AND consumed_at IS NULL AND revoked_at IS NULL
	`, action.UserID, action.Action, action.CreatedAt); err != nil {
		return fmt.Errorf("revoking superseded account action: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO account_action_tokens (
			id,user_id,action,token_hash,payload_ciphertext,requested_ip,user_agent,expires_at,created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, action.ID, action.UserID, action.Action, action.TokenHash, action.PayloadCiphertext,
		action.RequestedIP, action.UserAgent, action.ExpiresAt, action.CreatedAt); err != nil {
		return fmt.Errorf("inserting account action: %w", err)
	}
	if err := insertOutboxEmail(ctx, tx, email); err != nil {
		return err
	}
	if err := insertAuditEvent(ctx, tx, "account.action_requested", action.UserID, action.CreatedAt, map[string]any{
		"action":     action.Action,
		"result":     "success",
		"risk_level": "medium",
	}); err != nil {
		return err
	}
	return nil
}

func (s *Store) ReplacePendingVerificationAndQueueEmail(ctx context.Context, expectedEmail string, action *ActionToken, email *OutboxEmail, now time.Time) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting pending verification replacement: %w", err)
	}
	defer tx.Rollback(ctx)
	var lockedID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT registration.id
		FROM self_registrations AS registration
		JOIN users ON users.id=registration.user_id
		WHERE registration.user_id=$1 AND registration.status='pending' AND registration.expires_at>$2
		  AND users.status='pending' AND users.email_verified_at IS NULL
		  AND LOWER(BTRIM(users.email))=$3
		FOR UPDATE OF registration,users
	`, action.UserID, now.UTC(), expectedEmail).Scan(&lockedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("locking pending registration: %w", err)
	}
	if err := ReplaceActionAndQueueEmailTx(ctx, tx, action, email); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing pending verification replacement: %w", err)
	}
	return nil
}

func (s *Store) GetUsableAction(ctx context.Context, tokenHash []byte, action Action, now time.Time) (*ActionToken, error) {
	var token ActionToken
	err := s.db.QueryRow(ctx, `
		SELECT id,user_id,action,token_hash,payload_ciphertext,host(requested_ip),user_agent,
		       expires_at,consumed_at,revoked_at,created_at
		FROM account_action_tokens
		WHERE token_hash=$1 AND action=$2 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>$3
	`, tokenHash, action, now).Scan(
		&token.ID, &token.UserID, &token.Action, &token.TokenHash, &token.PayloadCiphertext,
		&token.RequestedIP, &token.UserAgent, &token.ExpiresAt, &token.ConsumedAt,
		&token.RevokedAt, &token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidActionToken
		}
		return nil, fmt.Errorf("getting account action: %w", err)
	}
	return &token, nil
}

func (s *Store) ConsumePasswordReset(ctx context.Context, token *ActionToken, expectedEmail, passwordHash string, notices []*OutboxEmail, now time.Time) (*models.User, error) {
	return s.consumeAction(ctx, token, now, notices, func(tx pgx.Tx) (*models.User, error) {
		accountUser, err := scanAccountUser(tx.QueryRow(ctx, `
			UPDATE users SET password_hash=$3,password_changed_at=$4,auth_version=auth_version+1,
			       must_change_password=FALSE,updated_at=$4
			WHERE id=$1 AND status='active' AND LOWER(BTRIM(email))=$2
			RETURNING `+accountUserSelectCols,
			token.UserID, expectedEmail, passwordHash, now,
		))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, ErrInvalidActionToken
			}
			return nil, fmt.Errorf("resetting account password: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE account_action_tokens SET revoked_at=$2,revoked_reason='credential_changed',payload_ciphertext=''
			WHERE user_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL AND id<>$3
		`, token.UserID, now, token.ID); err != nil {
			return nil, fmt.Errorf("revoking account actions after password reset: %w", err)
		}
		if err := insertAuditEvent(ctx, tx, "user.password_reset", token.UserID, now, map[string]any{
			"result": "success", "risk_level": "high", "auth_version": accountUser.AuthVersion,
		}); err != nil {
			return nil, err
		}
		return accountUser, nil
	})
}

func (s *Store) ConsumeEmailVerification(ctx context.Context, token *ActionToken, expectedEmail string, now time.Time) (*models.User, *time.Duration, error) {
	var verificationDuration *time.Duration
	updated, err := s.consumeAction(ctx, token, now, nil, func(tx pgx.Tx) (*models.User, error) {
		var currentStatus models.UserStatus
		var username string
		if err := tx.QueryRow(ctx, `
			SELECT status,username FROM users
			WHERE id=$1 AND status IN ('active','pending') AND LOWER(BTRIM(email))=$2
			FOR UPDATE
		`, token.UserID, expectedEmail).Scan(&currentStatus, &username); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, ErrInvalidActionToken
			}
			return nil, fmt.Errorf("locking account for email verification: %w", err)
		}
		if currentStatus == models.UserStatusPending {
			actorID := token.UserID
			transition, err := registration.CompleteForUserTx(
				ctx, tx, token.UserID, now, false, "email_verification",
				registration.AuditContext{ActorID: &actorID, ActorName: username},
			)
			if err != nil {
				return nil, err
			}
			if !transition.Changed {
				return nil, ErrInvalidActionToken
			}
			duration := now.Sub(transition.CreatedAt)
			if duration >= 0 {
				verificationDuration = &duration
			}
		}
		accountUser, err := scanAccountUser(tx.QueryRow(ctx, `
			UPDATE users SET email_verified_at=$3,updated_at=$3,
				status = CASE WHEN status='pending' THEN 'active' ELSE status END
			WHERE id=$1 AND status IN ('active','pending') AND LOWER(BTRIM(email))=$2
			RETURNING `+accountUserSelectCols,
			token.UserID, expectedEmail, now,
		))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, ErrInvalidActionToken
			}
			return nil, fmt.Errorf("verifying account email: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE account_action_tokens SET revoked_at=$3,revoked_reason='completed',payload_ciphertext=''
			WHERE user_id=$1 AND action=$2 AND consumed_at IS NULL AND revoked_at IS NULL AND id<>$4
		`, token.UserID, ActionEmailVerification, now, token.ID); err != nil {
			return nil, fmt.Errorf("revoking other email verification actions: %w", err)
		}
		if err := insertAuditEvent(ctx, tx, models.AuditUserEmailVerified, token.UserID, now, map[string]any{
			"result": "success", "risk_level": "low",
		}); err != nil {
			return nil, err
		}
		return accountUser, nil
	})
	return updated, verificationDuration, err
}

func (s *Store) ConsumeEmailChange(ctx context.Context, token *ActionToken, previousEmail, newEmail string, notices []*OutboxEmail, now time.Time) (*models.User, error) {
	accountUser, err := s.consumeAction(ctx, token, now, notices, func(tx pgx.Tx) (*models.User, error) {
		query := `
			UPDATE users SET email=$3,email_verified_at=$4,auth_version=auth_version+1,updated_at=$4
			WHERE id=$1 AND status='active' AND (
				($2='' AND email IS NULL) OR LOWER(BTRIM(email))=$2
			)
			RETURNING ` + accountUserSelectCols
		updated, err := scanAccountUser(tx.QueryRow(ctx, query, token.UserID, previousEmail, newEmail, now))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, ErrInvalidActionToken
			}
			if isUniqueViolation(err) {
				return nil, ErrEmailInUse
			}
			return nil, fmt.Errorf("changing account email: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE account_action_tokens SET revoked_at=$2,revoked_reason='identity_changed',payload_ciphertext=''
			WHERE user_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL AND id<>$3
		`, token.UserID, now, token.ID); err != nil {
			return nil, fmt.Errorf("revoking account actions after email change: %w", err)
		}
		if err := insertAuditEvent(ctx, tx, models.AuditUserEmailChanged, token.UserID, now, map[string]any{
			"result": "success", "risk_level": "high", "auth_version": updated.AuthVersion,
		}); err != nil {
			return nil, err
		}
		return updated, nil
	})
	if isUniqueViolation(err) {
		return nil, ErrEmailInUse
	}
	return accountUser, err
}

func (s *Store) consumeAction(
	ctx context.Context,
	token *ActionToken,
	now time.Time,
	notices []*OutboxEmail,
	apply func(tx pgx.Tx) (*models.User, error),
) (*models.User, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var lockedID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT id FROM account_action_tokens
		WHERE id=$1 AND token_hash=$2 AND action=$3 AND consumed_at IS NULL
		  AND revoked_at IS NULL AND expires_at>$4
		FOR UPDATE
	`, token.ID, token.TokenHash, token.Action, now).Scan(&lockedID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidActionToken
		}
		return nil, fmt.Errorf("locking account action: %w", err)
	}
	updated, err := apply(tx)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE account_action_tokens SET consumed_at=$2,payload_ciphertext='' WHERE id=$1`, lockedID, now); err != nil {
		return nil, fmt.Errorf("consuming account action: %w", err)
	}
	for _, notice := range notices {
		if err := insertOutboxEmail(ctx, tx, notice); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrEmailInUse
		}
		return nil, err
	}
	return updated, nil
}

func insertOutboxEmail(ctx context.Context, tx pgx.Tx, email *OutboxEmail) error {
	if email == nil || email.UserID == nil {
		return fmt.Errorf("email outbox user is required")
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO email_outbox (
			id,user_id,message_type,recipient_hash,encrypted_message,status,attempt_count,
			available_at,expires_at,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,'pending',0,$6,$7,$8,$8)
	`, email.ID, *email.UserID, email.MessageType, email.RecipientHash, email.EncryptedMessage,
		email.AvailableAt, email.ExpiresAt, email.CreatedAt)
	if err != nil {
		return fmt.Errorf("inserting email outbox message: %w", err)
	}
	if err := accountstats.AddMailDailyTx(ctx, tx, email.CreatedAt, accountstats.MailDailyDelta{Enqueued: 1}); err != nil {
		return fmt.Errorf("recording queued email statistics: %w", err)
	}
	return nil
}

// EnqueueEmailTx inserts a prepared encrypted email in the caller's
// transaction. A nil email represents an account without verified mail
// capability and is intentionally a no-op.
func EnqueueEmailTx(ctx context.Context, tx pgx.Tx, email *OutboxEmail) error {
	if email == nil {
		return nil
	}
	if tx == nil {
		return fmt.Errorf("email outbox transaction is required")
	}
	return insertOutboxEmail(ctx, tx, email)
}

func insertAuditEvent(ctx context.Context, tx pgx.Tx, event string, userID uuid.UUID, now time.Time, payload map[string]any) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO audit_event_outbox (id,event,aggregate_type,aggregate_id,payload,available_at,created_at,updated_at)
		VALUES ($1,$2,'user',$3,$4,$5,$5,$5)
	`, uuid.New(), event, userID.String(), payload, now)
	if err != nil {
		return fmt.Errorf("inserting audit event outbox record: %w", err)
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func IsNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
