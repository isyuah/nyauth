package mfa

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

type PasskeyAuthentication struct {
	UserID         uuid.UUID
	Username       string
	AuthVersion    int64
	SessionVersion int64
	Credential     PasskeyCredential
}

func (s *Service) FinishPasskeyRegistration(
	ctx context.Context,
	current *models.User,
	binding AuthenticationBinding,
	name string,
	encodedSession []byte,
	parsed *protocol.ParsedCredentialCreationData,
	gate ChallengeCommitGate,
	auditContext AuditContext,
	now time.Time,
) (PasskeyCredential, error) {
	if s.passkeys == nil {
		return PasskeyCredential{}, ErrPasskeysUnavailable
	}
	name, err := ValidatePasskeyName(name)
	if err != nil {
		return PasskeyCredential{}, err
	}
	sessionData, err := s.validatePasskeySession(encodedSession)
	if err != nil {
		return PasskeyCredential{}, err
	}
	if parsed == nil {
		return PasskeyCredential{}, ErrInvalidPasskey
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return PasskeyCredential{}, fmt.Errorf("starting Passkey registration: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockSecurityShared(ctx, tx); err != nil {
		return PasskeyCredential{}, err
	}
	security, err := settings.LoadSecurityTx(ctx, tx)
	if err != nil {
		return PasskeyCredential{}, err
	}
	if !security.PasskeysEnabled {
		return PasskeyCredential{}, ErrPasskeysDisabled
	}
	if _, err := lockAuthenticationState(ctx, tx, current.ID, binding); err != nil {
		return PasskeyCredential{}, err
	}
	handle, err := lockPasskeyHandleTx(ctx, tx, s.passkeys.rpID, current.ID)
	if err != nil {
		return PasskeyCredential{}, err
	}
	user, err := s.loadPasskeyUserWithHandle(ctx, tx, current, handle, true)
	if err != nil {
		return PasskeyCredential{}, err
	}
	credential, err := s.passkeys.webAuthn.CreateCredential(user, sessionData, parsed)
	if err != nil {
		return PasskeyCredential{}, fmt.Errorf("%w: %v", ErrInvalidPasskey, err)
	}
	row, err := s.insertPasskeyCredentialTx(ctx, tx, current.ID, name, credential, now.UTC())
	if err != nil {
		return PasskeyCredential{}, err
	}
	if err := incrementAuthVersion(ctx, tx, current.ID, now.UTC()); err != nil {
		return PasskeyCredential{}, err
	}
	if err := enqueuePasskeyAudit(
		ctx, tx, models.AuditPasskeyRegistered, current.ID, auditContext,
		row.ID, "success", "high", map[string]any{
			"name": name, "backup_eligible": credential.Flags.BackupEligible,
		}, now.UTC(),
	); err != nil {
		return PasskeyCredential{}, err
	}
	if err := consumeChallengeBeforeCommit(ctx, &gate); err != nil {
		return PasskeyCredential{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PasskeyCredential{}, fmt.Errorf("committing Passkey registration: %w", err)
	}
	return passkeyModel(row), nil
}

func (s *Service) FinishKnownPasskeyAuthentication(
	ctx context.Context,
	current *models.User,
	encodedSession []byte,
	parsed *protocol.ParsedCredentialAssertionData,
	gate ChallengeCommitGate,
	purpose string,
	auditContext AuditContext,
	now time.Time,
) (PasskeyCredential, error) {
	if s.passkeys == nil {
		return PasskeyCredential{}, ErrPasskeysUnavailable
	}
	sessionData, err := s.validatePasskeySession(encodedSession)
	if err != nil {
		return PasskeyCredential{}, err
	}
	if parsed == nil {
		return PasskeyCredential{}, ErrInvalidPasskey
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return PasskeyCredential{}, fmt.Errorf("starting Passkey authentication: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := lockChallengeAuthenticationState(ctx, tx, current.ID, &gate); err != nil {
		return PasskeyCredential{}, err
	}
	handle, err := lockPasskeyHandleTx(ctx, tx, s.passkeys.rpID, current.ID)
	if err != nil {
		return PasskeyCredential{}, err
	}
	user, err := s.loadPasskeyUserWithHandle(ctx, tx, current, handle, true)
	if err != nil {
		return PasskeyCredential{}, err
	}
	credential, err := s.passkeys.webAuthn.ValidateLogin(user, sessionData, parsed)
	if err != nil {
		return PasskeyCredential{}, fmt.Errorf("%w: %v", ErrInvalidPasskey, err)
	}
	row, err := s.updatePasskeyCredentialTx(ctx, tx, user, credential, now.UTC())
	if err != nil {
		return PasskeyCredential{}, err
	}
	risk := "low"
	if credential.Authenticator.CloneWarning {
		risk = "high"
	}
	if err := enqueuePasskeyAudit(
		ctx, tx, models.AuditPasskeyLogin, current.ID, auditContext,
		row.ID, "success", risk, map[string]any{
			"purpose": purpose, "clone_warning": credential.Authenticator.CloneWarning,
			"backup_state": credential.Flags.BackupState,
		}, now.UTC(),
	); err != nil {
		return PasskeyCredential{}, err
	}
	if err := consumeChallengeBeforeCommit(ctx, &gate); err != nil {
		return PasskeyCredential{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PasskeyCredential{}, fmt.Errorf("committing Passkey authentication: %w", err)
	}
	return passkeyModel(row), nil
}

func (s *Service) FinishDiscoverablePasskeyLogin(
	ctx context.Context,
	encodedSession []byte,
	parsed *protocol.ParsedCredentialAssertionData,
	consume func(context.Context) error,
	auditContext AuditContext,
	now time.Time,
) (PasskeyAuthentication, error) {
	if s.passkeys == nil {
		return PasskeyAuthentication{}, ErrPasskeysUnavailable
	}
	sessionData, err := s.validatePasskeySession(encodedSession)
	if err != nil {
		return PasskeyAuthentication{}, err
	}
	if parsed == nil {
		return PasskeyAuthentication{}, ErrInvalidPasskey
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return PasskeyAuthentication{}, fmt.Errorf("starting discoverable Passkey login: %w", err)
	}
	defer tx.Rollback(ctx)
	var resolved *passkeyUser
	var resolverErr error
	resolver := func(rawID, userHandle []byte) (gowebauthn.User, error) {
		resolved, resolverErr = s.loadDiscoverablePasskeyUserTx(ctx, tx, rawID, userHandle)
		if resolverErr != nil {
			return nil, errors.New("credential lookup failed")
		}
		return resolved, nil
	}
	validatedUser, credential, err := s.passkeys.webAuthn.ValidatePasskeyLogin(resolver, sessionData, parsed)
	if resolverErr != nil && !errors.Is(resolverErr, ErrInvalidPasskey) {
		return PasskeyAuthentication{}, resolverErr
	}
	if err != nil {
		return PasskeyAuthentication{}, fmt.Errorf("%w: %v", ErrInvalidPasskey, err)
	}
	if resolved == nil || validatedUser != resolved {
		return PasskeyAuthentication{}, ErrInvalidPasskey
	}
	row, err := s.updatePasskeyCredentialTx(ctx, tx, resolved, credential, now.UTC())
	if err != nil {
		return PasskeyAuthentication{}, err
	}
	risk := "low"
	if credential.Authenticator.CloneWarning {
		risk = "high"
	}
	auditContext.ActorID = resolved.id
	auditContext.ActorName = resolved.username
	if err := enqueuePasskeyAudit(
		ctx, tx, models.AuditPasskeyLogin, resolved.id, auditContext,
		row.ID, "success", risk, map[string]any{
			"purpose": "login", "clone_warning": credential.Authenticator.CloneWarning,
			"backup_state": credential.Flags.BackupState,
		}, now.UTC(),
	); err != nil {
		return PasskeyAuthentication{}, err
	}
	if consume == nil {
		return PasskeyAuthentication{}, fmt.Errorf("consuming Passkey ceremony: missing commit gate")
	}
	if err := consume(ctx); err != nil {
		return PasskeyAuthentication{}, fmt.Errorf("consuming Passkey ceremony: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return PasskeyAuthentication{}, fmt.Errorf("committing discoverable Passkey login: %w", err)
	}
	return PasskeyAuthentication{
		UserID: resolved.id, Username: resolved.username, AuthVersion: resolved.authVersion,
		SessionVersion: resolved.sessionVersion, Credential: passkeyModel(row),
	}, nil
}

func (s *Service) RenamePasskey(
	ctx context.Context,
	userID, passkeyID uuid.UUID,
	name string,
	auditContext AuditContext,
	now time.Time,
) (PasskeyCredential, error) {
	name, err := ValidatePasskeyName(name)
	if err != nil {
		return PasskeyCredential{}, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return PasskeyCredential{}, fmt.Errorf("starting Passkey rename: %w", err)
	}
	defer tx.Rollback(ctx)
	row, err := s.lockPasskeyRowByID(ctx, tx, userID, passkeyID)
	if err != nil {
		return PasskeyCredential{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE user_passkey_credentials SET name=$4,updated_at=$5
		WHERE rp_id=$1 AND user_id=$2 AND id=$3
	`, s.passkeys.rpID, userID, passkeyID, name, now.UTC()); err != nil {
		return PasskeyCredential{}, fmt.Errorf("renaming Passkey: %w", err)
	}
	row.Name = name
	row.UpdatedAt = now.UTC()
	if err := enqueuePasskeyAudit(
		ctx, tx, models.AuditPasskeyRenamed, userID, auditContext,
		passkeyID, "success", "low", map[string]any{"name": name}, now.UTC(),
	); err != nil {
		return PasskeyCredential{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PasskeyCredential{}, fmt.Errorf("committing Passkey rename: %w", err)
	}
	return passkeyModel(row), nil
}

func (s *Service) DeletePasskey(
	ctx context.Context,
	userID, passkeyID uuid.UUID,
	binding AuthenticationBinding,
	auditContext AuditContext,
	now time.Time,
) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting Passkey removal: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockSecurityShared(ctx, tx); err != nil {
		return err
	}
	security, err := settings.LoadSecurityTx(ctx, tx)
	if err != nil {
		return err
	}
	role, err := lockAuthenticationState(ctx, tx, userID, binding)
	if err != nil {
		return err
	}
	row, err := s.lockPasskeyRowByID(ctx, tx, userID, passkeyID)
	if err != nil {
		return err
	}
	var passkeyCount int
	var hasPassword, hasIdentity, hasTOTP bool
	if err := tx.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM user_passkey_credentials WHERE rp_id=$1 AND user_id=$2),
			EXISTS (SELECT 1 FROM users WHERE id=$2 AND password_hash IS NOT NULL),
			EXISTS (
				SELECT 1
				FROM identities AS identity
				JOIN oauth_providers AS provider ON provider.name=identity.provider
				WHERE identity.user_id=$2 AND provider.enabled
			),
			EXISTS (
				SELECT 1 FROM user_totp_credentials
				WHERE user_id=$2 AND confirmed_at IS NOT NULL
			)
	`, s.passkeys.rpID, userID).Scan(&passkeyCount, &hasPassword, &hasIdentity, &hasTOTP); err != nil {
		return fmt.Errorf("checking remaining authentication methods: %w", err)
	}
	if passkeyCount <= 1 && !hasPassword && !hasIdentity {
		return ErrLastAuthenticationMethod
	}
	if security.RequireMFAForAdmins && role == "admin" && passkeyCount <= 1 && !hasTOTP {
		return ErrRequiredByPolicy
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM user_passkey_credentials WHERE rp_id=$1 AND user_id=$2 AND id=$3
	`, s.passkeys.rpID, userID, passkeyID); err != nil {
		return fmt.Errorf("removing Passkey: %w", err)
	}
	if err := incrementAuthVersion(ctx, tx, userID, now.UTC()); err != nil {
		return err
	}
	if err := enqueuePasskeyAudit(
		ctx, tx, models.AuditPasskeyRemoved, userID, auditContext,
		row.ID, "success", "high", map[string]any{"name": row.Name}, now.UTC(),
	); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing Passkey removal: %w", err)
	}
	return nil
}

func (s *Service) validatePasskeySession(encoded []byte) (gowebauthn.SessionData, error) {
	if s.passkeys == nil {
		return gowebauthn.SessionData{}, ErrPasskeysUnavailable
	}
	sessionData, err := unmarshalPasskeySession(encoded)
	if err != nil {
		return gowebauthn.SessionData{}, err
	}
	if sessionData.RelyingPartyID != s.passkeys.rpID {
		return gowebauthn.SessionData{}, ErrInvalidPasskey
	}
	return sessionData, nil
}

func lockPasskeyHandleTx(ctx context.Context, tx pgx.Tx, rpID string, userID uuid.UUID) ([]byte, error) {
	var handle []byte
	if err := tx.QueryRow(ctx, `
		SELECT user_handle FROM user_passkey_handles
		WHERE rp_id=$1 AND user_id=$2
		FOR UPDATE
	`, rpID, userID).Scan(&handle); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPasskeyNotFound
	} else if err != nil {
		return nil, fmt.Errorf("locking Passkey user handle: %w", err)
	}
	return handle, nil
}

func (s *Service) loadDiscoverablePasskeyUserTx(
	ctx context.Context,
	tx pgx.Tx,
	rawID, userHandle []byte,
) (*passkeyUser, error) {
	var current models.User
	err := tx.QueryRow(ctx, `
		SELECT handle.user_id
		FROM user_passkey_handles AS handle
		JOIN user_passkey_credentials AS credential
		  ON credential.rp_id=handle.rp_id AND credential.user_id=handle.user_id
		WHERE handle.rp_id=$1 AND handle.user_handle=$2
		  AND credential.credential_id=$3
	`, s.passkeys.rpID, userHandle, rawID).Scan(&current.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidPasskey
	}
	if err != nil {
		return nil, fmt.Errorf("resolving discoverable Passkey: %w", err)
	}

	// Match every authentication path's lock order: user, handle, then all
	// credential rows in deterministic order. This prevents two credentials
	// for the same account from updating counters through opposing lock orders.
	if err := tx.QueryRow(ctx, `
		SELECT username,display_name,status,auth_version,session_version
		FROM users WHERE id=$1 FOR UPDATE
	`, current.ID).Scan(
		&current.Username, &current.DisplayName, &current.Status,
		&current.AuthVersion, &current.SessionVersion,
	); errors.Is(err, pgx.ErrNoRows) || current.Status != models.UserStatusActive {
		return nil, ErrInvalidPasskey
	} else if err != nil {
		return nil, fmt.Errorf("locking discoverable Passkey user: %w", err)
	}
	lockedHandle, err := lockPasskeyHandleTx(ctx, tx, s.passkeys.rpID, current.ID)
	if errors.Is(err, ErrPasskeyNotFound) {
		return nil, ErrInvalidPasskey
	}
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(lockedHandle, userHandle) {
		return nil, ErrInvalidPasskey
	}
	return s.loadPasskeyUserWithHandle(ctx, tx, &current, lockedHandle, true)
}

func (s *Service) insertPasskeyCredentialTx(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	name string,
	credential *gowebauthn.Credential,
	now time.Time,
) (passkeyRow, error) {
	row := passkeyRow{
		ID: uuid.New(), RPID: s.passkeys.rpID, UserID: userID,
		CredentialID: append([]byte(nil), credential.ID...), Name: name,
		Transports: passkeyTransports(credential), AAGUID: append([]byte(nil), credential.Authenticator.AAGUID...),
		SignCount: int64(credential.Authenticator.SignCount), CloneWarning: credential.Authenticator.CloneWarning,
		Attachment: string(credential.Authenticator.Attachment), BackupEligible: credential.Flags.BackupEligible,
		BackupState: credential.Flags.BackupState, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
		Credential: *credential,
	}
	ciphertext, err := s.encryptPasskeyCredential(row.ID, userID, credential)
	if err != nil {
		return passkeyRow{}, err
	}
	row.Ciphertext = ciphertext
	_, err = tx.Exec(ctx, `
		INSERT INTO user_passkey_credentials (
			id,rp_id,user_id,credential_id,credential_ciphertext,name,transports,aaguid,
			sign_count,clone_warning,attachment,backup_eligible,backup_state,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)
	`, row.ID, row.RPID, row.UserID, row.CredentialID, row.Ciphertext, row.Name,
		row.Transports, passkeyAAGUIDValue(credential), row.SignCount, row.CloneWarning,
		row.Attachment, row.BackupEligible, row.BackupState, now.UTC())
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return passkeyRow{}, ErrPasskeyAlreadyRegistered
		}
		return passkeyRow{}, fmt.Errorf("storing Passkey credential: %w", err)
	}
	return row, nil
}

func (s *Service) updatePasskeyCredentialTx(
	ctx context.Context,
	tx pgx.Tx,
	user *passkeyUser,
	credential *gowebauthn.Credential,
	now time.Time,
) (passkeyRow, error) {
	row, ok := user.rows[string(credential.ID)]
	if !ok {
		return passkeyRow{}, ErrInvalidPasskey
	}
	ciphertext, err := s.encryptPasskeyCredential(row.ID, row.UserID, credential)
	if err != nil {
		return passkeyRow{}, err
	}
	result, err := tx.Exec(ctx, `
		UPDATE user_passkey_credentials SET
			credential_ciphertext=$4,transports=$5,aaguid=$6,sign_count=$7,
			clone_warning=$8,attachment=$9,backup_eligible=$10,backup_state=$11,
			updated_at=$12,last_used_at=$12
		WHERE rp_id=$1 AND user_id=$2 AND id=$3
	`, s.passkeys.rpID, row.UserID, row.ID, ciphertext, passkeyTransports(credential),
		passkeyAAGUIDValue(credential), int64(credential.Authenticator.SignCount),
		credential.Authenticator.CloneWarning, string(credential.Authenticator.Attachment),
		credential.Flags.BackupEligible, credential.Flags.BackupState, now.UTC())
	if err != nil {
		return passkeyRow{}, fmt.Errorf("updating Passkey credential: %w", err)
	}
	if result.RowsAffected() != 1 {
		return passkeyRow{}, ErrPasskeyNotFound
	}
	row.Ciphertext = ciphertext
	row.Transports = passkeyTransports(credential)
	row.AAGUID = append([]byte(nil), credential.Authenticator.AAGUID...)
	row.SignCount = int64(credential.Authenticator.SignCount)
	row.CloneWarning = credential.Authenticator.CloneWarning
	row.Attachment = string(credential.Authenticator.Attachment)
	row.BackupEligible = credential.Flags.BackupEligible
	row.BackupState = credential.Flags.BackupState
	row.UpdatedAt = now.UTC()
	row.LastUsedAt = &now
	row.Credential = *credential
	return row, nil
}

func (s *Service) lockPasskeyRowByID(ctx context.Context, tx pgx.Tx, userID, passkeyID uuid.UUID) (passkeyRow, error) {
	var row passkeyRow
	err := tx.QueryRow(ctx, `
		SELECT id,rp_id,user_id,credential_id,credential_ciphertext,name,transports,aaguid,
		       sign_count,clone_warning,attachment,backup_eligible,backup_state,
		       created_at,updated_at,last_used_at
		FROM user_passkey_credentials
		WHERE rp_id=$1 AND user_id=$2 AND id=$3
		FOR UPDATE
	`, s.passkeys.rpID, userID, passkeyID).Scan(
		&row.ID, &row.RPID, &row.UserID, &row.CredentialID, &row.Ciphertext, &row.Name,
		&row.Transports, &row.AAGUID, &row.SignCount, &row.CloneWarning, &row.Attachment,
		&row.BackupEligible, &row.BackupState, &row.CreatedAt, &row.UpdatedAt, &row.LastUsedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return passkeyRow{}, ErrPasskeyNotFound
	}
	if err != nil {
		return passkeyRow{}, fmt.Errorf("locking Passkey credential: %w", err)
	}
	credential, err := s.decryptPasskeyCredential(row)
	if err != nil {
		return passkeyRow{}, err
	}
	row.Credential = credential
	return row, nil
}

func enqueuePasskeyAudit(
	ctx context.Context,
	tx pgx.Tx,
	event string,
	userID uuid.UUID,
	auditContext AuditContext,
	passkeyID uuid.UUID,
	result, risk string,
	details map[string]any,
	now time.Time,
) error {
	actorID := auditContext.ActorID
	if actorID == uuid.Nil {
		actorID = userID
	}
	if err := audit.EnqueueTargetResultTx(
		ctx, tx, event, &actorID, auditContext.ActorName, "passkey", passkeyID.String(),
		result, risk, auditContext.IPAddress, auditContext.UserAgent, details, now.UTC(),
	); err != nil {
		return fmt.Errorf("auditing %s: %w", event, err)
	}
	return nil
}
