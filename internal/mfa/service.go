package mfa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	nyacrypto "github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

const totpEnvelopePurpose = "mfa.totp.secret"

var (
	ErrTOTPDisabled          = errors.New("TOTP enrollment is disabled")
	ErrAlreadyEnrolled       = errors.New("TOTP is already enrolled")
	ErrNotEnrolled           = errors.New("TOTP is not enrolled")
	ErrEnrollmentChanged     = errors.New("TOTP enrollment changed")
	ErrInvalidCode           = errors.New("invalid MFA code")
	ErrCodeReplayed          = errors.New("TOTP code has already been used")
	ErrAuthenticationChanged = errors.New("authentication state changed")
	ErrRequiredByPolicy      = errors.New("MFA is required for active administrators")
)

type Options struct {
	ActiveKeyID string
	MasterKeys  map[string][]byte
	Passkeys    *PasskeyConfig
}

type Service struct {
	db          *pgxpool.Pool
	activeKeyID string
	masterKeys  map[string][]byte
	passkeys    *passkeyRuntime
}

type AuditContext struct {
	ActorID   uuid.UUID
	ActorName string
	IPAddress string
	UserAgent string
}

// AuthenticationBinding captures the security generations of the session
// that authorized a sensitive MFA mutation. A mutation must not cross a
// concurrent password change, role/status change, or session revocation.
type AuthenticationBinding struct {
	AuthVersion    int64
	SessionVersion int64
}

// ChallengeCommitGate binds factor consumption to the authentication state
// captured when the MFA challenge was created. Consume is called after all
// PostgreSQL writes have succeeded but before the transaction commits, so a
// Redis failure rolls back TOTP/recovery-code consumption.
type ChallengeCommitGate struct {
	AuthVersion    int64
	SessionVersion int64
	Consume        func(context.Context) error
}

type Status struct {
	TOTPEnrolled           bool `json:"totp_enrolled"`
	RecoveryCodesRemaining int  `json:"recovery_codes_remaining"`
	PasskeysEnrolled       int  `json:"passkeys_enrolled"`
}

type Enrollment struct {
	Secret     string `json:"secret"`
	OTPAuthURI string `json:"otpauth_uri"`
}

func NewService(db *pgxpool.Pool, options Options) (*Service, error) {
	if db == nil {
		return nil, fmt.Errorf("MFA database is required")
	}
	options.ActiveKeyID = strings.TrimSpace(options.ActiveKeyID)
	activeKey, ok := options.MasterKeys[options.ActiveKeyID]
	if !ok || len(activeKey) != 32 {
		return nil, fmt.Errorf("active MFA master key must contain exactly 32 bytes")
	}
	keys := make(map[string][]byte, len(options.MasterKeys))
	for keyID, key := range options.MasterKeys {
		if strings.TrimSpace(keyID) == "" || len(key) != 32 {
			return nil, fmt.Errorf("MFA master key %q must contain exactly 32 bytes", keyID)
		}
		keys[keyID] = append([]byte(nil), key...)
	}
	passkeys, err := newPasskeyRuntime(options.Passkeys)
	if err != nil {
		return nil, err
	}
	return &Service{db: db, activeKeyID: options.ActiveKeyID, masterKeys: keys, passkeys: passkeys}, nil
}

func (s *Service) Status(ctx context.Context, userID uuid.UUID) (Status, error) {
	var status Status
	rpID := ""
	if s.passkeys != nil {
		rpID = s.passkeys.rpID
	}
	err := s.db.QueryRow(ctx, `
		SELECT
			EXISTS (
				SELECT 1 FROM user_totp_credentials
				WHERE user_id=$1 AND confirmed_at IS NOT NULL
			),
			(
				SELECT COUNT(*) FROM user_recovery_codes
				WHERE user_id=$1 AND used_at IS NULL
			),
			(
				SELECT COUNT(*) FROM user_passkey_credentials
				WHERE user_id=$1 AND ($2='' OR rp_id=$2)
			)
	`, userID, rpID).Scan(&status.TOTPEnrolled, &status.RecoveryCodesRemaining, &status.PasskeysEnrolled)
	if err != nil {
		return Status{}, fmt.Errorf("loading MFA status: %w", err)
	}
	return status, nil
}

// VerifyStoredSecrets authenticates every persisted TOTP envelope without
// returning plaintext. It is used by the read-only disaster-recovery verifier
// so a restored database cannot appear healthy with an unrelated master key.
func (s *Service) VerifyStoredSecrets(ctx context.Context) (int64, error) {
	rows, err := s.db.Query(ctx, `
		SELECT user_id,secret_ciphertext
		FROM user_totp_credentials
		ORDER BY user_id
	`)
	if err != nil {
		return 0, fmt.Errorf("querying stored TOTP envelopes: %w", err)
	}
	defer rows.Close()

	var verified int64
	for rows.Next() {
		var userID uuid.UUID
		var ciphertext string
		if err := rows.Scan(&userID, &ciphertext); err != nil {
			return 0, fmt.Errorf("scanning stored TOTP envelope: %w", err)
		}
		if _, err := nyacrypto.DecryptEnvelope(
			s.masterKeys, totpEnvelopePurpose, ciphertext, []byte(userID.String()),
		); err != nil {
			return 0, fmt.Errorf("verifying stored TOTP envelope: %w", err)
		}
		verified++
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterating stored TOTP envelopes: %w", err)
	}
	return verified, nil
}

func (s *Service) LoginMethods(ctx context.Context, userID uuid.UUID) ([]string, error) {
	status, err := s.Status(ctx, userID)
	if err != nil {
		return nil, err
	}
	methods := make([]string, 0, 3)
	if status.TOTPEnrolled {
		methods = append(methods, "totp")
		if status.RecoveryCodesRemaining > 0 {
			methods = append(methods, "recovery_code")
		}
	}
	if status.PasskeysEnrolled > 0 {
		methods = append(methods, "passkey")
	}
	return methods, nil
}

func (s *Service) BeginEnrollment(ctx context.Context, userID uuid.UUID, issuer, account string, now time.Time) (Enrollment, error) {
	secret, encodedSecret, err := generateTOTPSecret()
	if err != nil {
		return Enrollment{}, err
	}
	ciphertext, err := nyacrypto.EncryptEnvelope(
		s.masterKeys[s.activeKeyID], s.activeKeyID, totpEnvelopePurpose,
		secret, []byte(userID.String()),
	)
	if err != nil {
		return Enrollment{}, fmt.Errorf("encrypting TOTP secret: %w", err)
	}
	uri, err := totpURI(issuer, account, encodedSecret)
	if err != nil {
		return Enrollment{}, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Enrollment{}, fmt.Errorf("starting TOTP enrollment: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockSecurityShared(ctx, tx); err != nil {
		return Enrollment{}, err
	}
	security, err := settings.LoadSecurityTx(ctx, tx)
	if err != nil {
		return Enrollment{}, err
	}
	if !security.TOTPEnabled {
		return Enrollment{}, ErrTOTPDisabled
	}
	var storedUserID uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO user_totp_credentials (
			user_id,secret_ciphertext,confirmed_at,last_used_step,created_at,updated_at
		) VALUES ($1,$2,NULL,NULL,$3,$3)
		ON CONFLICT (user_id) DO UPDATE SET
			secret_ciphertext=EXCLUDED.secret_ciphertext,
			confirmed_at=NULL,last_used_step=NULL,updated_at=EXCLUDED.updated_at
		WHERE user_totp_credentials.confirmed_at IS NULL
		RETURNING user_id
	`, userID, ciphertext, now.UTC()).Scan(&storedUserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Enrollment{}, ErrAlreadyEnrolled
	}
	if err != nil {
		return Enrollment{}, fmt.Errorf("storing pending TOTP enrollment: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Enrollment{}, fmt.Errorf("committing TOTP enrollment: %w", err)
	}
	return Enrollment{Secret: encodedSecret, OTPAuthURI: uri}, nil
}

func (s *Service) ConfirmEnrollment(
	ctx context.Context,
	userID uuid.UUID,
	binding AuthenticationBinding,
	code string,
	auditContext AuditContext,
	now time.Time,
) ([]string, error) {
	var ciphertext string
	if err := s.db.QueryRow(ctx, `
		SELECT secret_ciphertext FROM user_totp_credentials
		WHERE user_id=$1 AND confirmed_at IS NULL
	`, userID).Scan(&ciphertext); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotEnrolled
	} else if err != nil {
		return nil, fmt.Errorf("loading pending TOTP enrollment: %w", err)
	}
	secret, err := nyacrypto.DecryptEnvelope(s.masterKeys, totpEnvelopePurpose, ciphertext, []byte(userID.String()))
	if err != nil {
		return nil, fmt.Errorf("decrypting TOTP secret: %w", err)
	}
	matchedStep, ok := matchTOTP(secret, code, now)
	if !ok {
		return nil, ErrInvalidCode
	}
	codes, records, err := generateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting TOTP confirmation: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockSecurityShared(ctx, tx); err != nil {
		return nil, err
	}
	security, err := settings.LoadSecurityTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	if !security.TOTPEnabled {
		return nil, ErrTOTPDisabled
	}
	if _, err := lockAuthenticationState(ctx, tx, userID, binding); err != nil {
		return nil, err
	}
	result, err := tx.Exec(ctx, `
		UPDATE user_totp_credentials
		SET confirmed_at=$3,last_used_step=$4,updated_at=$3
		WHERE user_id=$1 AND secret_ciphertext=$2 AND confirmed_at IS NULL
	`, userID, ciphertext, now.UTC(), matchedStep)
	if err != nil {
		return nil, fmt.Errorf("confirming TOTP enrollment: %w", err)
	}
	if result.RowsAffected() == 0 {
		return nil, ErrEnrollmentChanged
	}
	if err := insertRecoveryCodes(ctx, tx, userID, records, now.UTC()); err != nil {
		return nil, err
	}
	if err := incrementAuthVersion(ctx, tx, userID, now.UTC()); err != nil {
		return nil, err
	}
	if err := enqueueAudit(ctx, tx, models.AuditMFAEnrolled, userID, auditContext, map[string]any{
		"method": "totp", "recovery_codes": len(codes),
	}, now.UTC()); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing TOTP confirmation: %w", err)
	}
	return codes, nil
}

func (s *Service) VerifyTOTP(ctx context.Context, userID uuid.UUID, code string, now time.Time) error {
	return s.verifyTOTP(ctx, userID, code, now, nil)
}

func (s *Service) VerifyTOTPChallenge(
	ctx context.Context,
	userID uuid.UUID,
	code string,
	now time.Time,
	gate ChallengeCommitGate,
) error {
	return s.verifyTOTP(ctx, userID, code, now, &gate)
}

func (s *Service) verifyTOTP(
	ctx context.Context,
	userID uuid.UUID,
	code string,
	now time.Time,
	gate *ChallengeCommitGate,
) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting TOTP verification: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := lockChallengeAuthenticationState(ctx, tx, userID, gate); err != nil {
		return err
	}
	var ciphertext string
	var lastUsedStep *int64
	err = tx.QueryRow(ctx, `
		SELECT secret_ciphertext,last_used_step
		FROM user_totp_credentials
		WHERE user_id=$1 AND confirmed_at IS NOT NULL
		FOR UPDATE
	`, userID).Scan(&ciphertext, &lastUsedStep)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotEnrolled
	}
	if err != nil {
		return fmt.Errorf("locking TOTP credential: %w", err)
	}
	secret, err := nyacrypto.DecryptEnvelope(s.masterKeys, totpEnvelopePurpose, ciphertext, []byte(userID.String()))
	if err != nil {
		return fmt.Errorf("decrypting TOTP secret: %w", err)
	}
	matchedStep, ok := matchTOTP(secret, code, now)
	if !ok {
		return ErrInvalidCode
	}
	if lastUsedStep != nil && matchedStep <= *lastUsedStep {
		return ErrCodeReplayed
	}
	if _, err := tx.Exec(ctx, `
		UPDATE user_totp_credentials SET last_used_step=$2,updated_at=$3 WHERE user_id=$1
	`, userID, matchedStep, now.UTC()); err != nil {
		return fmt.Errorf("recording TOTP use: %w", err)
	}
	if err := consumeChallengeBeforeCommit(ctx, gate); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing TOTP verification: %w", err)
	}
	return nil
}

func (s *Service) ConsumeRecoveryCode(ctx context.Context, userID uuid.UUID, code string, auditContext AuditContext, now time.Time) error {
	return s.consumeRecoveryCode(ctx, userID, code, auditContext, now, nil)
}

func (s *Service) ConsumeRecoveryCodeChallenge(
	ctx context.Context,
	userID uuid.UUID,
	code string,
	auditContext AuditContext,
	now time.Time,
	gate ChallengeCommitGate,
) error {
	return s.consumeRecoveryCode(ctx, userID, code, auditContext, now, &gate)
}

func (s *Service) consumeRecoveryCode(
	ctx context.Context,
	userID uuid.UUID,
	code string,
	auditContext AuditContext,
	now time.Time,
	gate *ChallengeCommitGate,
) error {
	normalized, selectorHash, ok := parseRecoveryCode(code)
	if !ok {
		return ErrInvalidCode
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting recovery-code verification: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := lockChallengeAuthenticationState(ctx, tx, userID, gate); err != nil {
		return err
	}
	var id uuid.UUID
	var codeHash string
	err = tx.QueryRow(ctx, `
		SELECT id,code_hash FROM user_recovery_codes
		WHERE user_id=$1 AND selector_hash=$2 AND used_at IS NULL
		FOR UPDATE
	`, userID, selectorHash).Scan(&id, &codeHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidCode
	}
	if err != nil {
		return fmt.Errorf("locking recovery code: %w", err)
	}
	verified, err := nyacrypto.VerifyPassword(normalized, codeHash)
	if err != nil {
		return fmt.Errorf("verifying recovery code: %w", err)
	}
	if !verified {
		return ErrInvalidCode
	}
	if _, err := tx.Exec(ctx, `UPDATE user_recovery_codes SET used_at=$2 WHERE id=$1`, id, now.UTC()); err != nil {
		return fmt.Errorf("consuming recovery code: %w", err)
	}
	if err := enqueueAudit(ctx, tx, models.AuditRecoveryCodeUsed, userID, auditContext, map[string]any{
		"recovery_code_id": id.String(),
	}, now.UTC()); err != nil {
		return err
	}
	if err := consumeChallengeBeforeCommit(ctx, gate); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing recovery-code use: %w", err)
	}
	return nil
}

func lockChallengeAuthenticationState(ctx context.Context, tx pgx.Tx, userID uuid.UUID, gate *ChallengeCommitGate) error {
	if gate == nil {
		return nil
	}
	if gate.AuthVersion <= 0 || gate.SessionVersion <= 0 || gate.Consume == nil {
		return fmt.Errorf("invalid MFA challenge commit gate")
	}
	_, err := lockAuthenticationState(ctx, tx, userID, AuthenticationBinding{
		AuthVersion: gate.AuthVersion, SessionVersion: gate.SessionVersion,
	})
	return err
}

func lockAuthenticationState(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	binding AuthenticationBinding,
) (string, error) {
	if binding.AuthVersion <= 0 || binding.SessionVersion <= 0 {
		return "", fmt.Errorf("invalid authentication binding")
	}
	var role string
	var status models.UserStatus
	var authVersion, sessionVersion int64
	err := tx.QueryRow(ctx, `
		SELECT role,status,auth_version,session_version
		FROM users
		WHERE id=$1
		FOR UPDATE
	`, userID).Scan(&role, &status, &authVersion, &sessionVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrAuthenticationChanged
	}
	if err != nil {
		return "", fmt.Errorf("locking MFA user authentication state: %w", err)
	}
	if status != models.UserStatusActive || authVersion != binding.AuthVersion || sessionVersion != binding.SessionVersion {
		return "", ErrAuthenticationChanged
	}
	return role, nil
}

func consumeChallengeBeforeCommit(ctx context.Context, gate *ChallengeCommitGate) error {
	if gate == nil {
		return nil
	}
	if err := gate.Consume(ctx); err != nil {
		return fmt.Errorf("consuming MFA pending challenge: %w", err)
	}
	return nil
}

func (s *Service) RegenerateRecoveryCodes(
	ctx context.Context,
	userID uuid.UUID,
	binding AuthenticationBinding,
	auditContext AuditContext,
	now time.Time,
) ([]string, error) {
	codes, records, err := generateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting recovery-code regeneration: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := lockAuthenticationState(ctx, tx, userID, binding); err != nil {
		return nil, err
	}
	var credentialUserID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT user_id FROM user_totp_credentials
		WHERE user_id=$1 AND confirmed_at IS NOT NULL
		FOR UPDATE
	`, userID).Scan(&credentialUserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, fmt.Errorf("locking TOTP credential for recovery-code regeneration: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_recovery_codes WHERE user_id=$1`, userID); err != nil {
		return nil, fmt.Errorf("replacing recovery codes: %w", err)
	}
	if err := insertRecoveryCodes(ctx, tx, userID, records, now.UTC()); err != nil {
		return nil, err
	}
	if err := enqueueAudit(ctx, tx, models.AuditRecoveryCodesGenerated, userID, auditContext, map[string]any{
		"recovery_codes": len(codes),
	}, now.UTC()); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing recovery-code regeneration: %w", err)
	}
	return codes, nil
}

func (s *Service) Disable(
	ctx context.Context,
	userID uuid.UUID,
	binding AuthenticationBinding,
	auditContext AuditContext,
	now time.Time,
) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting TOTP disable: %w", err)
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
	if security.RequireMFAForAdmins && role == "admin" {
		rpID := ""
		if s.passkeys != nil {
			rpID = s.passkeys.rpID
		}
		var hasPasskey bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM user_passkey_credentials
				WHERE user_id=$1 AND ($2='' OR rp_id=$2)
			)
		`, userID, rpID).Scan(&hasPasskey); err != nil {
			return fmt.Errorf("checking administrator Passkey enrollment: %w", err)
		}
		if !hasPasskey {
			return ErrRequiredByPolicy
		}
	}
	result, err := tx.Exec(ctx, `DELETE FROM user_totp_credentials WHERE user_id=$1 AND confirmed_at IS NOT NULL`, userID)
	if err != nil {
		return fmt.Errorf("disabling TOTP: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotEnrolled
	}
	if err := incrementAuthVersion(ctx, tx, userID, now.UTC()); err != nil {
		return err
	}
	if err := enqueueAudit(ctx, tx, models.AuditMFADisabled, userID, auditContext, map[string]any{
		"method": "totp",
	}, now.UTC()); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing TOTP disable: %w", err)
	}
	return nil
}

func insertRecoveryCodes(ctx context.Context, tx pgx.Tx, userID uuid.UUID, records []recoveryCodeRecord, now time.Time) error {
	batch := &pgx.Batch{}
	for _, record := range records {
		batch.Queue(`
			INSERT INTO user_recovery_codes (id,user_id,selector_hash,code_hash,created_at)
			VALUES ($1,$2,$3,$4,$5)
		`, uuid.New(), userID, record.selectorHash, record.codeHash, now.UTC())
	}
	results := tx.SendBatch(ctx, batch)
	for range records {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return fmt.Errorf("storing recovery codes: %w", err)
		}
	}
	if err := results.Close(); err != nil {
		return fmt.Errorf("storing recovery codes: %w", err)
	}
	return nil
}

func incrementAuthVersion(ctx context.Context, tx pgx.Tx, userID uuid.UUID, now time.Time) error {
	result, err := tx.Exec(ctx, `
		UPDATE users SET auth_version=auth_version+1,updated_at=$2 WHERE id=$1
	`, userID, now.UTC())
	if err != nil {
		return fmt.Errorf("advancing user authentication version: %w", err)
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func enqueueAudit(ctx context.Context, tx pgx.Tx, event string, userID uuid.UUID, auditContext AuditContext, details map[string]any, now time.Time) error {
	actorID := auditContext.ActorID
	if actorID == uuid.Nil {
		actorID = userID
	}
	if err := audit.EnqueueTargetResultTx(
		ctx, tx, event, &actorID, auditContext.ActorName, "user", userID.String(),
		"success", "high", auditContext.IPAddress, auditContext.UserAgent, details, now.UTC(),
	); err != nil {
		return fmt.Errorf("auditing %s: %w", event, err)
	}
	return nil
}
