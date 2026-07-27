package mfa

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

type passkeyQueryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type passkeyRow struct {
	ID             uuid.UUID
	RPID           string
	UserID         uuid.UUID
	CredentialID   []byte
	Ciphertext     string
	Name           string
	Transports     []string
	AAGUID         []byte
	SignCount      int64
	CloneWarning   bool
	Attachment     string
	BackupEligible bool
	BackupState    bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUsedAt     *time.Time
	Credential     gowebauthn.Credential
}

func (s *Service) loadOrCreatePasskeyUser(ctx context.Context, current *models.User) (*passkeyUser, error) {
	if current == nil || current.ID == uuid.Nil {
		return nil, ErrPasskeyNotFound
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting Passkey user-handle transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockSecurityShared(ctx, tx); err != nil {
		return nil, err
	}
	security, err := settings.LoadSecurityTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	if !security.PasskeysEnabled {
		return nil, ErrPasskeysDisabled
	}
	handle, err := ensurePasskeyHandleTx(ctx, tx, s.passkeys.rpID, current.ID)
	if err != nil {
		return nil, err
	}
	user, err := s.loadPasskeyUserWithHandle(ctx, tx, current, handle, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing Passkey user handle: %w", err)
	}
	return user, nil
}

func (s *Service) loadPasskeyUser(ctx context.Context, current *models.User) (*passkeyUser, error) {
	if current == nil || current.ID == uuid.Nil {
		return nil, ErrPasskeyNotFound
	}
	var handle []byte
	if err := s.db.QueryRow(ctx, `
		SELECT user_handle FROM user_passkey_handles WHERE rp_id=$1 AND user_id=$2
	`, s.passkeys.rpID, current.ID).Scan(&handle); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPasskeyNotFound
	} else if err != nil {
		return nil, fmt.Errorf("loading Passkey user handle: %w", err)
	}
	return s.loadPasskeyUserWithHandle(ctx, s.db, current, handle, false)
}

func ensurePasskeyHandleTx(ctx context.Context, tx pgx.Tx, rpID string, userID uuid.UUID) ([]byte, error) {
	handle := make([]byte, passkeyUserHandleLength)
	if _, err := rand.Read(handle); err != nil {
		return nil, fmt.Errorf("generating Passkey user handle: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_passkey_handles (rp_id,user_id,user_handle)
		VALUES ($1,$2,$3)
		ON CONFLICT (rp_id,user_id) DO NOTHING
	`, rpID, userID, handle); err != nil {
		return nil, fmt.Errorf("storing Passkey user handle: %w", err)
	}
	if err := tx.QueryRow(ctx, `
		SELECT user_handle FROM user_passkey_handles WHERE rp_id=$1 AND user_id=$2 FOR UPDATE
	`, rpID, userID).Scan(&handle); err != nil {
		return nil, fmt.Errorf("locking Passkey user handle: %w", err)
	}
	return handle, nil
}

func (s *Service) loadPasskeyUserWithHandle(
	ctx context.Context,
	queryer passkeyQueryer,
	current *models.User,
	handle []byte,
	forUpdate bool,
) (*passkeyUser, error) {
	rows, err := s.loadPasskeyRows(ctx, queryer, current.ID, forUpdate)
	if err != nil {
		return nil, err
	}
	displayName := ""
	if current.DisplayName != nil {
		displayName = *current.DisplayName
	}
	user := &passkeyUser{
		id: current.ID, handle: append([]byte(nil), handle...), username: current.Username,
		displayName: displayName, credentials: make([]gowebauthn.Credential, 0, len(rows)),
		rows: make(map[string]passkeyRow, len(rows)), authVersion: current.AuthVersion,
		sessionVersion: current.SessionVersion,
	}
	for _, row := range rows {
		user.credentials = append(user.credentials, row.Credential)
		user.rows[string(row.CredentialID)] = row
	}
	return user, nil
}

func (s *Service) loadPasskeyRows(ctx context.Context, queryer passkeyQueryer, userID uuid.UUID, forUpdate bool) ([]passkeyRow, error) {
	query := `
		SELECT id,rp_id,user_id,credential_id,credential_ciphertext,name,transports,aaguid,
		       sign_count,clone_warning,attachment,backup_eligible,backup_state,
		       created_at,updated_at,last_used_at
		FROM user_passkey_credentials
		WHERE rp_id=$1 AND user_id=$2
		ORDER BY created_at,id
	`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	rows, err := queryer.Query(ctx, query, s.passkeys.rpID, userID)
	if err != nil {
		return nil, fmt.Errorf("loading Passkey credentials: %w", err)
	}
	defer rows.Close()
	result := make([]passkeyRow, 0)
	for rows.Next() {
		var row passkeyRow
		if err := rows.Scan(
			&row.ID, &row.RPID, &row.UserID, &row.CredentialID, &row.Ciphertext, &row.Name,
			&row.Transports, &row.AAGUID, &row.SignCount, &row.CloneWarning,
			&row.Attachment, &row.BackupEligible, &row.BackupState,
			&row.CreatedAt, &row.UpdatedAt, &row.LastUsedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning Passkey credential: %w", err)
		}
		credential, err := s.decryptPasskeyCredential(row)
		if err != nil {
			return nil, err
		}
		row.Credential = credential
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating Passkey credentials: %w", err)
	}
	return result, nil
}

func (s *Service) decryptPasskeyCredential(row passkeyRow) (gowebauthn.Credential, error) {
	plaintext, err := crypto.DecryptEnvelope(
		s.masterKeys, passkeyEnvelopePurpose, row.Ciphertext,
		passkeyAAD(row.RPID, row.ID, row.UserID, row.CredentialID),
	)
	if err != nil {
		return gowebauthn.Credential{}, fmt.Errorf("decrypting Passkey credential: %w", err)
	}
	var credential gowebauthn.Credential
	remainder, err := credential.UnmarshalMsg(plaintext)
	if err != nil {
		return gowebauthn.Credential{}, fmt.Errorf("decoding Passkey credential: %w", err)
	}
	if len(remainder) != 0 {
		return gowebauthn.Credential{}, fmt.Errorf("decoding Passkey credential: trailing data")
	}
	if !bytes.Equal(credential.ID, row.CredentialID) {
		return gowebauthn.Credential{}, fmt.Errorf("Passkey credential ID does not match encrypted record")
	}
	return credential, nil
}

func (s *Service) encryptPasskeyCredential(rowID, userID uuid.UUID, credential *gowebauthn.Credential) (string, error) {
	if credential == nil || len(credential.ID) == 0 {
		return "", ErrInvalidPasskey
	}
	encoded, err := credential.MarshalMsg(nil)
	if err != nil {
		return "", fmt.Errorf("encoding Passkey credential: %w", err)
	}
	encrypted, err := crypto.EncryptEnvelope(
		s.masterKeys[s.activeKeyID], s.activeKeyID, passkeyEnvelopePurpose, encoded,
		passkeyAAD(s.passkeys.rpID, rowID, userID, credential.ID),
	)
	if err != nil {
		return "", fmt.Errorf("encrypting Passkey credential: %w", err)
	}
	return encrypted, nil
}

func passkeyAAD(rpID string, rowID, userID uuid.UUID, credentialID []byte) []byte {
	value := make([]byte, 0, len(rpID)+1+16+16+1+len(credentialID))
	value = append(value, rpID...)
	value = append(value, 0)
	value = append(value, rowID[:]...)
	value = append(value, userID[:]...)
	value = append(value, 0)
	value = append(value, credentialID...)
	return value
}

func passkeyTransports(credential *gowebauthn.Credential) []string {
	result := make([]string, len(credential.Transport))
	for index, transport := range credential.Transport {
		result[index] = string(transport)
	}
	return result
}

func passkeyAAGUIDValue(credential *gowebauthn.Credential) any {
	if len(credential.Authenticator.AAGUID) == 0 {
		return nil
	}
	return credential.Authenticator.AAGUID
}

func passkeyAAGUIDDisplay(value []byte) string {
	if len(value) != 16 {
		return ""
	}
	parsed, err := uuid.FromBytes(value)
	if err != nil {
		return ""
	}
	return parsed.String()
}

func passkeyModel(row passkeyRow) PasskeyCredential {
	transports := append([]string(nil), row.Transports...)
	if transports == nil {
		transports = []string{}
	}
	return PasskeyCredential{
		ID: row.ID, Name: row.Name, Transports: transports, AAGUID: passkeyAAGUIDDisplay(row.AAGUID),
		Attachment: row.Attachment, BackupEligible: row.BackupEligible, BackupState: row.BackupState,
		CloneWarning: row.CloneWarning, CreatedAt: row.CreatedAt.UTC(), LastUsedAt: row.LastUsedAt,
	}
}

func (s *Service) ListPasskeys(ctx context.Context, userID uuid.UUID) ([]PasskeyCredential, error) {
	rows, err := s.loadPasskeyRows(ctx, s.db, userID, false)
	if err != nil {
		return nil, err
	}
	result := make([]PasskeyCredential, len(rows))
	for index, row := range rows {
		result[index] = passkeyModel(row)
	}
	return result, nil
}

func (s *Service) VerifyStoredPasskeys(ctx context.Context) (int64, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id,rp_id,user_id,credential_id,credential_ciphertext
		FROM user_passkey_credentials
		ORDER BY rp_id,user_id,id
	`)
	if err != nil {
		return 0, fmt.Errorf("querying stored Passkey envelopes: %w", err)
	}
	defer rows.Close()
	var verified int64
	for rows.Next() {
		var row passkeyRow
		if err := rows.Scan(&row.ID, &row.RPID, &row.UserID, &row.CredentialID, &row.Ciphertext); err != nil {
			return 0, fmt.Errorf("scanning stored Passkey envelope: %w", err)
		}
		if _, err := s.decryptPasskeyCredential(row); err != nil {
			return 0, fmt.Errorf("verifying stored Passkey envelope: %w", err)
		}
		verified++
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterating stored Passkey envelopes: %w", err)
	}
	return verified, nil
}
