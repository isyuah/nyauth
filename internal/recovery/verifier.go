package recovery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/auth"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/mfa"
	"github.com/nyasharp/nyauth/internal/provider"
)

const emailEnvelopeSampleLimit = 100

// ResourceCounts is deliberately limited to non-sensitive aggregate evidence.
type ResourceCounts struct {
	Users          int64 `json:"users"`
	OAuthClients   int64 `json:"oauth_clients"`
	OAuthProviders int64 `json:"oauth_providers"`
	JWKKeys        int64 `json:"jwk_keys"`
	AuditLogs      int64 `json:"audit_logs"`
	EmailOutbox    int64 `json:"email_outbox"`
}

// Report is emitted by the read-only recovery verifier. It never contains
// decrypted payloads, provider credentials, email recipients, or private keys.
type Report struct {
	SchemaVersion             int64          `json:"schema_version"`
	SchemaDirty               bool           `json:"schema_dirty"`
	Counts                    ResourceCounts `json:"counts"`
	SigningKeyID              string         `json:"signing_key_id"`
	JWKEnvelopeVerified       bool           `json:"jwk_envelope_verified"`
	ProviderEnvelopesVerified int64          `json:"provider_envelopes_verified"`
	TOTPEnvelopesVerified     int64          `json:"totp_envelopes_verified"`
	EmailEnvelopeRows         int64          `json:"email_envelope_rows"`
	EmailEnvelopeSampled      int64          `json:"email_envelopes_sampled"`
	EmailEnvelopeSampleLimit  int            `json:"email_envelope_sample_limit"`
}

// Verify authenticates restored encrypted state and collects aggregate counts.
// It performs no writes and makes no provider or SMTP network requests.
func Verify(ctx context.Context, db *pgxpool.Pool, masterKey []byte) (Report, error) {
	report := Report{EmailEnvelopeSampleLimit: emailEnvelopeSampleLimit}
	if db == nil {
		return report, errors.New("recovery database is required")
	}
	if len(masterKey) != 32 {
		return report, errors.New("recovery master key must contain exactly 32 bytes")
	}
	if err := database.ValidateSchemaVersion(ctx, db); err != nil {
		return report, fmt.Errorf("validating recovered schema: %w", err)
	}
	if err := db.QueryRow(ctx, `SELECT version,dirty FROM schema_migrations LIMIT 1`).Scan(&report.SchemaVersion, &report.SchemaDirty); err != nil {
		return report, fmt.Errorf("reading recovered schema version: %w", err)
	}
	if report.SchemaDirty {
		return report, errors.New("recovered schema is dirty")
	}
	if err := db.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM users),
			(SELECT COUNT(*) FROM oauth_clients),
			(SELECT COUNT(*) FROM oauth_providers),
			(SELECT COUNT(*) FROM jwk_keys),
			(SELECT COUNT(*) FROM audit_logs),
			(SELECT COUNT(*) FROM email_outbox)
	`).Scan(
		&report.Counts.Users,
		&report.Counts.OAuthClients,
		&report.Counts.OAuthProviders,
		&report.Counts.JWKKeys,
		&report.Counts.AuditLogs,
		&report.Counts.EmailOutbox,
	); err != nil {
		return report, fmt.Errorf("counting recovered resources: %w", err)
	}

	jwkManager := auth.NewJWKManager(db, 2048, 24*time.Hour)
	if err := jwkManager.Configure(masterKey, 24*time.Hour); err != nil {
		return report, fmt.Errorf("configuring recovered JWK verification: %w", err)
	}
	if _, kid, err := jwkManager.GetPrivateKey(ctx); err != nil {
		return report, fmt.Errorf("verifying recovered signing-key envelope: %w", err)
	} else {
		report.SigningKeyID = kid
		report.JWKEnvelopeVerified = true
	}

	providerManager := provider.NewManager(db, masterKey)
	verifiedProviders, err := providerManager.VerifyStoredSecrets(ctx)
	if err != nil {
		return report, err
	}
	if verifiedProviders != report.Counts.OAuthProviders {
		return report, fmt.Errorf("verified provider envelope count %d does not match provider count %d", verifiedProviders, report.Counts.OAuthProviders)
	}
	report.ProviderEnvelopesVerified = verifiedProviders

	mfaService, err := mfa.NewService(db, mfa.Options{
		ActiveKeyID: "primary", MasterKeys: map[string][]byte{"primary": masterKey},
	})
	if err != nil {
		return report, fmt.Errorf("configuring recovered TOTP verification: %w", err)
	}
	verifiedTOTP, err := mfaService.VerifyStoredSecrets(ctx)
	if err != nil {
		return report, err
	}
	report.TOTPEnvelopesVerified = verifiedTOTP

	if err := verifyEmailEnvelopes(ctx, db, masterKey, &report); err != nil {
		return report, err
	}
	return report, nil
}

func verifyEmailEnvelopes(ctx context.Context, db *pgxpool.Pool, masterKey []byte, report *Report) error {
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM email_outbox WHERE encrypted_message <> ''`).Scan(&report.EmailEnvelopeRows); err != nil {
		return fmt.Errorf("counting recoverable email envelopes: %w", err)
	}
	rows, err := db.Query(ctx, `
		SELECT id,user_id,message_type,encrypted_message
		FROM email_outbox
		WHERE encrypted_message <> ''
		ORDER BY created_at DESC,id
		LIMIT $1
	`, emailEnvelopeSampleLimit)
	if err != nil {
		return fmt.Errorf("querying recoverable email envelopes: %w", err)
	}
	defer rows.Close()

	keyring := map[string][]byte{"primary": append([]byte(nil), masterKey...)}
	for rows.Next() {
		var item account.OutboxEmail
		var userID uuid.UUID
		if err := rows.Scan(&item.ID, &userID, &item.MessageType, &item.EncryptedMessage); err != nil {
			return fmt.Errorf("scanning email envelope evidence: %w", err)
		}
		item.UserID = &userID
		if err := account.VerifyOutboxEnvelope(keyring, item); err != nil {
			return fmt.Errorf("verifying email envelope %s: %w", item.ID, err)
		}
		report.EmailEnvelopeSampled++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating email envelope evidence: %w", err)
	}
	return nil
}
