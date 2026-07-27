package database_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/auth"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/mfa"
	"github.com/nyasharp/nyauth/internal/provider"
	"github.com/nyasharp/nyauth/internal/recovery"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestRecoveryVerifierAuthenticatesRestoredEnvelopes(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	masterKey := []byte("0123456789abcdef0123456789abcdef")

	userID := uuid.New()
	email := "recovery@example.test"
	verifiedAt := time.Now().UTC()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,email,email_verified_at,status,role)
		VALUES ($1,$2,$3,$4,'active','admin')
	`, userID, "recovery-admin", email, verifiedAt); err != nil {
		t.Fatalf("insert recovery user: %v", err)
	}

	jwkManager := auth.NewJWKManager(schema.pool, 2048, 24*time.Hour)
	if err := jwkManager.Configure(masterKey, 24*time.Hour); err != nil {
		t.Fatalf("Configure JWK manager: %v", err)
	}
	if err := jwkManager.EnsureActiveKey(ctx); err != nil {
		t.Fatalf("EnsureActiveKey: %v", err)
	}

	providerManager := provider.NewManager(schema.pool, masterKey)
	encryptedProviderSecret, err := providerManager.EncryptSecret("recovery-github", "restored-provider-secret")
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO oauth_providers (name,type,client_id,client_secret,scopes,enabled)
		VALUES ('recovery-github','github','recovery-client',$1,ARRAY['read:user'],FALSE)
	`, encryptedProviderSecret); err != nil {
		t.Fatalf("insert recovery provider: %v", err)
	}

	mfaService, err := mfa.NewService(schema.pool, mfa.Options{
		ActiveKeyID: "primary", MasterKeys: map[string][]byte{"primary": masterKey},
	})
	if err != nil {
		t.Fatalf("New MFA service: %v", err)
	}
	if _, err := mfaService.BeginEnrollment(ctx, userID, "Nyauth Recovery", "recovery-admin", time.Now().UTC()); err != nil {
		t.Fatalf("store recovery TOTP envelope: %v", err)
	}
	var originalTOTPCiphertext string
	if err := schema.pool.QueryRow(ctx, `SELECT secret_ciphertext FROM user_totp_credentials WHERE user_id=$1`, userID).Scan(&originalTOTPCiphertext); err != nil {
		t.Fatalf("read recovery TOTP envelope: %v", err)
	}

	accountService, err := account.NewService(account.NewStore(schema.pool), account.ServiceOptions{
		PublicBaseURL: "https://auth.example.test",
		ActiveKeyID:   "primary",
		MasterKeys:    map[string][]byte{"primary": masterKey},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	user := &models.User{ID: userID, Email: &email, EmailVerifiedAt: &verifiedAt}
	outbox, err := accountService.BuildSecurityNotification(user, account.SecurityNotice{MessageType: account.MessagePasswordChanged})
	if err != nil {
		t.Fatalf("BuildSecurityNotification: %v", err)
	}
	if outbox == nil {
		t.Fatal("BuildSecurityNotification returned no encrypted email")
	}
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO email_outbox (
			id,user_id,message_type,recipient_hash,encrypted_message,status,
			attempt_count,available_at,expires_at,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,'pending',0,$6,$7,$8,$8)
	`, outbox.ID, userID, outbox.MessageType, outbox.RecipientHash, outbox.EncryptedMessage,
		outbox.AvailableAt, outbox.ExpiresAt, outbox.CreatedAt); err != nil {
		t.Fatalf("insert recovery email: %v", err)
	}

	report, err := recovery.Verify(ctx, schema.pool, masterKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.JWKEnvelopeVerified || report.ProviderEnvelopesVerified != 1 || report.TOTPEnvelopesVerified != 1 || report.EmailEnvelopeSampled != 1 {
		t.Fatalf("unexpected envelope report: %#v", report)
	}
	if report.Counts.Users != 1 || report.Counts.OAuthProviders != 1 || report.Counts.EmailOutbox != 1 {
		t.Fatalf("unexpected resource counts: %#v", report.Counts)
	}

	if _, err := schema.pool.Exec(ctx, `UPDATE user_totp_credentials SET secret_ciphertext=secret_ciphertext || 'x' WHERE user_id=$1`, userID); err != nil {
		t.Fatalf("tamper recovery TOTP envelope: %v", err)
	}
	if _, err := recovery.Verify(ctx, schema.pool, masterKey); err == nil || !strings.Contains(err.Error(), "TOTP envelope") {
		t.Fatalf("Verify(tampered TOTP) error = %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `UPDATE user_totp_credentials SET secret_ciphertext=$2 WHERE user_id=$1`, userID, originalTOTPCiphertext); err != nil {
		t.Fatalf("restore recovery TOTP envelope: %v", err)
	}

	if _, err := schema.pool.Exec(ctx, `UPDATE email_outbox SET encrypted_message=encrypted_message || 'x' WHERE id=$1`, outbox.ID); err != nil {
		t.Fatalf("tamper recovery email: %v", err)
	}
	if _, err := recovery.Verify(ctx, schema.pool, masterKey); err == nil || !strings.Contains(err.Error(), "email envelope") {
		t.Fatalf("Verify(tampered email) error = %v", err)
	}
}
