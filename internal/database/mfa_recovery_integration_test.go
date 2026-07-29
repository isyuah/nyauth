package database_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/mfa"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestMFARecoveryResetIsAtomicAuditedAndPolicyAware(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run MFA recovery migrations: %v", err)
	}
	ctx := context.Background()
	admin := registrationTestUser("recovery-admin", models.UserStatusActive)
	admin.Role = "admin"
	insertRegistrationTestUser(t, schema, admin)
	passkeyID := insertMFARecoveryFactors(t, schema, admin.ID)
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO runtime_settings (key,value,revision,updated_by)
		VALUES ('security',$1,4,'integration setup')
	`, `{"totp_enabled":true,"passkeys_enabled":true,"require_mfa_for_admins":true}`); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	input := mfa.RecoveryResetInput{
		Username: admin.Username, Scope: mfa.RecoveryResetAll,
		Reason:    "administrator lost every registered authenticator",
		ActorName: "integration recovery CLI", Now: now,
	}
	if _, err := mfa.ResetForRecovery(ctx, schema.pool, input); !errors.Is(err, mfa.ErrRecoveryAdminPolicyConflict) {
		t.Fatalf("reset without policy override error = %v", err)
	}
	assertMFARecoveryCounts(t, schema, admin.ID, 1, 1, 1, 1)
	var unchangedAuthVersion int64
	if err := schema.pool.QueryRow(ctx, `SELECT auth_version FROM users WHERE id=$1`, admin.ID).Scan(&unchangedAuthVersion); err != nil || unchangedAuthVersion != 1 {
		t.Fatalf("auth version after rejected reset = %d, err=%v", unchangedAuthVersion, err)
	}

	input.DisableAdminMFARequirement = true
	report, err := mfa.ResetForRecovery(ctx, schema.pool, input)
	if err != nil {
		t.Fatalf("reset with policy override: %v", err)
	}
	if report.UserID != admin.ID || report.Username != admin.Username || report.Scope != mfa.RecoveryResetAll {
		t.Fatalf("unexpected recovery report target: %#v", report)
	}
	if report.RemovedTOTPCredentials != 1 || report.RemovedRecoveryCodes != 1 || report.RemovedPasskeys != 1 || report.PreservedPasskeyHandles != 1 {
		t.Fatalf("unexpected recovery report counts: %#v", report)
	}
	if report.AuthVersion != 2 || report.SessionVersion != 1 || !report.AdminMFARequirementDisabled || report.SecurityRevision != 5 {
		t.Fatalf("unexpected recovery report state: %#v", report)
	}
	assertMFARecoveryCounts(t, schema, admin.ID, 0, 0, 0, 1)

	var securityJSON []byte
	var securityRevision int64
	if err := schema.pool.QueryRow(ctx, `SELECT value,revision FROM runtime_settings WHERE key='security'`).Scan(&securityJSON, &securityRevision); err != nil {
		t.Fatal(err)
	}
	var security map[string]any
	if err := json.Unmarshal(securityJSON, &security); err != nil {
		t.Fatal(err)
	}
	if security["require_mfa_for_admins"] != false || securityRevision != 5 {
		t.Fatalf("security after recovery = %#v revision=%d", security, securityRevision)
	}
	var resetAudits, settingsAudits int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_event_outbox WHERE event=$1 AND aggregate_id=$2`, models.AuditMFARecoveryReset, admin.ID.String()).Scan(&resetAudits); err != nil {
		t.Fatal(err)
	}
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_event_outbox WHERE event=$1 AND aggregate_id='security'`, models.AuditSettingsUpdated).Scan(&settingsAudits); err != nil {
		t.Fatal(err)
	}
	if resetAudits != 1 || settingsAudits != 1 {
		t.Fatalf("recovery audits reset=%d settings=%d", resetAudits, settingsAudits)
	}
	var revokedAuthVersion, revokedSessionVersion int64
	if err := schema.pool.QueryRow(ctx, `SELECT auth_version,session_version FROM security_revocation_outbox WHERE user_id=$1`, admin.ID).Scan(&revokedAuthVersion, &revokedSessionVersion); err != nil {
		t.Fatal(err)
	}
	if revokedAuthVersion != 2 || revokedSessionVersion != 1 {
		t.Fatalf("security revocation versions = %d/%d", revokedAuthVersion, revokedSessionVersion)
	}
	var removedTarget string
	if err := schema.pool.QueryRow(ctx, `SELECT payload->>'target_id' FROM audit_event_outbox WHERE event=$1`, models.AuditMFARecoveryReset).Scan(&removedTarget); err != nil {
		t.Fatal(err)
	}
	if removedTarget != admin.ID.String() || passkeyID == uuid.Nil {
		t.Fatalf("audit target=%q passkey=%s", removedTarget, passkeyID)
	}
}

func TestMFARecoveryResetRefusesToRemoveLastPrimaryMethod(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run MFA recovery migrations: %v", err)
	}
	user := registrationTestUser("passkey-only-recovery", models.UserStatusActive)
	insertRegistrationTestUser(t, schema, user)
	if _, err := schema.pool.Exec(context.Background(), `
		UPDATE users SET password_hash=NULL,password_changed_at=NULL WHERE id=$1
	`, user.ID); err != nil {
		t.Fatal(err)
	}
	insertMFARecoveryPasskey(t, schema, user.ID)

	_, err := mfa.ResetForRecovery(context.Background(), schema.pool, mfa.RecoveryResetInput{
		UserID: user.ID, Scope: mfa.RecoveryResetPasskeys,
		Reason: "lost only authenticator", ActorName: "integration recovery CLI",
	})
	if !errors.Is(err, mfa.ErrRecoveryPrimaryMethodNeeded) {
		t.Fatalf("last primary method reset error = %v", err)
	}
	assertMFARecoveryCounts(t, schema, user.ID, 0, 0, 1, 1)
}

func insertMFARecoveryFactors(t *testing.T, schema *postgresTestSchema, userID uuid.UUID) uuid.UUID {
	t.Helper()
	now := time.Now().UTC()
	if _, err := schema.pool.Exec(context.Background(), `
		INSERT INTO user_totp_credentials (user_id,secret_ciphertext,confirmed_at,created_at,updated_at)
		VALUES ($1,'integration-totp-envelope',$2,$2,$2)
	`, userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := schema.pool.Exec(context.Background(), `
		INSERT INTO user_recovery_codes (user_id,selector_hash,code_hash,created_at)
		VALUES ($1,$2,'integration-recovery-hash',$3)
	`, userID, bytes.Repeat([]byte{0x42}, 32), now); err != nil {
		t.Fatal(err)
	}
	return insertMFARecoveryPasskey(t, schema, userID)
}

func insertMFARecoveryPasskey(t *testing.T, schema *postgresTestSchema, userID uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO user_passkey_handles (rp_id,user_id,user_handle,created_at)
		VALUES ('auth.example.test',$1,$2,$3)
	`, userID, bytes.Repeat([]byte{0x24}, 32), now); err != nil {
		t.Fatal(err)
	}
	passkeyID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO user_passkey_credentials (
			id,rp_id,user_id,credential_id,credential_ciphertext,name,created_at,updated_at
		) VALUES ($1,'auth.example.test',$2,$3,'integration-passkey-envelope','Recovery test key',$4,$4)
	`, passkeyID, userID, []byte("integration-recovery-passkey"), now); err != nil {
		t.Fatal(err)
	}
	return passkeyID
}

func assertMFARecoveryCounts(
	t *testing.T,
	schema *postgresTestSchema,
	userID uuid.UUID,
	wantTOTP, wantRecovery, wantPasskeys, wantHandles int,
) {
	t.Helper()
	var totp, recovery, passkeys, handles int
	if err := schema.pool.QueryRow(context.Background(), `
		SELECT
			(SELECT COUNT(*) FROM user_totp_credentials WHERE user_id=$1),
			(SELECT COUNT(*) FROM user_recovery_codes WHERE user_id=$1),
			(SELECT COUNT(*) FROM user_passkey_credentials WHERE user_id=$1),
			(SELECT COUNT(*) FROM user_passkey_handles WHERE user_id=$1)
	`, userID).Scan(&totp, &recovery, &passkeys, &handles); err != nil {
		t.Fatal(err)
	}
	if totp != wantTOTP || recovery != wantRecovery || passkeys != wantPasskeys || handles != wantHandles {
		t.Fatalf("MFA counts = totp:%d recovery:%d passkeys:%d handles:%d", totp, recovery, passkeys, handles)
	}
}
