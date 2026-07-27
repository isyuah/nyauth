package database_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/identity"
	"github.com/nyasharp/nyauth/internal/mfa"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestPasskeyPoliciesAreScopedToCurrentRelyingParty(t *testing.T) {
	const otherRPID = "old-auth.example.test"

	t.Run("login methods ignore another RP", func(t *testing.T) {
		schema := newPasskeyTestSchema(t)
		current := registrationTestUser("passkey-rp-login", models.UserStatusActive)
		insertRegistrationTestUser(t, schema, current)
		insertSyntheticPasskey(t, schema, otherRPID, current.ID, []byte("other-rp-login-key"), "Old issuer")
		service := newPasskeyTestService(t, schema, passkeyTestRPID)

		status, err := service.Status(context.Background(), current.ID)
		if err != nil || status.PasskeysEnrolled != 0 {
			t.Fatalf("current-RP MFA status=%#v err=%v", status, err)
		}
		methods, err := service.LoginMethods(context.Background(), current.ID)
		if err != nil {
			t.Fatalf("load login methods: %v", err)
		}
		for _, method := range methods {
			if method == "passkey" {
				t.Fatalf("other-RP credential enabled current-RP Passkey login: %v", methods)
			}
		}
		if _, err := service.BeginKnownPasskeyAuthentication(context.Background(), current); !errors.Is(err, mfa.ErrPasskeyNotFound) {
			t.Fatalf("begin current-RP authentication with only another-RP credential: %v", err)
		}
	})

	t.Run("administrator policy ignores another RP", func(t *testing.T) {
		schema := newPasskeyTestSchema(t)
		admin := registrationTestUser("passkey-rp-policy", models.UserStatusActive)
		admin.Role = "admin"
		insertRegistrationTestUser(t, schema, admin)
		insertSyntheticPasskey(t, schema, otherRPID, admin.ID, []byte("other-rp-admin-key"), "Old issuer")
		manager := settings.NewManagerForRP(schema.pool, settings.Branding{Title: "Nyauth Test"}, passkeyTestRPID)
		security := settings.DefaultSecurity()
		security.RequireMFAForAdmins = true

		err := manager.SetSecurity(context.Background(), security, admin.Username, mfaSecuritySettingsMutation(admin))
		var missing *settings.AdminsMissingMFAError
		if !errors.As(err, &missing) || len(missing.Usernames) != 1 || missing.Usernames[0] != admin.Username {
			t.Fatalf("other-RP credential satisfied administrator MFA policy: err=%v missing=%#v", err, missing)
		}

		insertSyntheticPasskey(t, schema, passkeyTestRPID, admin.ID, []byte("current-rp-admin-key"), "Current issuer")
		if err := manager.SetSecurity(context.Background(), security, admin.Username, mfaSecuritySettingsMutation(admin)); err != nil {
			t.Fatalf("current-RP credential did not satisfy administrator MFA policy: %v", err)
		}
	})

	t.Run("administrator promotion ignores another RP", func(t *testing.T) {
		schema := newPasskeyTestSchema(t)
		candidate := registrationTestUser("passkey-rp-promotion", models.UserStatusActive)
		insertRegistrationTestUser(t, schema, candidate)
		insertSyntheticPasskey(t, schema, otherRPID, candidate.ID, []byte("other-rp-promotion-key"), "Old issuer")
		if _, err := schema.pool.Exec(context.Background(), `
			INSERT INTO runtime_settings (key,value,updated_by)
			VALUES ('security','{"totp_enabled":true,"passkeys_enabled":true,"require_mfa_for_admins":true}'::jsonb,'test')
			ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value,updated_by=EXCLUDED.updated_by
		`); err != nil {
			t.Fatalf("enable administrator MFA policy: %v", err)
		}
		role := "admin"
		mutation := audit.MutationAudit{
			Event: models.AuditUserRoleChanged, ActorID: uuid.New(), ActorName: "policy-admin",
			Result: "success", RiskLevel: "high",
		}
		_, err := user.NewService(user.NewStoreForRP(schema.pool, passkeyTestRPID)).AdminUpdate(
			context.Background(), candidate.ID, models.AdminUpdateUserRequest{Role: &role}, mutation,
		)
		if !errors.Is(err, user.ErrAdminMFARequired) {
			t.Fatalf("other-RP credential allowed administrator promotion: %v", err)
		}
	})

	t.Run("last provider identity ignores another RP", func(t *testing.T) {
		schema := newPasskeyTestSchema(t)
		current := registrationTestUser("passkey-rp-provider", models.UserStatusActive)
		insertRegistrationTestUser(t, schema, current)
		clearPasskeyTestPassword(t, schema, current)
		identityID := uuid.New()
		if _, err := schema.pool.Exec(context.Background(), `
			INSERT INTO identities (id,user_id,provider,external_id,metadata)
			VALUES ($1,$2,'oidc','external-user','{}'::jsonb)
		`, identityID, current.ID); err != nil {
			t.Fatalf("insert provider identity: %v", err)
		}
		insertSyntheticPasskey(t, schema, otherRPID, current.ID, []byte("other-rp-provider-key"), "Old issuer")
		mutation := audit.MutationAudit{
			Event: models.AuditIdentityUnbound, ActorID: current.ID, ActorName: current.Username,
			Result: "success", RiskLevel: "high",
		}
		err := identity.NewStoreForRP(schema.pool, passkeyTestRPID).DeleteOwned(
			context.Background(), current.ID, identityID, mutation,
		)
		if !errors.Is(err, identity.ErrLastAuthenticationMethod) {
			t.Fatalf("other-RP credential allowed removal of last current login method: %v", err)
		}
	})
}

func TestPasskeyDeletionMaintainsAuthenticationAndAdministratorInvariants(t *testing.T) {
	t.Run("successful removal advances authentication version", func(t *testing.T) {
		schema := newPasskeyTestSchema(t)
		ctx := context.Background()
		current := registrationTestUser("passkey-delete-version", models.UserStatusActive)
		insertRegistrationTestUser(t, schema, current)
		passkeyID := insertSyntheticPasskey(t, schema, passkeyTestRPID, current.ID, []byte("delete-version-key"), "Removable")
		service := newPasskeyTestService(t, schema, passkeyTestRPID)
		err := service.DeletePasskey(
			ctx, current.ID, passkeyID,
			mfa.AuthenticationBinding{AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion},
			mfa.AuditContext{ActorID: current.ID, ActorName: current.Username}, time.Now().UTC(),
		)
		if err != nil {
			t.Fatalf("delete Passkey: %v", err)
		}
		var authVersion int64
		var passkeyCount, auditCount int
		if err := schema.pool.QueryRow(ctx, `
			SELECT
				(SELECT auth_version FROM users WHERE id=$1),
				(SELECT COUNT(*) FROM user_passkey_credentials WHERE id=$2),
				(SELECT COUNT(*) FROM audit_event_outbox WHERE event=$3 AND aggregate_id=$4)
		`, current.ID, passkeyID, models.AuditPasskeyRemoved, passkeyID.String()).Scan(
			&authVersion, &passkeyCount, &auditCount,
		); err != nil {
			t.Fatalf("read Passkey deletion state: %v", err)
		}
		if authVersion != current.AuthVersion+1 || passkeyCount != 0 || auditCount != 1 {
			t.Fatalf("deletion state: auth_version=%d passkeys=%d audits=%d", authVersion, passkeyCount, auditCount)
		}
	})

	t.Run("last login method is retained", func(t *testing.T) {
		schema := newPasskeyTestSchema(t)
		ctx := context.Background()
		current := registrationTestUser("passkey-delete-last", models.UserStatusActive)
		insertRegistrationTestUser(t, schema, current)
		clearPasskeyTestPassword(t, schema, current)
		passkeyID := insertSyntheticPasskey(t, schema, passkeyTestRPID, current.ID, []byte("delete-last-key"), "Only login")
		insertSyntheticPasskey(t, schema, "old-auth.example.test", current.ID, []byte("delete-last-old-rp"), "Old issuer")
		service := newPasskeyTestService(t, schema, passkeyTestRPID)
		err := service.DeletePasskey(
			ctx, current.ID, passkeyID,
			mfa.AuthenticationBinding{AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion},
			mfa.AuditContext{ActorID: current.ID, ActorName: current.Username}, time.Now().UTC(),
		)
		if !errors.Is(err, mfa.ErrLastAuthenticationMethod) {
			t.Fatalf("delete last current-RP login method: %v", err)
		}
		assertPasskeyMutationRolledBack(t, schema, current, passkeyID)
	})

	for _, providerState := range []string{"enabled", "disabled", "deleted"} {
		t.Run(providerState+" provider identity", func(t *testing.T) {
			schema := newPasskeyTestSchema(t)
			ctx := context.Background()
			current := registrationTestUser("passkey-provider-"+providerState, models.UserStatusActive)
			insertRegistrationTestUser(t, schema, current)
			clearPasskeyTestPassword(t, schema, current)
			passkeyID := insertSyntheticPasskey(
				t, schema, passkeyTestRPID, current.ID,
				[]byte("provider-"+providerState+"-passkey"), "Provider fallback",
			)
			providerName := "provider-" + providerState
			if _, err := schema.pool.Exec(ctx, `
				INSERT INTO oauth_providers (name,type,client_id,client_secret,enabled)
				VALUES ($1,'github','test-client','test-secret',$2)
			`, providerName, providerState != "disabled"); err != nil {
				t.Fatalf("insert %s provider: %v", providerState, err)
			}
			if _, err := schema.pool.Exec(ctx, `
				INSERT INTO identities (id,user_id,provider,external_id,metadata)
				VALUES ($1,$2,$3,$4,'{}'::jsonb)
			`, uuid.New(), current.ID, providerName, "external-"+providerState); err != nil {
				t.Fatalf("insert %s provider identity: %v", providerState, err)
			}
			if providerState == "deleted" {
				if _, err := schema.pool.Exec(ctx, `DELETE FROM oauth_providers WHERE name=$1`, providerName); err != nil {
					t.Fatalf("delete provider: %v", err)
				}
			}

			service := newPasskeyTestService(t, schema, passkeyTestRPID)
			err := service.DeletePasskey(
				ctx, current.ID, passkeyID,
				mfa.AuthenticationBinding{AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion},
				mfa.AuditContext{ActorID: current.ID, ActorName: current.Username}, time.Now().UTC(),
			)
			if providerState == "enabled" {
				if err != nil {
					t.Fatalf("enabled provider did not preserve a login method: %v", err)
				}
				return
			}
			if !errors.Is(err, mfa.ErrLastAuthenticationMethod) {
				t.Fatalf("%s provider allowed removal of the last usable login method: %v", providerState, err)
			}
			assertPasskeyMutationRolledBack(t, schema, current, passkeyID)
		})
	}

	t.Run("required administrator factor is retained", func(t *testing.T) {
		schema := newPasskeyTestSchema(t)
		ctx := context.Background()
		admin := registrationTestUser("passkey-delete-admin", models.UserStatusActive)
		admin.Role = "admin"
		insertRegistrationTestUser(t, schema, admin)
		passkeyID := insertSyntheticPasskey(t, schema, passkeyTestRPID, admin.ID, []byte("delete-admin-key"), "Required MFA")
		manager := settings.NewManagerForRP(schema.pool, settings.Branding{Title: "Nyauth Test"}, passkeyTestRPID)
		security := settings.DefaultSecurity()
		security.RequireMFAForAdmins = true
		if err := manager.SetSecurity(ctx, security, admin.Username, mfaSecuritySettingsMutation(admin)); err != nil {
			t.Fatalf("enable administrator MFA policy: %v", err)
		}
		service := newPasskeyTestService(t, schema, passkeyTestRPID)
		err := service.DeletePasskey(
			ctx, admin.ID, passkeyID,
			mfa.AuthenticationBinding{AuthVersion: admin.AuthVersion, SessionVersion: admin.SessionVersion},
			mfa.AuditContext{ActorID: admin.ID, ActorName: admin.Username}, time.Now().UTC(),
		)
		if !errors.Is(err, mfa.ErrRequiredByPolicy) {
			t.Fatalf("delete required administrator factor: %v", err)
		}
		assertPasskeyMutationRolledBack(t, schema, admin, passkeyID)
	})
}

func insertSyntheticPasskey(
	t *testing.T,
	schema *postgresTestSchema,
	rpID string,
	userID uuid.UUID,
	credentialID []byte,
	name string,
) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	handle := sha256.Sum256([]byte(rpID + "\x00" + userID.String()))
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO user_passkey_handles (rp_id,user_id,user_handle)
		VALUES ($1,$2,$3) ON CONFLICT (rp_id,user_id) DO NOTHING
	`, rpID, userID, handle[:]); err != nil {
		t.Fatalf("insert Passkey handle for %s: %v", rpID, err)
	}
	credential := gowebauthn.Credential{
		ID: append([]byte(nil), credentialID...), PublicKey: []byte("synthetic-public-key"),
		Authenticator: gowebauthn.Authenticator{AAGUID: make([]byte, 16)},
	}
	encoded, err := credential.MarshalMsg(nil)
	if err != nil {
		t.Fatalf("encode synthetic Passkey: %v", err)
	}
	rowID := uuid.New()
	ciphertext, err := crypto.EncryptEnvelope(
		passkeyTestMasterKey, passkeyTestKeyID, "mfa.passkey.credential", encoded,
		passkeyTestAAD(rpID, rowID, userID, credentialID),
	)
	if err != nil {
		t.Fatalf("encrypt synthetic Passkey: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO user_passkey_credentials (
			id,rp_id,user_id,credential_id,credential_ciphertext,name,aaguid
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, rowID, rpID, userID, credentialID, ciphertext, name, make([]byte, 16)); err != nil {
		t.Fatalf("insert synthetic Passkey for %s: %v", rpID, err)
	}
	return rowID
}

func assertPasskeyMutationRolledBack(t *testing.T, schema *postgresTestSchema, current *models.User, passkeyID uuid.UUID) {
	t.Helper()
	var authVersion int64
	var count int
	if err := schema.pool.QueryRow(context.Background(), `
		SELECT
			(SELECT auth_version FROM users WHERE id=$1),
			(SELECT COUNT(*) FROM user_passkey_credentials WHERE id=$2)
	`, current.ID, passkeyID).Scan(&authVersion, &count); err != nil {
		t.Fatalf("read rolled-back Passkey mutation: %v", err)
	}
	if authVersion != current.AuthVersion || count != 1 {
		t.Fatalf("Passkey mutation was not rolled back: auth_version=%d passkey_count=%d", authVersion, count)
	}
}

func clearPasskeyTestPassword(t *testing.T, schema *postgresTestSchema, current *models.User) {
	t.Helper()
	if _, err := schema.pool.Exec(context.Background(), `
		UPDATE users SET password_hash=NULL,password_changed_at=NULL WHERE id=$1
	`, current.ID); err != nil {
		t.Fatalf("clear test user password: %v", err)
	}
	current.PasswordHash = nil
	current.PasswordChangedAt = nil
}
