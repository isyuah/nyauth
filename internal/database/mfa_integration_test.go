package database_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/mfa"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestTOTPMFALifecyclePolicyAndAuditIntegration(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run MFA migrations: %v", err)
	}
	ctx := context.Background()
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	service, err := mfa.NewService(schema.pool, mfa.Options{
		ActiveKeyID: "primary", MasterKeys: map[string][]byte{"primary": masterKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	admin := registrationTestUser("mfa-admin", models.UserStatusActive)
	admin.Role = "admin"
	insertRegistrationTestUser(t, schema, admin)
	candidate := registrationTestUser("mfa-candidate", models.UserStatusActive)
	insertRegistrationTestUser(t, schema, candidate)

	now := time.Now().UTC().Truncate(time.Second)
	enrollment, err := service.BeginEnrollment(ctx, admin.ID, "Nyauth Test", admin.Username, now)
	if err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}
	if !strings.HasPrefix(enrollment.OTPAuthURI, "otpauth://totp/") || enrollment.Secret == "" {
		t.Fatalf("enrollment=%#v", enrollment)
	}
	var ciphertext string
	if err := schema.pool.QueryRow(ctx, `
		SELECT secret_ciphertext FROM user_totp_credentials WHERE user_id=$1
	`, admin.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ciphertext, enrollment.Secret) {
		t.Fatal("stored TOTP ciphertext contains the plaintext secret")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	code := integrationTOTPCode(secret, now.Unix()/30)
	auditContext := mfa.AuditContext{
		ActorID: admin.ID, ActorName: admin.Username,
		IPAddress: "192.0.2.10", UserAgent: "integration-browser",
	}
	recoveryCodes, err := service.ConfirmEnrollment(ctx, admin.ID, mfa.AuthenticationBinding{
		AuthVersion: admin.AuthVersion, SessionVersion: admin.SessionVersion,
	}, code, auditContext, now)
	if err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}
	if len(recoveryCodes) != 10 {
		t.Fatalf("recovery codes=%d", len(recoveryCodes))
	}
	status, err := service.Status(ctx, admin.ID)
	if err != nil || !status.TOTPEnrolled || status.RecoveryCodesRemaining != 10 {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	updatedAdmin, err := user.NewService(user.NewStore(schema.pool)).GetByID(ctx, admin.ID)
	if err != nil || updatedAdmin.AuthVersion != 2 {
		t.Fatalf("updated admin=%#v err=%v", updatedAdmin, err)
	}
	if err := service.VerifyTOTP(ctx, admin.ID, code, now); !errors.Is(err, mfa.ErrCodeReplayed) {
		t.Fatalf("confirmation code replay error=%v", err)
	}
	next := now.Add(30 * time.Second)
	nextCode := integrationTOTPCode(secret, next.Unix()/30)
	if err := service.VerifyTOTP(ctx, admin.ID, nextCode, next); err != nil {
		t.Fatalf("verify next TOTP: %v", err)
	}
	if err := service.VerifyTOTP(ctx, admin.ID, nextCode, next); !errors.Is(err, mfa.ErrCodeReplayed) {
		t.Fatalf("second TOTP replay error=%v", err)
	}

	if err := service.ConsumeRecoveryCode(ctx, admin.ID, recoveryCodes[0], auditContext, next); err != nil {
		t.Fatalf("consume recovery code: %v", err)
	}
	if err := service.ConsumeRecoveryCode(ctx, admin.ID, recoveryCodes[0], auditContext, next); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("reused recovery code error=%v", err)
	}
	status, err = service.Status(ctx, admin.ID)
	if err != nil || status.RecoveryCodesRemaining != 9 {
		t.Fatalf("status after recovery=%#v err=%v", status, err)
	}
	regenerated, err := service.RegenerateRecoveryCodes(ctx, admin.ID, mfa.AuthenticationBinding{
		AuthVersion: 2, SessionVersion: admin.SessionVersion,
	}, auditContext, next)
	if err != nil || len(regenerated) != 10 {
		t.Fatalf("regenerated=%d err=%v", len(regenerated), err)
	}
	if err := service.ConsumeRecoveryCode(ctx, admin.ID, recoveryCodes[1], auditContext, next); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("old recovery code after regeneration error=%v", err)
	}

	settingsManager := settings.NewManager(schema.pool, settings.Branding{Title: "Nyauth Test"})
	security := settings.DefaultSecurity()
	security.RequireMFAForAdmins = true
	settingsMutation := mfaSecuritySettingsMutation(admin)
	if err := setSecurityPolicy(ctx, settingsManager, security, admin.Username, settingsMutation); err != nil {
		t.Fatalf("require administrator MFA: %v", err)
	}
	mutation := audit.MutationAudit{
		Event: models.AuditUserRoleChanged, ActorID: admin.ID, ActorName: admin.Username,
		Result: "success", RiskLevel: "high", IPAddress: "192.0.2.10", UserAgent: "integration-browser",
	}
	role := "admin"
	if _, err := user.NewService(user.NewStore(schema.pool)).AdminUpdate(
		ctx, candidate.ID, models.AdminUpdateUserRequest{Role: &role}, mutation,
	); !errors.Is(err, user.ErrAdminMFARequired) {
		t.Fatalf("promote administrator without MFA error=%v", err)
	}
	if err := service.Disable(ctx, admin.ID, mfa.AuthenticationBinding{
		AuthVersion: 2, SessionVersion: admin.SessionVersion,
	}, auditContext, next); !errors.Is(err, mfa.ErrRequiredByPolicy) {
		t.Fatalf("disable required administrator MFA error=%v", err)
	}

	security.RequireMFAForAdmins = false
	if err := setSecurityPolicy(ctx, settingsManager, security, admin.Username, settingsMutation); err != nil {
		t.Fatalf("relax administrator MFA policy: %v", err)
	}
	if err := service.Disable(ctx, admin.ID, mfa.AuthenticationBinding{
		AuthVersion: 2, SessionVersion: admin.SessionVersion,
	}, auditContext, next); err != nil {
		t.Fatalf("disable TOTP: %v", err)
	}
	status, err = service.Status(ctx, admin.ID)
	if err != nil || status.TOTPEnrolled || status.RecoveryCodesRemaining != 0 {
		t.Fatalf("disabled status=%#v err=%v", status, err)
	}
	updatedAdmin, err = user.NewService(user.NewStore(schema.pool)).GetByID(ctx, admin.ID)
	if err != nil || updatedAdmin.AuthVersion != 3 {
		t.Fatalf("admin after disable=%#v err=%v", updatedAdmin, err)
	}

	security.RequireMFAForAdmins = true
	err = setSecurityPolicy(ctx, settingsManager, security, admin.Username, settingsMutation)
	var missing *settings.AdminsMissingMFAError
	if !errors.As(err, &missing) || len(missing.Usernames) != 1 || missing.Usernames[0] != admin.Username {
		t.Fatalf("missing administrator error=%v details=%#v", err, missing)
	}

	wantEvents := []string{
		models.AuditMFAEnrolled,
		models.AuditRecoveryCodeUsed,
		models.AuditRecoveryCodesGenerated,
		models.AuditMFADisabled,
	}
	for _, event := range wantEvents {
		var count int
		if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_event_outbox WHERE event=$1`, event).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("audit event %s count=%d", event, count)
		}
	}
}

func TestExplicitLoginMFARequiresAndRetainsAnEnrolledFactor(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run MFA migrations: %v", err)
	}
	ctx := context.Background()
	service, err := mfa.NewService(schema.pool, mfa.Options{
		ActiveKeyID: "primary",
		MasterKeys:  map[string][]byte{"primary": []byte("0123456789abcdef0123456789abcdef")},
	})
	if err != nil {
		t.Fatal(err)
	}
	current := registrationTestUser("explicit-login-mfa", models.UserStatusActive)
	insertRegistrationTestUser(t, schema, current)
	now := time.Now().UTC().Truncate(time.Second)
	auditContext := mfa.AuditContext{ActorID: current.ID, ActorName: current.Username}

	if changed, err := service.SetLoginMFARequirement(ctx, current.ID, mfa.AuthenticationBinding{
		AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
	}, true, auditContext, now); changed || !errors.Is(err, mfa.ErrLoginMFAFactorRequired) {
		t.Fatalf("enable without factor: changed=%v err=%v", changed, err)
	}

	enrollment, err := service.BeginEnrollment(ctx, current.ID, "Nyauth Test", current.Username, now)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConfirmEnrollment(ctx, current.ID, mfa.AuthenticationBinding{
		AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
	}, integrationTOTPCode(secret, now.Unix()/30), auditContext, now); err != nil {
		t.Fatal(err)
	}
	changed, err := service.SetLoginMFARequirement(ctx, current.ID, mfa.AuthenticationBinding{
		AuthVersion: current.AuthVersion + 1, SessionVersion: current.SessionVersion,
	}, true, auditContext, now.Add(time.Second))
	if err != nil || !changed {
		t.Fatalf("enable with factor: changed=%v err=%v", changed, err)
	}
	status, err := service.Status(ctx, current.ID)
	if err != nil || !status.LoginMFAEnabled || !status.TOTPEnrolled {
		t.Fatalf("enabled status=%#v err=%v", status, err)
	}
	if err := service.Disable(ctx, current.ID, mfa.AuthenticationBinding{
		AuthVersion: current.AuthVersion + 2, SessionVersion: current.SessionVersion,
	}, auditContext, now.Add(2*time.Second)); !errors.Is(err, mfa.ErrLoginMFAFactorRequired) {
		t.Fatalf("disable final required factor: %v", err)
	}
	changed, err = service.SetLoginMFARequirement(ctx, current.ID, mfa.AuthenticationBinding{
		AuthVersion: current.AuthVersion + 2, SessionVersion: current.SessionVersion,
	}, false, auditContext, now.Add(3*time.Second))
	if err != nil || !changed {
		t.Fatalf("disable login MFA: changed=%v err=%v", changed, err)
	}
	if err := service.Disable(ctx, current.ID, mfa.AuthenticationBinding{
		AuthVersion: current.AuthVersion + 3, SessionVersion: current.SessionVersion,
	}, auditContext, now.Add(4*time.Second)); err != nil {
		t.Fatalf("disable factor after relaxing login policy: %v", err)
	}
	var auditCount int
	if err := schema.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_event_outbox
		WHERE event=$1 AND aggregate_id=$2
	`, models.AuditMFALoginRequirementUpdated, current.ID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 2 {
		t.Fatalf("login MFA audit count=%d", auditCount)
	}
}

func TestAdministratorMFAPolicyRacesMaintainInvariant(t *testing.T) {
	t.Run("policy enable races with factor disable", func(t *testing.T) {
		schema := newPostgresTestSchema(t)
		if err := database.RunMigrations(schema.migrationDSN); err != nil {
			t.Fatalf("run MFA migrations: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		service, err := mfa.NewService(schema.pool, mfa.Options{
			ActiveKeyID: "primary",
			MasterKeys:  map[string][]byte{"primary": []byte("0123456789abcdef0123456789abcdef")},
		})
		if err != nil {
			t.Fatal(err)
		}
		admin := registrationTestUser("mfa-disable-race", models.UserStatusActive)
		admin.Role = "admin"
		insertRegistrationTestUser(t, schema, admin)
		now := time.Now().UTC().Truncate(time.Second)
		enrollment, err := service.BeginEnrollment(ctx, admin.ID, "Nyauth Test", admin.Username, now)
		if err != nil {
			t.Fatal(err)
		}
		secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
		if err != nil {
			t.Fatal(err)
		}
		auditContext := mfa.AuditContext{ActorID: admin.ID, ActorName: admin.Username}
		if _, err := service.ConfirmEnrollment(ctx, admin.ID, mfa.AuthenticationBinding{
			AuthVersion: admin.AuthVersion, SessionVersion: admin.SessionVersion,
		}, integrationTOTPCode(secret, now.Unix()/30), auditContext, now); err != nil {
			t.Fatal(err)
		}

		blocker, err := schema.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(ctx)
		if err := runtimecoord.LockSecurityExclusive(ctx, blocker); err != nil {
			t.Fatal(err)
		}
		manager := settings.NewManager(schema.pool, settings.Branding{Title: "Nyauth Test"})
		security := settings.DefaultSecurity()
		security.RequireMFAForAdmins = true
		ready := make(chan struct{}, 2)
		disableResult := make(chan error, 1)
		policyResult := make(chan error, 1)
		go func() {
			ready <- struct{}{}
			disableResult <- service.Disable(ctx, admin.ID, mfa.AuthenticationBinding{
				AuthVersion: 2, SessionVersion: admin.SessionVersion,
			}, auditContext, now.Add(time.Minute))
		}()
		go func() {
			ready <- struct{}{}
			policyResult <- setSecurityPolicy(ctx, manager, security, admin.Username, mfaSecuritySettingsMutation(admin))
		}()
		<-ready
		<-ready
		if err := blocker.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		disableErr := <-disableResult
		policyErr := <-policyResult
		if err := manager.Load(ctx); err != nil {
			t.Fatal(err)
		}
		status, err := service.Status(ctx, admin.ID)
		if err != nil {
			t.Fatal(err)
		}
		storedPolicy := manager.Security()
		if storedPolicy.RequireMFAForAdmins && !status.TOTPEnrolled {
			t.Fatalf("invalid final state: policy=%#v status=%#v", storedPolicy, status)
		}
		if policyErr == nil {
			if !errors.Is(disableErr, mfa.ErrRequiredByPolicy) || !status.TOTPEnrolled || !storedPolicy.RequireMFAForAdmins {
				t.Fatalf("policy-won results: policy_err=%v disable_err=%v policy=%#v status=%#v", policyErr, disableErr, storedPolicy, status)
			}
		} else {
			var missing *settings.AdminsMissingMFAError
			if !errors.As(policyErr, &missing) || disableErr != nil || status.TOTPEnrolled || storedPolicy.RequireMFAForAdmins {
				t.Fatalf("disable-won results: policy_err=%v disable_err=%v policy=%#v status=%#v", policyErr, disableErr, storedPolicy, status)
			}
		}
	})

	t.Run("policy enable races with administrator promotion", func(t *testing.T) {
		schema := newPostgresTestSchema(t)
		if err := database.RunMigrations(schema.migrationDSN); err != nil {
			t.Fatalf("run MFA migrations: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		service, err := mfa.NewService(schema.pool, mfa.Options{
			ActiveKeyID: "primary",
			MasterKeys:  map[string][]byte{"primary": []byte("0123456789abcdef0123456789abcdef")},
		})
		if err != nil {
			t.Fatal(err)
		}
		admin := registrationTestUser("mfa-policy-race-admin", models.UserStatusActive)
		admin.Role = "admin"
		insertRegistrationTestUser(t, schema, admin)
		candidate := registrationTestUser("mfa-policy-race-candidate", models.UserStatusActive)
		insertRegistrationTestUser(t, schema, candidate)
		now := time.Now().UTC().Truncate(time.Second)
		enrollment, err := service.BeginEnrollment(ctx, admin.ID, "Nyauth Test", admin.Username, now)
		if err != nil {
			t.Fatal(err)
		}
		secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.ConfirmEnrollment(ctx, admin.ID, mfa.AuthenticationBinding{
			AuthVersion: admin.AuthVersion, SessionVersion: admin.SessionVersion,
		}, integrationTOTPCode(secret, now.Unix()/30), mfa.AuditContext{ActorID: admin.ID, ActorName: admin.Username}, now); err != nil {
			t.Fatal(err)
		}

		blocker, err := schema.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(ctx)
		if err := runtimecoord.LockSecurityExclusive(ctx, blocker); err != nil {
			t.Fatal(err)
		}
		manager := settings.NewManager(schema.pool, settings.Branding{Title: "Nyauth Test"})
		security := settings.DefaultSecurity()
		security.RequireMFAForAdmins = true
		role := "admin"
		mutation := audit.MutationAudit{
			Event: models.AuditUserRoleChanged, ActorID: admin.ID, ActorName: admin.Username,
			Result: "success", RiskLevel: "high",
		}
		ready := make(chan struct{}, 2)
		promotionResult := make(chan error, 1)
		policyResult := make(chan error, 1)
		go func() {
			ready <- struct{}{}
			_, updateErr := user.NewService(user.NewStore(schema.pool)).AdminUpdate(
				ctx, candidate.ID, models.AdminUpdateUserRequest{Role: &role}, mutation,
			)
			promotionResult <- updateErr
		}()
		go func() {
			ready <- struct{}{}
			policyResult <- setSecurityPolicy(ctx, manager, security, admin.Username, mfaSecuritySettingsMutation(admin))
		}()
		<-ready
		<-ready
		if err := blocker.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		promotionErr := <-promotionResult
		policyErr := <-policyResult
		if err := manager.Load(ctx); err != nil {
			t.Fatal(err)
		}
		updatedCandidate, err := user.NewService(user.NewStore(schema.pool)).GetByID(ctx, candidate.ID)
		if err != nil {
			t.Fatal(err)
		}
		storedPolicy := manager.Security()
		if storedPolicy.RequireMFAForAdmins && updatedCandidate.Role == "admin" {
			t.Fatalf("invalid final state: policy=%#v candidate=%#v", storedPolicy, updatedCandidate)
		}
		if policyErr == nil {
			if !errors.Is(promotionErr, user.ErrAdminMFARequired) || updatedCandidate.Role != "user" || !storedPolicy.RequireMFAForAdmins {
				t.Fatalf("policy-won results: policy_err=%v promotion_err=%v policy=%#v candidate=%#v", policyErr, promotionErr, storedPolicy, updatedCandidate)
			}
		} else {
			var missing *settings.AdminsMissingMFAError
			if !errors.As(policyErr, &missing) || promotionErr != nil || updatedCandidate.Role != "admin" || storedPolicy.RequireMFAForAdmins {
				t.Fatalf("promotion-won results: policy_err=%v promotion_err=%v policy=%#v candidate=%#v", policyErr, promotionErr, storedPolicy, updatedCandidate)
			}
		}
	})
}

func mfaSecuritySettingsMutation(actor *models.User) audit.MutationAudit {
	return audit.MutationAudit{
		Event: models.AuditSettingsUpdated, ActorID: actor.ID, ActorName: actor.Username,
		Result: "success", RiskLevel: "high", IPAddress: "192.0.2.10",
		UserAgent: "mfa-integration-test",
	}
}

func setSecurityPolicy(
	ctx context.Context,
	manager *settings.Manager,
	value settings.Security,
	actorName string,
	mutation audit.MutationAudit,
) error {
	_, err := manager.SetSecurity(
		ctx, value, manager.SecuritySnapshot().Revision, actorName, mutation,
	)
	return err
}

func integrationTOTPCode(secret []byte, step int64) string {
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, uint64(step))
	digest := hmac.New(sha1.New, secret)
	_, _ = digest.Write(message)
	sum := digest.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1_000_000)
}
