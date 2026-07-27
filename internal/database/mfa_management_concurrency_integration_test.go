package database_test

import (
	"context"
	"encoding/base32"
	"errors"
	"testing"
	"time"

	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/mfa"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestMFAManagementMutationsRejectRevokedSessionBinding(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run MFA migrations: %v", err)
	}
	ctx := context.Background()
	service := newManagementTestMFAService(t, schema)
	now := time.Now().UTC().Truncate(30 * time.Second)

	pending := registrationTestUser("mfa-stale-confirm", models.UserStatusActive)
	insertRegistrationTestUser(t, schema, pending)
	enrollment, err := service.BeginEnrollment(ctx, pending.ID, "Nyauth Test", pending.Username, now)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	stalePendingBinding := mfa.AuthenticationBinding{
		AuthVersion: pending.AuthVersion, SessionVersion: pending.SessionVersion,
	}
	if _, err := schema.pool.Exec(ctx, `UPDATE users SET session_version=session_version+1 WHERE id=$1`, pending.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConfirmEnrollment(
		ctx, pending.ID, stalePendingBinding, integrationTOTPCode(secret, now.Unix()/30),
		mfa.AuditContext{ActorID: pending.ID, ActorName: pending.Username}, now,
	); !errors.Is(err, mfa.ErrAuthenticationChanged) {
		t.Fatalf("stale enrollment confirmation error=%v", err)
	}
	status, err := service.Status(ctx, pending.ID)
	if err != nil || status.TOTPEnrolled || status.RecoveryCodesRemaining != 0 {
		t.Fatalf("stale enrollment changed factor state: status=%#v err=%v", status, err)
	}

	enrolled, binding, _, auditContext := newEnrolledManagementTestUser(t, schema, service, "mfa-stale-management", now)
	if _, err := schema.pool.Exec(ctx, `UPDATE users SET session_version=session_version+1 WHERE id=$1`, enrolled.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RegenerateRecoveryCodes(ctx, enrolled.ID, binding, auditContext, now.Add(time.Minute)); !errors.Is(err, mfa.ErrAuthenticationChanged) {
		t.Fatalf("stale recovery-code regeneration error=%v", err)
	}
	if err := service.Disable(ctx, enrolled.ID, binding, auditContext, now.Add(time.Minute)); !errors.Is(err, mfa.ErrAuthenticationChanged) {
		t.Fatalf("stale TOTP disable error=%v", err)
	}
	status, err = service.Status(ctx, enrolled.ID)
	if err != nil || !status.TOTPEnrolled || status.RecoveryCodesRemaining != 10 {
		t.Fatalf("stale management request changed factor state: status=%#v err=%v", status, err)
	}
}

func TestConcurrentRecoveryCodeRegenerationLeavesOnlyLatestBatchValid(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run MFA migrations: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	service := newManagementTestMFAService(t, schema)
	now := time.Now().UTC().Truncate(30 * time.Second)
	current, binding, _, auditContext := newEnrolledManagementTestUser(
		t, schema, service, "mfa-regeneration-race", now,
	)

	type result struct {
		codes []string
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			codes, err := service.RegenerateRecoveryCodes(
				ctx, current.ID, binding, auditContext, now.Add(time.Minute),
			)
			results <- result{codes: codes, err: err}
		}()
	}
	close(start)
	first := <-results
	second := <-results
	if first.err != nil || second.err != nil || len(first.codes) != 10 || len(second.codes) != 10 {
		t.Fatalf("concurrent regeneration results: first=%d/%v second=%d/%v", len(first.codes), first.err, len(second.codes), second.err)
	}

	firstErr := service.ConsumeRecoveryCode(ctx, current.ID, first.codes[0], auditContext, now.Add(2*time.Minute))
	secondErr := service.ConsumeRecoveryCode(ctx, current.ID, second.codes[0], auditContext, now.Add(2*time.Minute))
	valid := 0
	invalid := 0
	for _, err := range []error{firstErr, secondErr} {
		switch {
		case err == nil:
			valid++
		case errors.Is(err, mfa.ErrInvalidCode):
			invalid++
		default:
			t.Fatalf("unexpected recovery-code validation error: %v", err)
		}
	}
	if valid != 1 || invalid != 1 {
		t.Fatalf("concurrent batches valid=%d invalid=%d, want one latest batch only", valid, invalid)
	}
	status, err := service.Status(ctx, current.ID)
	if err != nil || status.RecoveryCodesRemaining != 9 {
		t.Fatalf("recovery-code status after concurrent regeneration=%#v err=%v", status, err)
	}
}

func newManagementTestMFAService(t *testing.T, schema *postgresTestSchema) *mfa.Service {
	t.Helper()
	service, err := mfa.NewService(schema.pool, mfa.Options{
		ActiveKeyID: "primary",
		MasterKeys:  map[string][]byte{"primary": []byte("0123456789abcdef0123456789abcdef")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func newEnrolledManagementTestUser(
	t *testing.T,
	schema *postgresTestSchema,
	service *mfa.Service,
	username string,
	now time.Time,
) (*models.User, mfa.AuthenticationBinding, []string, mfa.AuditContext) {
	t.Helper()
	current := registrationTestUser(username, models.UserStatusActive)
	insertRegistrationTestUser(t, schema, current)
	enrollment, err := service.BeginEnrollment(context.Background(), current.ID, "Nyauth Test", current.Username, now)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	auditContext := mfa.AuditContext{ActorID: current.ID, ActorName: current.Username}
	codes, err := service.ConfirmEnrollment(
		context.Background(), current.ID,
		mfa.AuthenticationBinding{AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion},
		integrationTOTPCode(secret, now.Unix()/30), auditContext, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := user.NewService(user.NewStore(schema.pool)).GetByID(context.Background(), current.ID)
	if err != nil {
		t.Fatal(err)
	}
	return updated, mfa.AuthenticationBinding{
		AuthVersion: updated.AuthVersion, SessionVersion: updated.SessionVersion,
	}, codes, auditContext
}
