package database_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/invite"
	"github.com/nyasharp/nyauth/internal/registration"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

func newMigratedRegistrationSchema(t *testing.T) *postgresTestSchema {
	t.Helper()
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run registration migrations: %v", err)
	}
	return schema
}

func registrationTestUser(username string, status models.UserStatus) *models.User {
	email := username + "@example.test"
	passwordHash := "integration-password-hash"
	return &models.User{
		ID: uuid.New(), Username: username, Email: &email, PasswordHash: &passwordHash, Status: status,
		Role: "user", AuthVersion: 1, SessionVersion: 1, Metadata: map[string]string{},
	}
}

func insertRegistrationTestUser(t *testing.T, schema *postgresTestSchema, u *models.User) {
	t.Helper()
	if err := user.NewStore(schema.pool).Create(context.Background(), u); err != nil {
		t.Fatalf("insert registration test user %q: %v", u.Username, err)
	}
}

func createRegistrationTestInvite(
	t *testing.T,
	schema *postgresTestSchema,
	createdBy *uuid.UUID,
	maxUses int,
	createdAt, expiresAt time.Time,
) (uuid.UUID, string) {
	t.Helper()
	inviteID := uuid.New()
	codeHash := invite.HashCode("invite-" + uuid.NewString())
	if _, err := schema.pool.Exec(context.Background(), `
		INSERT INTO invites (id,code_hash,created_by,note,max_uses,expires_at,created_at)
		VALUES ($1,$2,$3,'integration invite',$4,$5,$6)
	`, inviteID, codeHash, createdBy, maxUses, expiresAt.UTC(), createdAt.UTC()); err != nil {
		t.Fatalf("insert registration test invite: %v", err)
	}
	return inviteID, codeHash
}

func validPreparedVerification(u *models.User, createdAt, expiresAt time.Time) *account.PreparedActionEmail {
	tokenHash := sha256.Sum256([]byte("verification-" + u.ID.String()))
	recipientHash := sha256.Sum256([]byte(strings.ToLower(*u.Email)))
	userID := u.ID
	return &account.PreparedActionEmail{
		Action: &account.ActionToken{
			ID: uuid.New(), UserID: u.ID, Action: account.ActionEmailVerification,
			TokenHash: tokenHash[:], PayloadCiphertext: "integration-action-envelope",
			ExpiresAt: expiresAt.UTC(), CreatedAt: createdAt.UTC(),
		},
		Email: &account.OutboxEmail{
			ID: uuid.New(), UserID: &userID, MessageType: account.MessageEmailVerification,
			RecipientHash: recipientHash[:], EncryptedMessage: "integration-email-envelope",
			AvailableAt: createdAt.UTC(), ExpiresAt: expiresAt.UTC(), CreatedAt: createdAt.UTC(),
		},
	}
}

func newRegistrationAccountService(
	t *testing.T,
	schema *postgresTestSchema,
	clock *time.Time,
	tokens ...string,
) *account.Service {
	t.Helper()
	tokenIndex := 0
	service, err := account.NewService(account.NewStore(schema.pool), account.ServiceOptions{
		PublicBaseURL: "https://auth.example.test", ActiveKeyID: "primary",
		MasterKeys: map[string][]byte{"primary": []byte("0123456789abcdef0123456789abcdef")},
		Clock:      func() time.Time { return clock.UTC() },
		GenerateToken: func() (string, error) {
			if tokenIndex >= len(tokens) {
				return "", fmt.Errorf("test token sequence exhausted")
			}
			token := tokens[tokenIndex]
			tokenIndex++
			return token, nil
		},
	})
	if err != nil {
		t.Fatalf("create registration account service: %v", err)
	}
	return service
}

func createPendingRegistration(
	t *testing.T,
	schema *postgresTestSchema,
	accountService *account.Service,
	u *models.User,
	inviteHash *string,
	createdAt, expiresAt time.Time,
) {
	t.Helper()
	prepared, err := accountService.PrepareEmailVerification(u, account.RequestMetadata{}, expiresAt)
	if err != nil {
		t.Fatalf("prepare registration verification: %v", err)
	}
	if _, err := user.NewStore(schema.pool).CreateRegistration(context.Background(), u, user.RegistrationCommitOptions{
		InviteCodeHash: inviteHash, ExpiresAt: expiresAt, Now: createdAt,
		Mode: settingsModeForInvite(inviteHash), Verification: prepared,
	}); err != nil {
		t.Fatalf("create pending registration: %v", err)
	}
}

func settingsModeForInvite(inviteHash *string) string {
	if inviteHash != nil {
		return "invite_only"
	}
	return "open"
}

func registrationInviteByID(t *testing.T, schema *postgresTestSchema, id uuid.UUID, now time.Time) models.Invite {
	t.Helper()
	items, err := invite.NewStore(schema.pool).List(context.Background(), 200)
	if err != nil {
		t.Fatalf("list registration invites: %v", err)
	}
	for _, item := range items {
		if item.ID == id {
			item.Status = item.StatusAt(now)
			return item
		}
	}
	t.Fatalf("invite %s was not listed", id)
	return models.Invite{}
}

func countRegistrationRows(t *testing.T, schema *postgresTestSchema, query string, args ...any) int {
	t.Helper()
	var count int
	if err := schema.pool.QueryRow(context.Background(), query, args...).Scan(&count); err != nil {
		t.Fatalf("count registration rows: %v", err)
	}
	return count
}

func registrationMutation(event string) audit.MutationAudit {
	return audit.MutationAudit{
		Event: event, ActorID: uuid.New(), ActorName: "integration-admin",
		Result: "success", RiskLevel: "high", IPAddress: "192.0.2.10",
	}
}

func TestRegistrationInviteFinalCapacityIsSerialized(t *testing.T) {
	schema := newMigratedRegistrationSchema(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	inviteID, codeHash := createRegistrationTestInvite(t, schema, nil, 1, now.Add(-time.Minute), now.Add(time.Hour))
	store := user.NewStore(schema.pool)

	start := make(chan struct{})
	errorsByWorker := make(chan error, 2)
	var workers sync.WaitGroup
	for worker := 0; worker < 2; worker++ {
		worker := worker
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			u := registrationTestUser(fmt.Sprintf("final-slot-%d-%s", worker, uuid.NewString()[:8]), models.UserStatusActive)
			_, err := store.CreateRegistration(context.Background(), u, user.RegistrationCommitOptions{
				InviteCodeHash: &codeHash, ExpiresAt: now.Add(72 * time.Hour), Now: now,
				Mode: "invite_only",
			})
			errorsByWorker <- err
		}()
	}
	close(start)
	workers.Wait()
	close(errorsByWorker)

	succeeded, rejected := 0, 0
	for err := range errorsByWorker {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, registration.ErrInviteInvalid):
			rejected++
		default:
			t.Fatalf("unexpected final-slot registration error: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("final-slot results: succeeded=%d rejected=%d", succeeded, rejected)
	}
	item := registrationInviteByID(t, schema, inviteID, now)
	if item.UsedCount != 1 || item.ReservedCount != 0 || item.Status != "exhausted" {
		t.Fatalf("final-slot invite = %#v", item)
	}
}

func TestRegistrationDuplicateUsernameRollsBackInviteReservation(t *testing.T) {
	schema := newMigratedRegistrationSchema(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	existing := registrationTestUser("duplicate-registration", models.UserStatusActive)
	insertRegistrationTestUser(t, schema, existing)
	inviteID, codeHash := createRegistrationTestInvite(t, schema, nil, 1, now.Add(-time.Minute), now.Add(time.Hour))
	store := user.NewStore(schema.pool)

	duplicate := registrationTestUser(existing.Username, models.UserStatusActive)
	if _, err := store.CreateRegistration(context.Background(), duplicate, user.RegistrationCommitOptions{
		InviteCodeHash: &codeHash, ExpiresAt: now.Add(72 * time.Hour), Now: now, Mode: "invite_only",
	}); err == nil {
		t.Fatal("duplicate username registration unexpectedly succeeded")
	}
	item := registrationInviteByID(t, schema, inviteID, now)
	if item.UsedCount != 0 || item.ReservedCount != 0 || item.Status != "active" {
		t.Fatalf("invite was consumed by rolled-back duplicate: %#v", item)
	}

	retry := registrationTestUser("duplicate-retry", models.UserStatusActive)
	if _, err := store.CreateRegistration(context.Background(), retry, user.RegistrationCommitOptions{
		InviteCodeHash: &codeHash, ExpiresAt: now.Add(72 * time.Hour), Now: now, Mode: "invite_only",
	}); err != nil {
		t.Fatalf("retry after duplicate rollback: %v", err)
	}
}

func TestRegistrationVerificationArtifactFailureRollsBackEverything(t *testing.T) {
	for _, test := range []struct {
		name        string
		breakAction bool
		breakEmail  bool
	}{
		{name: "token", breakAction: true},
		{name: "outbox", breakEmail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			schema := newMigratedRegistrationSchema(t)
			now := time.Now().UTC().Truncate(time.Microsecond)
			u := registrationTestUser("artifact-"+test.name, models.UserStatusPending)
			prepared := validPreparedVerification(u, now, now.Add(24*time.Hour))
			if test.breakAction {
				prepared.Action.TokenHash = []byte{1}
			}
			if test.breakEmail {
				prepared.Email.RecipientHash = []byte{1}
			}

			if _, err := user.NewStore(schema.pool).CreateRegistration(context.Background(), u, user.RegistrationCommitOptions{
				ExpiresAt: now.Add(72 * time.Hour), Now: now, Mode: "open", Verification: prepared,
			}); err == nil {
				t.Fatal("invalid verification artifacts unexpectedly committed")
			}
			for name, query := range map[string]string{
				"user":         `SELECT COUNT(*) FROM users WHERE id=$1`,
				"registration": `SELECT COUNT(*) FROM self_registrations WHERE user_id=$1`,
				"token":        `SELECT COUNT(*) FROM account_action_tokens WHERE user_id=$1`,
				"outbox":       `SELECT COUNT(*) FROM email_outbox WHERE user_id=$1`,
				"audit":        `SELECT COUNT(*) FROM audit_event_outbox WHERE aggregate_id=$1`,
			} {
				if count := countRegistrationRows(t, schema, query, u.ID.String()); count != 0 {
					t.Fatalf("%s rows after rollback = %d", name, count)
				}
			}
		})
	}
}

func TestEmailVerificationConsumesReservedInvite(t *testing.T) {
	schema := newMigratedRegistrationSchema(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	inviteID, codeHash := createRegistrationTestInvite(t, schema, nil, 1, now.Add(-time.Minute), now.Add(time.Hour))
	rawToken := "verify-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	clock := now
	accountService := newRegistrationAccountService(t, schema, &clock, rawToken)
	u := registrationTestUser("verified-registration", models.UserStatusPending)
	createPendingRegistration(t, schema, accountService, u, &codeHash, now, now.Add(72*time.Hour))

	reserved := registrationInviteByID(t, schema, inviteID, now)
	if reserved.UsedCount != 0 || reserved.ReservedCount != 1 || reserved.Status != "exhausted" {
		t.Fatalf("reserved invite = %#v", reserved)
	}
	verified, err := accountService.ConfirmEmailVerification(context.Background(), rawToken)
	if err != nil {
		t.Fatalf("confirm registration email: %v", err)
	}
	if verified.Status != models.UserStatusActive || verified.EmailVerifiedAt == nil {
		t.Fatalf("verified user = %#v", verified)
	}

	consumed := registrationInviteByID(t, schema, inviteID, now)
	if consumed.UsedCount != 1 || consumed.ReservedCount != 0 || consumed.Status != "exhausted" {
		t.Fatalf("consumed invite = %#v", consumed)
	}
	for _, event := range []string{
		models.AuditUserRegistered,
		models.AuditInviteReserved,
		models.AuditInviteConsumed,
		"user.email_verified",
	} {
		if count := countRegistrationRows(t, schema, `SELECT COUNT(*) FROM audit_event_outbox WHERE event=$1`, event); count != 1 {
			t.Fatalf("audit event %s count = %d", event, count)
		}
	}
}

func TestExistingReservationCanCompleteAfterInviteBecomesUnusable(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate string
		status string
	}{
		{name: "revoked", mutate: `UPDATE invites SET revoked_at=$2 WHERE id=$1`, status: "revoked"},
		{name: "expired", mutate: `UPDATE invites SET expires_at=$2 WHERE id=$1`, status: "expired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			schema := newMigratedRegistrationSchema(t)
			now := time.Now().UTC().Truncate(time.Microsecond)
			inviteID, codeHash := createRegistrationTestInvite(t, schema, nil, 1, now.Add(-2*time.Hour), now.Add(time.Hour))
			rawToken := "verify-" + strings.ReplaceAll(uuid.NewString(), "-", "")
			clock := now
			accountService := newRegistrationAccountService(t, schema, &clock, rawToken)
			u := registrationTestUser("unusable-"+test.name, models.UserStatusPending)
			createPendingRegistration(t, schema, accountService, u, &codeHash, now, now.Add(6*time.Hour))

			unusableAt := now
			if test.name == "expired" {
				unusableAt = now.Add(-time.Minute)
			}
			if _, err := schema.pool.Exec(context.Background(), test.mutate, inviteID, unusableAt); err != nil {
				t.Fatalf("make invite %s: %v", test.name, err)
			}
			before := registrationInviteByID(t, schema, inviteID, now)
			if before.Status != test.status || before.ReservedCount != 1 {
				t.Fatalf("unusable reserved invite = %#v", before)
			}
			if _, err := accountService.ConfirmEmailVerification(context.Background(), rawToken); err != nil {
				t.Fatalf("verify after invite became %s: %v", test.name, err)
			}
			after := registrationInviteByID(t, schema, inviteID, now)
			if after.UsedCount != 1 || after.ReservedCount != 0 || after.Status != test.status {
				t.Fatalf("completed unusable invite = %#v", after)
			}
		})
	}
}

func TestRegistrationAdministrativeLifecycleAndCleanup(t *testing.T) {
	schema := newMigratedRegistrationSchema(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	creator := registrationTestUser("invite-creator", models.UserStatusActive)
	insertRegistrationTestUser(t, schema, creator)
	inviteID, codeHash := createRegistrationTestInvite(t, schema, &creator.ID, 3, now.Add(-3*time.Hour), now.Add(24*time.Hour))
	store := user.NewStore(schema.pool)
	service := user.NewService(store)

	deletedPending := registrationTestUser("pending-admin-delete", models.UserStatusPending)
	if _, err := store.CreateRegistration(context.Background(), deletedPending, user.RegistrationCommitOptions{
		InviteCodeHash: &codeHash, ExpiresAt: now.Add(4 * time.Hour), Now: now,
		Mode: "invite_only", Verification: validPreparedVerification(deletedPending, now, now.Add(4*time.Hour)),
	}); err != nil {
		t.Fatalf("create pending deletion registration: %v", err)
	}
	if err := service.Delete(context.Background(), deletedPending.ID, registrationMutation(models.AuditUserDeleted)); err != nil {
		t.Fatalf("delete pending registration: %v", err)
	}
	var releasedStatus, releaseReason string
	var releasedUserID *uuid.UUID
	if err := schema.pool.QueryRow(context.Background(), `
		SELECT status,release_reason,user_id FROM self_registrations WHERE invite_id=$1 AND status='released'
	`, inviteID).Scan(&releasedStatus, &releaseReason, &releasedUserID); err != nil {
		t.Fatalf("read released pending registration: %v", err)
	}
	if releasedStatus != registration.StatusReleased || releaseReason != registration.ReleaseReasonAdminDeleted || releasedUserID != nil {
		t.Fatalf("released pending state: status=%s reason=%s user=%v", releasedStatus, releaseReason, releasedUserID)
	}

	activated := registrationTestUser("pending-admin-activate", models.UserStatusPending)
	createdAt := now.Add(-2 * time.Hour)
	if _, err := store.CreateRegistration(context.Background(), activated, user.RegistrationCommitOptions{
		InviteCodeHash: &codeHash, ExpiresAt: now.Add(-time.Hour), Now: createdAt,
		Mode: "invite_only", Verification: validPreparedVerification(activated, createdAt, now.Add(-time.Hour)),
	}); err != nil {
		t.Fatalf("create expired pending activation registration: %v", err)
	}
	activeStatus := models.UserStatusActive
	updated, err := service.AdminUpdate(context.Background(), activated.ID, models.AdminUpdateUserRequest{Status: &activeStatus}, registrationMutation(models.AuditUserActivated))
	if err != nil {
		t.Fatalf("activate expired pending registration: %v", err)
	}
	if updated.Status != models.UserStatusActive {
		t.Fatalf("activated status = %s", updated.Status)
	}
	if err := service.Delete(context.Background(), activated.ID, registrationMutation(models.AuditUserDeleted)); err != nil {
		t.Fatalf("delete completed registration user: %v", err)
	}
	var completedStatus string
	var completedUserID *uuid.UUID
	if err := schema.pool.QueryRow(context.Background(), `
		SELECT status,user_id FROM self_registrations WHERE invite_id=$1 AND status='completed'
	`, inviteID).Scan(&completedStatus, &completedUserID); err != nil {
		t.Fatalf("read completed registration after user deletion: %v", err)
	}
	if completedStatus != registration.StatusCompleted || completedUserID != nil {
		t.Fatalf("completed registration after deletion: status=%s user=%v", completedStatus, completedUserID)
	}

	expired := registrationTestUser("pending-cleanup", models.UserStatusPending)
	if _, err := store.CreateRegistration(context.Background(), expired, user.RegistrationCommitOptions{
		InviteCodeHash: &codeHash, ExpiresAt: now.Add(-30 * time.Minute), Now: createdAt,
		Mode: "invite_only", Verification: validPreparedVerification(expired, createdAt, now.Add(-30*time.Minute)),
	}); err != nil {
		t.Fatalf("create cleanup registration: %v", err)
	}
	cleanup, err := registration.NewStore(schema.pool).CleanupExpired(context.Background(), now, 10, 2)
	if err != nil {
		t.Fatalf("cleanup expired registrations: %v", err)
	}
	if !cleanup.LockAcquired || cleanup.Released != 1 || cleanup.DeletedUsers != 1 {
		t.Fatalf("cleanup result = %#v", cleanup)
	}
	if count := countRegistrationRows(t, schema, `SELECT COUNT(*) FROM users WHERE id=$1`, expired.ID); count != 0 {
		t.Fatalf("expired pending user survived cleanup: %d", count)
	}

	item := registrationInviteByID(t, schema, inviteID, now)
	if item.UsedCount != 1 || item.ReservedCount != 0 {
		t.Fatalf("invite counts after lifecycle operations = %#v", item)
	}
	if err := service.Delete(context.Background(), creator.ID, registrationMutation(models.AuditUserDeleted)); err != nil {
		t.Fatalf("delete invite creator: %v", err)
	}
	item = registrationInviteByID(t, schema, inviteID, now)
	if item.CreatedBy != nil || item.UsedCount != 1 {
		t.Fatalf("invite after creator deletion = %#v", item)
	}

	for _, event := range []string{models.AuditInviteReleased, models.AuditInviteConsumed, models.AuditRegistrationExpired} {
		if count := countRegistrationRows(t, schema, `SELECT COUNT(*) FROM audit_event_outbox WHERE event=$1`, event); count == 0 {
			t.Fatalf("missing lifecycle audit event %s", event)
		}
	}
}

func TestPendingVerificationResendKeepsPersistedDeadline(t *testing.T) {
	schema := newMigratedRegistrationSchema(t)
	createdAt := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
	now := createdAt.Add(2 * time.Hour)
	deadline := now.Add(3 * time.Hour)
	firstToken := "first-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	secondToken := "second-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	clock := createdAt
	accountService := newRegistrationAccountService(t, schema, &clock, firstToken, secondToken)
	u := registrationTestUser("resend-pending", models.UserStatusPending)
	createPendingRegistration(t, schema, accountService, u, nil, createdAt, deadline)
	active := registrationTestUser("resend-active", models.UserStatusActive)
	insertRegistrationTestUser(t, schema, active)

	clock = now
	for _, email := range []string{"unknown@example.test", *active.Email} {
		if err := accountService.RequestPendingEmailVerification(context.Background(), email, account.RequestMetadata{}); err != nil {
			t.Fatalf("enumeration-safe resend for %s: %v", email, err)
		}
	}
	if count := countRegistrationRows(t, schema, `SELECT COUNT(*) FROM account_action_tokens WHERE user_id=$1`, u.ID); count != 1 {
		t.Fatalf("unknown/active resend changed pending actions: %d", count)
	}

	if err := accountService.RequestPendingEmailVerification(context.Background(), *u.Email, account.RequestMetadata{}); err != nil {
		t.Fatalf("resend pending verification: %v", err)
	}
	var activeExpiry time.Time
	if err := schema.pool.QueryRow(context.Background(), `
		SELECT expires_at FROM account_action_tokens
		WHERE user_id=$1 AND action='email_verification' AND consumed_at IS NULL AND revoked_at IS NULL
	`, u.ID).Scan(&activeExpiry); err != nil {
		t.Fatalf("read resent verification action: %v", err)
	}
	if !activeExpiry.Equal(deadline) {
		t.Fatalf("resent verification expiry = %s, want %s", activeExpiry, deadline)
	}
	if count := countRegistrationRows(t, schema, `SELECT COUNT(*) FROM account_action_tokens WHERE user_id=$1`, u.ID); count != 2 {
		t.Fatalf("verification action count after resend = %d", count)
	}
	if count := countRegistrationRows(t, schema, `SELECT COUNT(*) FROM email_outbox WHERE user_id=$1`, u.ID); count != 2 {
		t.Fatalf("verification email count after resend = %d", count)
	}

	if _, err := schema.pool.Exec(context.Background(), `UPDATE self_registrations SET expires_at=$2 WHERE user_id=$1`, u.ID, now.Add(-time.Minute)); err != nil {
		t.Fatalf("expire pending registration: %v", err)
	}
	if err := accountService.RequestPendingEmailVerification(context.Background(), *u.Email, account.RequestMetadata{}); err != nil {
		t.Fatalf("expired resend must stay enumeration-safe: %v", err)
	}
	if count := countRegistrationRows(t, schema, `SELECT COUNT(*) FROM account_action_tokens WHERE user_id=$1`, u.ID); count != 2 {
		t.Fatalf("expired resend created another action: %d", count)
	}
}
