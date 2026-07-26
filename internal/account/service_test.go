package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

const testRawToken = "fixed-account-action-token-with-more-than-32-bytes"

var (
	testNow = time.Date(2026, time.July, 26, 8, 30, 0, 0, time.UTC)
	testKey = []byte("0123456789abcdef0123456789abcdef")
)

type fakeServiceStore struct {
	user                 *models.User
	lookupErr            error
	emailInUse           bool
	action               *ActionToken
	queuedEmail          *OutboxEmail
	consumePasswordHash  string
	consumeExpectedEmail string
	consumePreviousEmail string
	consumeNewEmail      string
	consumeNotices       []*OutboxEmail
	consumeErr           error
	verificationDuration *time.Duration
	pendingExpiresAt     time.Time
}

func (f *fakeServiceStore) GetUserByID(context.Context, uuid.UUID) (*models.User, error) {
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	return f.user, nil
}

func (f *fakeServiceStore) GetUserByEmail(context.Context, string) (*models.User, error) {
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	return f.user, nil
}

func (f *fakeServiceStore) GetPendingRegistrationByEmail(context.Context, string, time.Time) (*models.User, time.Time, error) {
	if f.lookupErr != nil {
		return nil, time.Time{}, f.lookupErr
	}
	return f.user, f.pendingExpiresAt, nil
}

func (f *fakeServiceStore) EmailInUse(context.Context, string, uuid.UUID) (bool, error) {
	return f.emailInUse, nil
}

func (f *fakeServiceStore) ReplaceActionAndQueueEmail(_ context.Context, action *ActionToken, email *OutboxEmail) error {
	f.action = action
	f.queuedEmail = email
	return nil
}

func (f *fakeServiceStore) ReplacePendingVerificationAndQueueEmail(_ context.Context, _ string, action *ActionToken, email *OutboxEmail, _ time.Time) error {
	f.action = action
	f.queuedEmail = email
	return nil
}

func (f *fakeServiceStore) GetUsableAction(_ context.Context, tokenHash []byte, action Action, now time.Time) (*ActionToken, error) {
	if f.action == nil || f.action.Action != action || !bytes.Equal(f.action.TokenHash, tokenHash) || !f.action.ExpiresAt.After(now) {
		return nil, ErrInvalidActionToken
	}
	return f.action, nil
}

func (f *fakeServiceStore) ConsumePasswordReset(_ context.Context, _ *ActionToken, expectedEmail, passwordHash string, notices []*OutboxEmail, _ time.Time) (*models.User, error) {
	f.consumeExpectedEmail = expectedEmail
	f.consumePasswordHash = passwordHash
	f.consumeNotices = notices
	if f.consumeErr != nil {
		return nil, f.consumeErr
	}
	updated := *f.user
	updated.AuthVersion++
	return &updated, nil
}

func (f *fakeServiceStore) ConsumeEmailVerification(_ context.Context, _ *ActionToken, expectedEmail string, _ time.Time) (*models.User, *time.Duration, error) {
	f.consumeExpectedEmail = expectedEmail
	if f.consumeErr != nil {
		return nil, nil, f.consumeErr
	}
	updated := *f.user
	updated.EmailVerifiedAt = &testNow
	return &updated, f.verificationDuration, nil
}

func (f *fakeServiceStore) ConsumeEmailChange(_ context.Context, _ *ActionToken, previousEmail, newEmail string, notices []*OutboxEmail, _ time.Time) (*models.User, error) {
	f.consumePreviousEmail = previousEmail
	f.consumeNewEmail = newEmail
	f.consumeNotices = notices
	if f.consumeErr != nil {
		return nil, f.consumeErr
	}
	updated := *f.user
	updated.Email = &newEmail
	updated.EmailVerifiedAt = &testNow
	updated.AuthVersion++
	return &updated, nil
}

func newTestService(t *testing.T, store *fakeServiceStore) *Service {
	t.Helper()
	service, err := newService(store, ServiceOptions{
		PublicBaseURL: "https://auth.example.test/base",
		ActiveKeyID:   "primary",
		MasterKeys:    map[string][]byte{"primary": testKey},
		Clock:         func() time.Time { return testNow },
		GenerateToken: func() (string, error) { return testRawToken, nil },
	})
	if err != nil {
		t.Fatalf("newService: %v", err)
	}
	return service
}

func TestServicePublicBaseURLCanBeUpdatedForNewMessages(t *testing.T) {
	service := newTestService(t, &fakeServiceStore{})
	before, err := service.actionMessage(ActionEmailVerification, "alice@example.test", testRawToken, time.Hour)
	if err != nil {
		t.Fatalf("actionMessage(before): %v", err)
	}
	if err := service.SetPublicBaseURL("https://new-auth.example.test/prefix"); err != nil {
		t.Fatalf("SetPublicBaseURL: %v", err)
	}
	after, err := service.actionMessage(ActionEmailVerification, "alice@example.test", testRawToken, time.Hour)
	if err != nil {
		t.Fatalf("actionMessage(after): %v", err)
	}
	if !strings.Contains(before.TextBody, "https://auth.example.test/base/verify-email") ||
		!strings.Contains(after.TextBody, "https://new-auth.example.test/prefix/verify-email") {
		t.Fatalf("unexpected links before=%q after=%q", before.TextBody, after.TextBody)
	}
	if err := service.SetPublicBaseURL("https://user:secret@example.test"); err == nil {
		t.Fatal("SetPublicBaseURL accepted credentials")
	}
}

func activeVerifiedUser() *models.User {
	email := "alice@example.test"
	verifiedAt := testNow.Add(-24 * time.Hour)
	return &models.User{
		ID: uuid.New(), Username: "alice", Email: &email, EmailVerifiedAt: &verifiedAt,
		Status: models.UserStatusActive, AuthVersion: 3, Metadata: map[string]string{},
	}
}

func TestBuildSecurityNotificationEncryptsWhitelistedTemplateAndSkipsUnavailableEmail(t *testing.T) {
	service := newTestService(t, &fakeServiceStore{})
	accountUser := activeVerifiedUser()
	outbox, err := service.BuildSecurityNotification(accountUser, SecurityNotice{
		MessageType: MessageRoleChanged, Role: "admin",
	})
	if err != nil {
		t.Fatalf("BuildSecurityNotification: %v", err)
	}
	if outbox == nil || outbox.MessageType != MessageRoleChanged {
		t.Fatalf("security notification was not prepared: %#v", outbox)
	}
	if strings.Contains(outbox.EncryptedMessage, "alice@example.test") || strings.Contains(outbox.EncryptedMessage, "admin") {
		t.Fatal("security notification persisted plaintext content")
	}
	plaintext, err := crypto.DecryptEnvelope(
		map[string][]byte{"primary": testKey}, emailEnvelopePurpose, outbox.EncryptedMessage,
		emailAAD(outbox.ID, outbox.MessageType, accountUser.ID),
	)
	if err != nil {
		t.Fatalf("decrypt security notification: %v", err)
	}
	var message EmailMessage
	if err := json.Unmarshal(plaintext, &message); err != nil {
		t.Fatalf("decode security notification: %v", err)
	}
	if message.To != "alice@example.test" || !strings.Contains(message.TextBody, "admin") {
		t.Fatalf("unexpected security notification: %#v", message)
	}

	unverified := *accountUser
	unverified.EmailVerifiedAt = nil
	if skipped, err := service.BuildSecurityNotification(&unverified, SecurityNotice{MessageType: MessagePasswordChanged}); err != nil || skipped != nil {
		t.Fatalf("unverified email notification = %#v, %v", skipped, err)
	}
	missing := *accountUser
	missing.Email = nil
	if skipped, err := service.BuildSecurityNotification(&missing, SecurityNotice{MessageType: MessagePasswordChanged}); err != nil || skipped != nil {
		t.Fatalf("missing email notification = %#v, %v", skipped, err)
	}
	if _, err := service.BuildSecurityNotification(accountUser, SecurityNotice{MessageType: MessageIdentityBound, Provider: "github<script>"}); err == nil {
		t.Fatal("unsafe provider label was accepted in a security notification")
	}
}

func TestRequestPasswordResetQueuesHashedEncryptedAction(t *testing.T) {
	store := &fakeServiceStore{user: activeVerifiedUser()}
	service := newTestService(t, store)
	if err := service.RequestPasswordReset(context.Background(), " Alice@Example.Test ", RequestMetadata{
		IPAddress: "203.0.113.8", UserAgent: "test-browser",
	}); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if store.action == nil || store.queuedEmail == nil {
		t.Fatal("password reset action and email were not queued")
	}
	if bytes.Equal(store.action.TokenHash, []byte(testRawToken)) || len(store.action.TokenHash) != 32 {
		t.Fatalf("token was not stored as a SHA-256 digest: %x", store.action.TokenHash)
	}
	if strings.Contains(store.action.PayloadCiphertext, testRawToken) || strings.Contains(store.queuedEmail.EncryptedMessage, testRawToken) {
		t.Fatal("raw action token leaked into persisted ciphertext representation")
	}
	if store.action.RequestedIP == nil || *store.action.RequestedIP != "203.0.113.8" {
		t.Fatalf("requested IP = %v", store.action.RequestedIP)
	}
	plaintext, err := crypto.DecryptEnvelope(
		map[string][]byte{"primary": testKey}, emailEnvelopePurpose, store.queuedEmail.EncryptedMessage,
		emailAAD(store.queuedEmail.ID, store.queuedEmail.MessageType, store.user.ID),
	)
	if err != nil {
		t.Fatalf("decrypt queued email: %v", err)
	}
	var message EmailMessage
	if err := json.Unmarshal(plaintext, &message); err != nil {
		t.Fatalf("decode queued email: %v", err)
	}
	if message.To != "alice@example.test" || !strings.Contains(message.TextBody, "https://auth.example.test/base/reset-password?token=") || !strings.Contains(message.TextBody, testRawToken) {
		t.Fatalf("unexpected password reset message: %#v", message)
	}
}

func TestRequestPasswordResetDoesNotRevealMissingOrUnverifiedAccount(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		store := &fakeServiceStore{lookupErr: pgx.ErrNoRows}
		if err := newTestService(t, store).RequestPasswordReset(context.Background(), "missing@example.test", RequestMetadata{}); err != nil {
			t.Fatalf("missing account returned an observable error: %v", err)
		}
		if store.action != nil {
			t.Fatal("missing account queued an action")
		}
	})
	t.Run("unverified", func(t *testing.T) {
		accountUser := activeVerifiedUser()
		accountUser.EmailVerifiedAt = nil
		store := &fakeServiceStore{user: accountUser}
		if err := newTestService(t, store).RequestPasswordReset(context.Background(), *accountUser.Email, RequestMetadata{}); err != nil {
			t.Fatalf("unverified account returned an observable error: %v", err)
		}
		if store.action != nil {
			t.Fatal("unverified account queued a password reset")
		}
	})
	t.Run("malformed", func(t *testing.T) {
		store := &fakeServiceStore{}
		if err := newTestService(t, store).RequestPasswordReset(context.Background(), "not-an-email", RequestMetadata{}); err != nil {
			t.Fatalf("malformed address returned an observable error: %v", err)
		}
	})
}

func TestConfirmPasswordResetUsesBoundClaimsAndQueuesNotification(t *testing.T) {
	store := &fakeServiceStore{user: activeVerifiedUser()}
	service := newTestService(t, store)
	if err := service.RequestPasswordReset(context.Background(), *store.user.Email, RequestMetadata{}); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	updated, err := service.ConfirmPasswordReset(context.Background(), testRawToken, "a-new-secure-password")
	if err != nil {
		t.Fatalf("ConfirmPasswordReset: %v", err)
	}
	if updated.AuthVersion != store.user.AuthVersion+1 {
		t.Fatalf("auth version = %d, want %d", updated.AuthVersion, store.user.AuthVersion+1)
	}
	if store.consumeExpectedEmail != "alice@example.test" || len(store.consumeNotices) != 1 {
		t.Fatalf("consume binding email=%q notices=%d", store.consumeExpectedEmail, len(store.consumeNotices))
	}
	valid, err := crypto.VerifyPassword("a-new-secure-password", store.consumePasswordHash)
	if err != nil || !valid {
		t.Fatalf("replacement password hash is invalid: valid=%v err=%v", valid, err)
	}
	if _, err := service.ConfirmPasswordReset(context.Background(), "wrong-token-with-at-least-thirty-two-bytes", "a-new-secure-password"); !errors.Is(err, ErrInvalidActionToken) {
		t.Fatalf("wrong token error = %v, want ErrInvalidActionToken", err)
	}
}

func TestActionEnvelopeIsBoundToUserAndAction(t *testing.T) {
	store := &fakeServiceStore{user: activeVerifiedUser()}
	store.user.EmailVerifiedAt = nil
	service := newTestService(t, store)
	if err := service.RequestEmailVerification(context.Background(), store.user.ID, RequestMetadata{}); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	store.action.UserID = uuid.New()
	if _, err := service.ConfirmEmailVerification(context.Background(), testRawToken); !errors.Is(err, ErrInvalidActionToken) {
		t.Fatalf("tampered action binding error = %v, want ErrInvalidActionToken", err)
	}
}

func TestPendingEmailVerificationReportsCommittedDuration(t *testing.T) {
	duration := 3*time.Hour + 15*time.Minute
	store := &fakeServiceStore{user: activeVerifiedUser(), verificationDuration: &duration}
	store.user.EmailVerifiedAt = nil
	var observed time.Duration
	service, err := newService(store, ServiceOptions{
		PublicBaseURL: "https://auth.example.test/base",
		ActiveKeyID:   "primary",
		MasterKeys:    map[string][]byte{"primary": testKey},
		Clock:         func() time.Time { return testNow },
		GenerateToken: func() (string, error) { return testRawToken, nil },
		OnEmailVerified: func(_ context.Context, current time.Duration) {
			observed = current
		},
	})
	if err != nil {
		t.Fatalf("newService: %v", err)
	}
	if err := service.RequestEmailVerification(context.Background(), store.user.ID, RequestMetadata{}); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	if _, err := service.ConfirmEmailVerification(context.Background(), testRawToken); err != nil {
		t.Fatalf("ConfirmEmailVerification: %v", err)
	}
	if observed != duration {
		t.Fatalf("verification duration = %s, want %s", observed, duration)
	}
}

func TestEmailChangeRequiresRecentAuthenticationAndQueuesBothNotices(t *testing.T) {
	store := &fakeServiceStore{user: activeVerifiedUser()}
	service := newTestService(t, store)
	if err := service.RequestEmailChange(context.Background(), store.user.ID, "new@example.test", testNow.Add(-11*time.Minute), RequestMetadata{}); !errors.Is(err, ErrRecentAuthenticationRequired) {
		t.Fatalf("stale authentication error = %v", err)
	}
	if err := service.RequestEmailChange(context.Background(), store.user.ID, "new@example.test", testNow.Add(-5*time.Minute), RequestMetadata{}); err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	updated, err := service.ConfirmEmailChange(context.Background(), testRawToken)
	if err != nil {
		t.Fatalf("ConfirmEmailChange: %v", err)
	}
	if updated.Email == nil || *updated.Email != "new@example.test" || updated.AuthVersion != store.user.AuthVersion+1 {
		t.Fatalf("unexpected updated user: %#v", updated)
	}
	if store.consumePreviousEmail != "alice@example.test" || store.consumeNewEmail != "new@example.test" || len(store.consumeNotices) != 2 {
		t.Fatalf("email change binding old=%q new=%q notices=%d", store.consumePreviousEmail, store.consumeNewEmail, len(store.consumeNotices))
	}
}

func TestEmailChangeRejectsAddressAlreadyInUse(t *testing.T) {
	store := &fakeServiceStore{user: activeVerifiedUser(), emailInUse: true}
	service := newTestService(t, store)
	err := service.RequestEmailChange(context.Background(), store.user.ID, "used@example.test", testNow, RequestMetadata{})
	if !errors.Is(err, ErrEmailInUse) {
		t.Fatalf("error = %v, want ErrEmailInUse", err)
	}
}
