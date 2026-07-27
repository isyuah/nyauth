package database_test

import (
	"context"
	"encoding/base32"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/mfa"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestMFAChallengeGateRollsBackFactorConsumption(t *testing.T) {
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
	current := registrationTestUser("mfa-gate-rollback", models.UserStatusActive)
	insertRegistrationTestUser(t, schema, current)
	now := time.Now().UTC().Truncate(30 * time.Second)
	enrollment, err := service.BeginEnrollment(ctx, current.ID, "Nyauth Test", current.Username, now)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32NoPaddingDecode(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	auditContext := mfa.AuditContext{ActorID: current.ID, ActorName: current.Username}
	recoveryCodes, err := service.ConfirmEnrollment(
		ctx, current.ID, mfa.AuthenticationBinding{
			AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
		}, integrationTOTPCode(secret, now.Unix()/30), auditContext, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	current, err = user.NewService(user.NewStore(schema.pool)).GetByID(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	gateFailure := errors.New("redis unavailable")
	gate := mfa.ChallengeCommitGate{
		AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
		Consume: func(context.Context) error { return gateFailure },
	}

	next := now.Add(30 * time.Second)
	nextCode := integrationTOTPCode(secret, next.Unix()/30)
	if err := service.VerifyTOTPChallenge(ctx, current.ID, nextCode, next, gate); !errors.Is(err, gateFailure) {
		t.Fatalf("TOTP gate failure=%v", err)
	}
	if err := service.VerifyTOTP(ctx, current.ID, nextCode, next); err != nil {
		t.Fatalf("TOTP step was not rolled back after gate failure: %v", err)
	}

	if err := service.ConsumeRecoveryCodeChallenge(
		ctx, current.ID, recoveryCodes[0], auditContext, next, gate,
	); !errors.Is(err, gateFailure) {
		t.Fatalf("recovery-code gate failure=%v", err)
	}
	if err := service.ConsumeRecoveryCode(ctx, current.ID, recoveryCodes[0], auditContext, next); err != nil {
		t.Fatalf("recovery code was not rolled back after gate failure: %v", err)
	}

	var challengeConsumed atomic.Bool
	concurrentGate := mfa.ChallengeCommitGate{
		AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
		Consume: func(context.Context) error {
			if challengeConsumed.CompareAndSwap(false, true) {
				return nil
			}
			return session.ErrNotFound
		},
	}
	type result struct {
		index int
		err   error
	}
	results := make(chan result, 2)
	for index := 1; index <= 2; index++ {
		index := index
		go func() {
			results <- result{index: index, err: service.ConsumeRecoveryCodeChallenge(
				ctx, current.ID, recoveryCodes[index], auditContext, next, concurrentGate,
			)}
		}()
	}
	succeeded := 0
	loser := -1
	for range 2 {
		result := <-results
		switch {
		case result.err == nil:
			succeeded++
		case errors.Is(result.err, session.ErrNotFound):
			loser = result.index
		default:
			t.Fatalf("unexpected concurrent recovery-code error: %v", result.err)
		}
	}
	if succeeded != 1 || loser < 0 {
		t.Fatalf("concurrent results: succeeded=%d loser=%d", succeeded, loser)
	}
	if err := service.ConsumeRecoveryCode(ctx, current.ID, recoveryCodes[loser], auditContext, next); err != nil {
		t.Fatalf("losing recovery code was consumed despite gate failure: %v", err)
	}
	status, err := service.Status(ctx, current.ID)
	if err != nil || status.RecoveryCodesRemaining != 7 {
		t.Fatalf("recovery-code status=%#v err=%v", status, err)
	}
}

func TestMFAChallengeRejectsChangedAuthenticationStateBeforeConsumption(t *testing.T) {
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
	current := registrationTestUser("mfa-gate-version", models.UserStatusActive)
	insertRegistrationTestUser(t, schema, current)
	now := time.Now().UTC().Truncate(30 * time.Second)
	enrollment, err := service.BeginEnrollment(ctx, current.ID, "Nyauth Test", current.Username, now)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32NoPaddingDecode(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConfirmEnrollment(
		ctx, current.ID, mfa.AuthenticationBinding{
			AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
		}, integrationTOTPCode(secret, now.Unix()/30),
		mfa.AuditContext{ActorID: current.ID, ActorName: current.Username}, now,
	); err != nil {
		t.Fatal(err)
	}
	current, err = user.NewService(user.NewStore(schema.pool)).GetByID(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := schema.pool.Exec(ctx, `UPDATE users SET auth_version=auth_version+1 WHERE id=$1`, current.ID); err != nil {
		t.Fatal(err)
	}
	var gateCalled atomic.Bool
	gate := mfa.ChallengeCommitGate{
		AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
		Consume: func(context.Context) error {
			gateCalled.Store(true)
			return nil
		},
	}
	next := now.Add(30 * time.Second)
	nextCode := integrationTOTPCode(secret, next.Unix()/30)
	if err := service.VerifyTOTPChallenge(ctx, current.ID, nextCode, next, gate); !errors.Is(err, mfa.ErrAuthenticationChanged) {
		t.Fatalf("changed authentication state error=%v", err)
	}
	if gateCalled.Load() {
		t.Fatal("pending challenge was consumed after authentication state changed")
	}
	if err := service.VerifyTOTP(ctx, current.ID, nextCode, next); err != nil {
		t.Fatalf("TOTP step was consumed for a stale challenge: %v", err)
	}
}

func base32NoPaddingDecode(value string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(value)
}
