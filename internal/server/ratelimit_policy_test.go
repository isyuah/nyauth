package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/securityaction"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

func TestRateLimitPolicyUsesRuntimeProtection(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	ctx := context.Background()

	setProtection := func(t *testing.T, value settings.Protection) int64 {
		t.Helper()
		confirmation := ""
		if settings.ProtectionDisables(testApp.app.settingsMgr.Protection(), value) {
			confirmation = settings.ProtectionDisableConfirmation
		}
		revision, err := testApp.app.settingsMgr.SetProtection(
			ctx,
			value,
			testApp.app.settingsMgr.ProtectionSnapshot().Revision,
			"rate-limit-policy-test",
			confirmation,
			audit.MutationAudit{
				Event: models.AuditSettingsUpdated, ActorID: uuid.New(),
				ActorName: "rate-limit-policy-test", Result: "success", RiskLevel: "critical",
			},
		)
		if err != nil {
			t.Fatalf("set protection policy: %v", err)
		}
		return revision
	}

	t.Run("revision changes isolate Redis counters", func(t *testing.T) {
		if err := testApp.app.rdb.FlushDB(ctx).Err(); err != nil {
			t.Fatalf("flush rate-limit Redis database: %v", err)
		}
		policy := settings.DefaultProtection()
		policy.Account.Window = "10s"
		policy.Account.SubjectLimit = 1
		policy.Account.IPLimit = 100
		firstRevision := setProtection(t, policy)

		allowed, _, err := testApp.app.accountLimiter.Reserve(ctx, securityaction.AccountEmailVerification, "192.0.2.80", "user-1")
		if err != nil || !allowed {
			t.Fatalf("first reservation: allowed=%v err=%v", allowed, err)
		}
		allowed, retry, err := testApp.app.accountLimiter.Reserve(ctx, securityaction.AccountEmailVerification, "192.0.2.80", "user-1")
		if err != nil || allowed || retry <= 0 {
			t.Fatalf("limited reservation: allowed=%v retry=%v err=%v", allowed, retry, err)
		}

		secondRevision := setProtection(t, policy)
		allowed, _, err = testApp.app.accountLimiter.Reserve(ctx, securityaction.AccountEmailVerification, "192.0.2.80", "user-1")
		if err != nil || !allowed {
			t.Fatalf("reservation after revision change: allowed=%v err=%v", allowed, err)
		}
		if secondRevision <= firstRevision {
			t.Fatalf("protection revision did not advance: first=%d second=%d", firstRevision, secondRevision)
		}

		firstPrefix := rateLimitNamespace("account", firstRevision) + ":"
		secondPrefix := rateLimitNamespace("account", secondRevision) + ":"
		var foundFirst, foundSecond bool
		for _, key := range testApp.mini.Keys() {
			foundFirst = foundFirst || strings.HasPrefix(key, firstPrefix)
			foundSecond = foundSecond || strings.HasPrefix(key, secondPrefix)
		}
		if !foundFirst || !foundSecond {
			t.Fatalf("revision-isolated Redis keys missing: first=%v second=%v keys=%v", foundFirst, foundSecond, testApp.mini.Keys())
		}
	})

	unavailableRedis := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:1", MaxRetries: -1,
		DialTimeout: 50 * time.Millisecond, ReadTimeout: 50 * time.Millisecond, WriteTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(func() { _ = unavailableRedis.Close() })

	t.Run("disabled group does not access unavailable Redis", func(t *testing.T) {
		policy := testApp.app.settingsMgr.Protection()
		policy.Account.Enabled = false
		setProtection(t, policy)
		limiter := NewAccountActionLimiter(unavailableRedis, testApp.app.settingsMgr)

		allowed, retry, err := limiter.Reserve(ctx, securityaction.AccountEmailVerification, "192.0.2.81", "user-2")
		if err != nil || !allowed || retry != 0 {
			t.Fatalf("disabled limiter: allowed=%v retry=%v err=%v", allowed, retry, err)
		}
	})

	t.Run("enabled group fails closed when Redis is unavailable", func(t *testing.T) {
		policy := testApp.app.settingsMgr.Protection()
		policy.Account.Enabled = true
		setProtection(t, policy)
		limiter := NewAccountActionLimiter(unavailableRedis, testApp.app.settingsMgr)

		allowed, retry, err := limiter.Reserve(ctx, securityaction.AccountEmailVerification, "192.0.2.82", "user-3")
		if err == nil || allowed || retry != 0 {
			t.Fatalf("enabled limiter with unavailable Redis: allowed=%v retry=%v err=%v", allowed, retry, err)
		}
	})
}
