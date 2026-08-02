package server

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/nyasharp/nyauth/internal/securityaction"
	"github.com/redis/go-redis/v9"
)

func TestLoginLimiterEnforcesIdentityLimitAcrossIPsAndResetsByIdentity(t *testing.T) {
	t.Parallel()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	limiter := NewLoginLimiter(rdb)
	ctx := context.Background()
	const username = "same-user"

	for attempt := 0; attempt < 5; attempt++ {
		ip := fmt.Sprintf("192.0.2.%d", attempt+1)
		allowed, _, err := limiter.Reserve(ctx, ip, username)
		if err != nil || !allowed {
			t.Fatalf("cross-IP login attempt %d: allowed=%v err=%v", attempt+1, allowed, err)
		}
	}
	allowed, retry, err := limiter.Reserve(ctx, "198.51.100.1", username)
	if err != nil {
		t.Fatalf("limited cross-IP login: %v", err)
	}
	if allowed || retry <= 0 {
		t.Fatalf("cross-IP identity limit: allowed=%v retry=%v", allowed, retry)
	}

	if err := limiter.ResetIdentity(ctx, "203.0.113.9", username); err != nil {
		t.Fatalf("reset identity: %v", err)
	}
	allowed, _, err = limiter.Reserve(ctx, "203.0.113.10", username)
	if err != nil || !allowed {
		t.Fatalf("login after identity reset: allowed=%v err=%v", allowed, err)
	}
}

func TestMailSettingsLimiterUsesRelaxedIndependentOperationBuckets(t *testing.T) {
	t.Parallel()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	limiter := NewMailSettingsLimiter(rdb)
	ctx := context.Background()
	const ip = "192.0.2.40"
	const adminID = "admin-user-id"

	for attempt := 1; attempt <= 30; attempt++ {
		allowed, _, err := limiter.Reserve(ctx, securityaction.MailCandidateTest, ip, adminID)
		if err != nil || !allowed {
			t.Fatalf("candidate test attempt %d: allowed=%v err=%v", attempt, allowed, err)
		}
	}
	allowed, retry, err := limiter.Reserve(ctx, securityaction.MailCandidateTest, ip, adminID)
	if err != nil {
		t.Fatalf("limited candidate test: %v", err)
	}
	if allowed || retry <= 0 {
		t.Fatalf("candidate test limit: allowed=%v retry=%v", allowed, retry)
	}

	for attempt := 1; attempt <= 60; attempt++ {
		allowed, _, err = limiter.Reserve(ctx, securityaction.MailCandidateSave, ip, adminID)
		if err != nil || !allowed {
			t.Fatalf("candidate save attempt %d: allowed=%v err=%v", attempt, allowed, err)
		}
	}
	allowed, retry, err = limiter.Reserve(ctx, securityaction.MailCandidateSave, ip, adminID)
	if err != nil {
		t.Fatalf("limited candidate save: %v", err)
	}
	if allowed || retry <= 0 {
		t.Fatalf("candidate save limit: allowed=%v retry=%v", allowed, retry)
	}

	allowed, _, err = limiter.Reserve(ctx, securityaction.MailActivate, ip, adminID)
	if err != nil || !allowed {
		t.Fatalf("independent activate bucket: allowed=%v err=%v", allowed, err)
	}

	for _, key := range mini.Keys() {
		if !strings.HasPrefix(key, "nyauth:mail-settings-limit:") {
			continue
		}
		if strings.Contains(key, ip) || strings.Contains(key, adminID) {
			t.Fatalf("mail settings rate-limit key exposes private input: %q", key)
		}
	}
}

func TestMailSettingsLimiterEnforcesSharedIPLimit(t *testing.T) {
	t.Parallel()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	limiter := NewMailSettingsLimiter(rdb)
	ctx := context.Background()
	const ip = "192.0.2.41"

	for attempt := 0; attempt < 200; attempt++ {
		adminID := fmt.Sprintf("admin-%d", attempt/30)
		allowed, _, err := limiter.Reserve(ctx, securityaction.MailCandidateTest, ip, adminID)
		if err != nil || !allowed {
			t.Fatalf("shared IP attempt %d: allowed=%v err=%v", attempt+1, allowed, err)
		}
	}
	allowed, retry, err := limiter.Reserve(ctx, securityaction.MailCandidateTest, ip, "admin-6")
	if err != nil {
		t.Fatalf("limited shared IP request: %v", err)
	}
	if allowed || retry <= 0 {
		t.Fatalf("shared IP limit: allowed=%v retry=%v", allowed, retry)
	}
}

func TestMailSettingsLimiterEnforcesSubjectLimitAcrossIPs(t *testing.T) {
	t.Parallel()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	limiter := NewMailSettingsLimiter(rdb)
	ctx := context.Background()
	const adminID = "admin-user-id"

	for attempt := 0; attempt < 30; attempt++ {
		ip := fmt.Sprintf("192.0.2.%d", attempt+1)
		allowed, _, err := limiter.Reserve(ctx, securityaction.MailCandidateTest, ip, adminID)
		if err != nil || !allowed {
			t.Fatalf("cross-IP subject attempt %d: allowed=%v err=%v", attempt+1, allowed, err)
		}
	}
	allowed, retry, err := limiter.Reserve(ctx, securityaction.MailCandidateTest, "198.51.100.1", adminID)
	if err != nil {
		t.Fatalf("limited cross-IP subject request: %v", err)
	}
	if allowed || retry <= 0 {
		t.Fatalf("cross-IP subject limit: allowed=%v retry=%v", allowed, retry)
	}
}

func TestMailSettingsLimiterRejectsUnknownOperation(t *testing.T) {
	t.Parallel()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	limiter := NewMailSettingsLimiter(rdb)

	allowed, _, err := limiter.Reserve(context.Background(), securityaction.MailOperation(255), "192.0.2.42", "admin")
	if err == nil || allowed {
		t.Fatalf("unknown operation: allowed=%v err=%v", allowed, err)
	}
	if len(mini.Keys()) != 0 {
		t.Fatalf("unknown operation created Redis keys: %v", mini.Keys())
	}
}

func TestAccountLimiterRejectsUnknownOperationBeforeRedis(t *testing.T) {
	t.Parallel()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	limiter := NewAccountActionLimiter(rdb)

	allowed, _, err := limiter.Reserve(context.Background(), securityaction.AccountOperation(255), "192.0.2.43", "user")
	if err == nil || allowed {
		t.Fatalf("unknown operation: allowed=%v err=%v", allowed, err)
	}
	if len(mini.Keys()) != 0 {
		t.Fatalf("unknown operation created Redis keys: %v", mini.Keys())
	}
}

func TestMediaMutationLimiterUsesIndependentReasonableBuckets(t *testing.T) {
	t.Parallel()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	limiter := NewMediaMutationLimiter(rdb)
	ctx := context.Background()
	operations := []securityaction.MediaOperation{
		securityaction.MediaAvatarUpload,
		securityaction.MediaAvatarDelete,
		securityaction.MediaClientLogoUpload,
		securityaction.MediaClientLogoDelete,
	}
	for _, operation := range operations {
		allowed, _, err := limiter.Reserve(ctx, operation, "192.0.2.50", "user-1")
		if err != nil || !allowed {
			t.Fatalf("initial operation %d allowed=%v err=%v", operation, allowed, err)
		}
	}
	for attempt := 2; attempt <= 30; attempt++ {
		allowed, _, err := limiter.Reserve(ctx, securityaction.MediaClientLogoUpload, "192.0.2.50", "user-1")
		if err != nil || !allowed {
			t.Fatalf("client logo upload attempt %d allowed=%v err=%v", attempt, allowed, err)
		}
	}
	allowed, retry, err := limiter.Reserve(ctx, securityaction.MediaClientLogoUpload, "192.0.2.50", "user-1")
	if err != nil || allowed || retry <= 0 {
		t.Fatalf("client logo upload limit allowed=%v retry=%v err=%v", allowed, retry, err)
	}
	allowed, _, err = limiter.Reserve(ctx, securityaction.MediaAvatarUpload, "192.0.2.50", "user-1")
	if err != nil || !allowed {
		t.Fatalf("avatar upload bucket was not independent: allowed=%v err=%v", allowed, err)
	}
	keysBefore := len(mini.Keys())
	if allowed, _, err := limiter.Reserve(ctx, securityaction.MediaOperation(255), "192.0.2.50", "user-1"); err == nil || allowed {
		t.Fatalf("unknown media action allowed=%v err=%v", allowed, err)
	}
	if len(mini.Keys()) != keysBefore {
		t.Fatalf("unknown media operation created Redis keys: before=%d after=%d", keysBefore, len(mini.Keys()))
	}
}
