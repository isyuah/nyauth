package server

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

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
		allowed, _, err := limiter.Reserve(ctx, mailSettingsActionCandidateTest, ip, adminID)
		if err != nil || !allowed {
			t.Fatalf("candidate test attempt %d: allowed=%v err=%v", attempt, allowed, err)
		}
	}
	allowed, retry, err := limiter.Reserve(ctx, mailSettingsActionCandidateTest, ip, adminID)
	if err != nil {
		t.Fatalf("limited candidate test: %v", err)
	}
	if allowed || retry <= 0 {
		t.Fatalf("candidate test limit: allowed=%v retry=%v", allowed, retry)
	}

	for attempt := 1; attempt <= 60; attempt++ {
		allowed, _, err = limiter.Reserve(ctx, mailSettingsActionCandidateSave, ip, adminID)
		if err != nil || !allowed {
			t.Fatalf("candidate save attempt %d: allowed=%v err=%v", attempt, allowed, err)
		}
	}
	allowed, retry, err = limiter.Reserve(ctx, mailSettingsActionCandidateSave, ip, adminID)
	if err != nil {
		t.Fatalf("limited candidate save: %v", err)
	}
	if allowed || retry <= 0 {
		t.Fatalf("candidate save limit: allowed=%v retry=%v", allowed, retry)
	}

	allowed, _, err = limiter.Reserve(ctx, mailSettingsActionActivate, ip, adminID)
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
		allowed, _, err := limiter.Reserve(ctx, mailSettingsActionCandidateTest, ip, adminID)
		if err != nil || !allowed {
			t.Fatalf("shared IP attempt %d: allowed=%v err=%v", attempt+1, allowed, err)
		}
	}
	allowed, retry, err := limiter.Reserve(ctx, mailSettingsActionCandidateTest, ip, "admin-6")
	if err != nil {
		t.Fatalf("limited shared IP request: %v", err)
	}
	if allowed || retry <= 0 {
		t.Fatalf("shared IP limit: allowed=%v retry=%v", allowed, retry)
	}
}

func TestMailSettingsLimiterRejectsUnknownOperation(t *testing.T) {
	t.Parallel()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	limiter := NewMailSettingsLimiter(rdb)

	allowed, _, err := limiter.Reserve(context.Background(), "unknown", "192.0.2.42", "admin")
	if err == nil || allowed {
		t.Fatalf("unknown operation: allowed=%v err=%v", allowed, err)
	}
	if len(mini.Keys()) != 0 {
		t.Fatalf("unknown operation created Redis keys: %v", mini.Keys())
	}
}

func TestAvatarLimiterUsesIndependentReasonableBuckets(t *testing.T) {
	t.Parallel()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	limiter := NewAvatarLimiter(rdb)
	ctx := context.Background()
	for attempt := 1; attempt <= 30; attempt++ {
		allowed, _, err := limiter.Reserve(ctx, "upload", "192.0.2.50", "user-1")
		if err != nil || !allowed {
			t.Fatalf("upload attempt %d allowed=%v err=%v", attempt, allowed, err)
		}
	}
	allowed, retry, err := limiter.Reserve(ctx, "upload", "192.0.2.50", "user-1")
	if err != nil || allowed || retry <= 0 {
		t.Fatalf("upload limit allowed=%v retry=%v err=%v", allowed, retry, err)
	}
	allowed, _, err = limiter.Reserve(ctx, "delete", "192.0.2.50", "user-1")
	if err != nil || !allowed {
		t.Fatalf("independent delete bucket allowed=%v err=%v", allowed, err)
	}
	if allowed, _, err := limiter.Reserve(ctx, "unknown", "192.0.2.50", "user-1"); err == nil || allowed {
		t.Fatalf("unknown avatar action allowed=%v err=%v", allowed, err)
	}
}
