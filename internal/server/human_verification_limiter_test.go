package server

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/nyasharp/nyauth/internal/humanverification"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/redis/go-redis/v9"
)

type humanVerificationSnapshotStub struct {
	effective humanverification.EffectiveConfig
}

func (s *humanVerificationSnapshotStub) Snapshot() humanverification.EffectiveConfig {
	return s.effective
}

func TestHumanVerificationLoginFailuresAreRevisionScoped(t *testing.T) {
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	runtime := &humanVerificationSnapshotStub{effective: humanverification.EffectiveConfig{State: humanverification.State{
		Mode: humanverification.ModeActive, Revision: 7,
		Policy: humanverification.Policy{LoginMode: humanverification.LoginAdaptive, LoginTriggerAfter: 3},
	}}}
	manager := settings.NewManager(nil, settings.Branding{Title: "Nyauth"})
	limiter := NewHumanVerificationLoginLimiter(rdb, runtime, manager)
	ctx := context.Background()

	for index := 0; index < 2; index++ {
		if err := limiter.RecordFailure(ctx, "203.0.113.8", "alice"); err != nil {
			t.Fatalf("record failure %d: %v", index, err)
		}
	}
	if count, err := limiter.FailureCount(ctx, "203.0.113.8", "alice"); err != nil || count != 2 {
		t.Fatalf("failure count = %d, %v", count, err)
	}
	if err := limiter.ResetIdentity(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if count, err := limiter.FailureCount(ctx, "203.0.113.8", "alice"); err != nil || count != 2 {
		t.Fatalf("IP risk should survive identity reset: count=%d err=%v", count, err)
	}
	if count, err := limiter.FailureCount(ctx, "203.0.113.9", "alice"); err != nil || count != 0 {
		t.Fatalf("reset identity count = %d, %v", count, err)
	}

	runtime.effective.State.Revision = 8
	if count, err := limiter.FailureCount(ctx, "203.0.113.8", "alice"); err != nil || count != 0 {
		t.Fatalf("new policy revision inherited old count: count=%d err=%v", count, err)
	}
}

func TestHumanVerificationLoginLimiterDoesNotTouchRedisWhenInactive(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = rdb.Close() })
	runtime := &humanVerificationSnapshotStub{effective: humanverification.EffectiveConfig{State: humanverification.State{
		Mode:   humanverification.ModeDisabled,
		Policy: humanverification.Policy{LoginMode: humanverification.LoginAdaptive, LoginTriggerAfter: 3},
	}}}
	limiter := NewHumanVerificationLoginLimiter(rdb, runtime, settings.NewManager(nil, settings.Branding{Title: "Nyauth"}))
	if count, err := limiter.FailureCount(context.Background(), "203.0.113.8", "alice"); err != nil || count != 0 {
		t.Fatalf("inactive limiter touched Redis: count=%d err=%v", count, err)
	}
	if err := limiter.RecordFailure(context.Background(), "203.0.113.8", "alice"); err != nil {
		t.Fatalf("inactive limiter touched Redis: %v", err)
	}
}
