package server

import (
	"context"
	"fmt"
	"strconv"

	"github.com/nyasharp/nyauth/internal/humanverification"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/redis/go-redis/v9"
)

type HumanVerificationLoginLimiter struct {
	rdb      *redis.Client
	runtime  humanVerificationSnapshotSource
	settings *settings.Manager
}

type humanVerificationSnapshotSource interface {
	Snapshot() humanverification.EffectiveConfig
}

var recordHumanVerificationFailureScript = redis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 then redis.call("PEXPIRE", KEYS[1], ARGV[1]) end
return count
`)

func NewHumanVerificationLoginLimiter(rdb *redis.Client, runtime humanVerificationSnapshotSource, settingsManager *settings.Manager) *HumanVerificationLoginLimiter {
	return &HumanVerificationLoginLimiter{rdb: rdb, runtime: runtime, settings: settingsManager}
}

func (l *HumanVerificationLoginLimiter) FailureCount(ctx context.Context, ip, username string) (int, error) {
	if l == nil || l.runtime == nil {
		return 0, nil
	}
	snapshot := l.runtime.Snapshot()
	if snapshot.State.Mode != humanverification.ModeActive || snapshot.State.Policy.LoginMode != humanverification.LoginAdaptive {
		return 0, nil
	}
	values, err := l.rdb.MGet(ctx, l.identityKey(snapshot.State.Revision, username), l.ipKey(snapshot.State.Revision, ip)).Result()
	if err != nil {
		return 0, err
	}
	maximum := 0
	for _, value := range values {
		if value == nil {
			continue
		}
		count, err := strconv.Atoi(fmt.Sprint(value))
		if err != nil || count < 0 {
			return 0, fmt.Errorf("invalid human verification failure count")
		}
		if count > maximum {
			maximum = count
		}
	}
	return maximum, nil
}

func (l *HumanVerificationLoginLimiter) RecordFailure(ctx context.Context, ip, username string) error {
	if l == nil || l.runtime == nil {
		return nil
	}
	snapshot := l.runtime.Snapshot()
	if snapshot.State.Mode != humanverification.ModeActive || snapshot.State.Policy.LoginMode != humanverification.LoginAdaptive {
		return nil
	}
	window := l.settings.Protection().LoginWindow()
	for _, key := range []string{l.identityKey(snapshot.State.Revision, username), l.ipKey(snapshot.State.Revision, ip)} {
		if _, err := recordHumanVerificationFailureScript.Run(ctx, l.rdb, []string{key}, window.Milliseconds()).Int64(); err != nil {
			return err
		}
	}
	return nil
}

func (l *HumanVerificationLoginLimiter) ResetIdentity(ctx context.Context, username string) error {
	if l == nil || l.runtime == nil {
		return nil
	}
	revision := l.runtime.Snapshot().State.Revision
	if revision < 1 {
		return nil
	}
	return l.rdb.Del(ctx, l.identityKey(revision, username)).Err()
}

func (l *HumanVerificationLoginLimiter) identityKey(revision int64, username string) string {
	return fmt.Sprintf("nyauth:human-verification-login:r%d:identity:%s", revision, limitDigest(username))
}

func (l *HumanVerificationLoginLimiter) ipKey(revision int64, ip string) string {
	return fmt.Sprintf("nyauth:human-verification-login:r%d:ip:%s", revision, limitDigest(ip))
}
