package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var loginLimitScript = redis.NewScript(`
local identity = redis.call("INCR", KEYS[1])
if identity == 1 then redis.call("PEXPIRE", KEYS[1], ARGV[3]) end
local address = redis.call("INCR", KEYS[2])
if address == 1 then redis.call("PEXPIRE", KEYS[2], ARGV[3]) end
local ttl1 = redis.call("PTTL", KEYS[1])
local ttl2 = redis.call("PTTL", KEYS[2])
local retry = math.max(ttl1, ttl2)
if identity > tonumber(ARGV[1]) or address > tonumber(ARGV[2]) then return {0, retry} end
return {1, retry}
`)

var singleLimitScript = redis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 then redis.call("PEXPIRE", KEYS[1], ARGV[2]) end
local ttl = redis.call("PTTL", KEYS[1])
if count > tonumber(ARGV[1]) then return {0, ttl} end
return {1, ttl}
`)

type LoginLimiter struct {
	rdb           *redis.Client
	window        time.Duration
	identityLimit int
	ipLimit       int
	ceremonyLimit int
}

// AccountActionLimiter bounds email-producing account actions without storing
// an email address or user identifier in Redis keys. A per-subject limit slows
// targeted abuse while the per-IP limit caps distributed address probing from
// one source.
type AccountActionLimiter struct {
	rdb          *redis.Client
	window       time.Duration
	subjectLimit int
	ipLimit      int
}

// MailSettingsLimiter protects trusted administrator mutations without
// applying the much tighter limits used by public account actions. Each
// operation has its own bucket so troubleshooting a candidate does not block
// activation, rollback, or disable operations.
type MailSettingsLimiter struct {
	rdb           *redis.Client
	window        time.Duration
	ipLimit       int
	subjectLimits map[string]int
}

type AvatarLimiter struct {
	rdb          *redis.Client
	window       time.Duration
	subjectLimit int
	ipLimit      int
}

const (
	mailSettingsActionCandidateSave = "candidate-save"
	mailSettingsActionCandidateTest = "candidate-test"
	mailSettingsActionActivate      = "activate"
	mailSettingsActionRollback      = "rollback"
	mailSettingsActionDisable       = "disable"
)

func NewLoginLimiter(rdb *redis.Client) *LoginLimiter {
	return &LoginLimiter{rdb: rdb, window: 5 * time.Minute, identityLimit: 5, ipLimit: 30, ceremonyLimit: 120}
}

func NewAccountActionLimiter(rdb *redis.Client) *AccountActionLimiter {
	return &AccountActionLimiter{rdb: rdb, window: 15 * time.Minute, subjectLimit: 5, ipLimit: 20}
}

func NewMailSettingsLimiter(rdb *redis.Client) *MailSettingsLimiter {
	return &MailSettingsLimiter{
		rdb:     rdb,
		window:  15 * time.Minute,
		ipLimit: 200,
		subjectLimits: map[string]int{
			mailSettingsActionCandidateSave: 60,
			mailSettingsActionCandidateTest: 30,
			mailSettingsActionActivate:      30,
			mailSettingsActionRollback:      30,
			mailSettingsActionDisable:       30,
		},
	}
}

func NewAvatarLimiter(rdb *redis.Client) *AvatarLimiter {
	return &AvatarLimiter{rdb: rdb, window: 15 * time.Minute, subjectLimit: 30, ipLimit: 200}
}

func limitDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (l *LoginLimiter) Reserve(ctx context.Context, ip, username string) (bool, time.Duration, error) {
	keys := []string{"nyauth:login-limit:identity:" + limitDigest(ip+"\x00"+username), "nyauth:login-limit:ip:" + limitDigest(ip)}
	values, err := loginLimitScript.Run(ctx, l.rdb, keys, l.identityLimit, l.ipLimit, l.window.Milliseconds()).Slice()
	if err != nil {
		return false, 0, err
	}
	if len(values) != 2 {
		return false, 0, fmt.Errorf("invalid rate limit result")
	}
	allowed, ok := values[0].(int64)
	if !ok {
		return false, 0, fmt.Errorf("invalid rate limit status")
	}
	millis, ok := values[1].(int64)
	if !ok {
		return false, 0, fmt.Errorf("invalid rate limit TTL")
	}
	if millis < 1000 {
		millis = 1000
	}
	return allowed == 1, time.Duration(millis) * time.Millisecond, nil
}
func (l *LoginLimiter) ResetIdentity(ctx context.Context, ip, username string) error {
	return l.rdb.Del(ctx, "nyauth:login-limit:identity:"+limitDigest(ip+"\x00"+username)).Err()
}

func (l *LoginLimiter) ReserveIP(ctx context.Context, ip string) (bool, time.Duration, error) {
	return reserveSingleLimit(
		ctx, l.rdb, "nyauth:login-limit:ip:"+limitDigest(ip), l.ipLimit, l.window,
	)
}

func (l *LoginLimiter) ReservePasskeyCeremony(ctx context.Context, ip string) (bool, time.Duration, error) {
	return reserveSingleLimit(
		ctx, l.rdb, "nyauth:passkey-ceremony-limit:ip:"+limitDigest(ip), l.ceremonyLimit, l.window,
	)
}

func reserveSingleLimit(
	ctx context.Context,
	rdb *redis.Client,
	key string,
	limit int,
	window time.Duration,
) (bool, time.Duration, error) {
	values, err := singleLimitScript.Run(ctx, rdb, []string{key}, limit, window.Milliseconds()).Slice()
	if err != nil {
		return false, 0, err
	}
	if len(values) != 2 {
		return false, 0, fmt.Errorf("invalid rate limit result")
	}
	allowed, ok := values[0].(int64)
	if !ok {
		return false, 0, fmt.Errorf("invalid rate limit status")
	}
	millis, ok := values[1].(int64)
	if !ok {
		return false, 0, fmt.Errorf("invalid rate limit TTL")
	}
	if millis < 1000 {
		millis = 1000
	}
	return allowed == 1, time.Duration(millis) * time.Millisecond, nil
}

func (l *AccountActionLimiter) Reserve(ctx context.Context, action, ip, subject string) (bool, time.Duration, error) {
	return reserveSubjectIPLimit(
		ctx, l.rdb, "nyauth:account-limit", action, ip, subject,
		l.subjectLimit, l.ipLimit, l.window,
	)
}

func (l *MailSettingsLimiter) Reserve(ctx context.Context, action, ip, subject string) (bool, time.Duration, error) {
	subjectLimit, ok := l.subjectLimits[action]
	if !ok {
		return false, 0, fmt.Errorf("unsupported mail settings rate limit action %q", action)
	}
	return reserveSubjectIPLimit(
		ctx, l.rdb, "nyauth:mail-settings-limit", action, ip, subject,
		subjectLimit, l.ipLimit, l.window,
	)
}

func (l *AvatarLimiter) Reserve(ctx context.Context, action, ip, subject string) (bool, time.Duration, error) {
	if action != "upload" && action != "delete" {
		return false, 0, fmt.Errorf("unsupported avatar rate limit action %q", action)
	}
	return reserveSubjectIPLimit(
		ctx, l.rdb, "nyauth:avatar-limit", action, ip, subject,
		l.subjectLimit, l.ipLimit, l.window,
	)
}

func reserveSubjectIPLimit(
	ctx context.Context,
	rdb *redis.Client,
	keyPrefix, action, ip, subject string,
	subjectLimit, ipLimit int,
	window time.Duration,
) (bool, time.Duration, error) {
	keys := []string{
		keyPrefix + ":subject:" + action + ":" + limitDigest(ip+"\x00"+subject),
		keyPrefix + ":ip:" + action + ":" + limitDigest(ip),
	}
	values, err := loginLimitScript.Run(ctx, rdb, keys, subjectLimit, ipLimit, window.Milliseconds()).Slice()
	if err != nil {
		return false, 0, err
	}
	if len(values) != 2 {
		return false, 0, fmt.Errorf("invalid action rate limit result")
	}
	allowed, ok := values[0].(int64)
	if !ok {
		return false, 0, fmt.Errorf("invalid action rate limit status")
	}
	millis, ok := values[1].(int64)
	if !ok {
		return false, 0, fmt.Errorf("invalid action rate limit TTL")
	}
	if millis < 1000 {
		millis = 1000
	}
	return allowed == 1, time.Duration(millis) * time.Millisecond, nil
}
