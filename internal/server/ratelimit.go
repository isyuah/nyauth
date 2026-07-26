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

type LoginLimiter struct {
	rdb           *redis.Client
	window        time.Duration
	identityLimit int
	ipLimit       int
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

func NewLoginLimiter(rdb *redis.Client) *LoginLimiter {
	return &LoginLimiter{rdb: rdb, window: 5 * time.Minute, identityLimit: 5, ipLimit: 30}
}

func NewAccountActionLimiter(rdb *redis.Client) *AccountActionLimiter {
	return &AccountActionLimiter{rdb: rdb, window: 15 * time.Minute, subjectLimit: 5, ipLimit: 20}
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

func (l *AccountActionLimiter) Reserve(ctx context.Context, action, ip, subject string) (bool, time.Duration, error) {
	keys := []string{
		"nyauth:account-limit:subject:" + action + ":" + limitDigest(ip+"\x00"+subject),
		"nyauth:account-limit:ip:" + action + ":" + limitDigest(ip),
	}
	values, err := loginLimitScript.Run(ctx, l.rdb, keys, l.subjectLimit, l.ipLimit, l.window.Milliseconds()).Slice()
	if err != nil {
		return false, 0, err
	}
	if len(values) != 2 {
		return false, 0, fmt.Errorf("invalid account action rate limit result")
	}
	allowed, ok := values[0].(int64)
	if !ok {
		return false, 0, fmt.Errorf("invalid account action rate limit status")
	}
	millis, ok := values[1].(int64)
	if !ok {
		return false, 0, fmt.Errorf("invalid account action rate limit TTL")
	}
	if millis < 1000 {
		millis = 1000
	}
	return allowed == 1, time.Duration(millis) * time.Millisecond, nil
}
