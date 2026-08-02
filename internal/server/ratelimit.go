package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/nyasharp/nyauth/internal/securityaction"
	"github.com/nyasharp/nyauth/internal/settings"
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
	rdb                       *redis.Client
	settings                  *settings.Manager
	ceremonyLimitTestOverride int
}

// AccountActionLimiter bounds email-producing account actions without storing
// an email address or user identifier in Redis keys. A per-subject limit slows
// targeted abuse while the per-IP limit caps distributed address probing from
// one source.
type AccountActionLimiter struct {
	rdb      *redis.Client
	settings *settings.Manager
}

// MailSettingsLimiter protects trusted administrator mutations without
// applying the much tighter limits used by public account actions. Each
// operation has its own bucket so troubleshooting a candidate does not block
// activation, rollback, or disable operations.
type MailSettingsLimiter struct {
	rdb      *redis.Client
	settings *settings.Manager
}

type MediaMutationLimiter struct {
	rdb      *redis.Client
	settings *settings.Manager
}

// OperationsSettingsLimiter bounds maintenance-control changes per
// administrator and source address without making normal troubleshooting
// impractical for trusted operators.
type OperationsSettingsLimiter struct {
	rdb          *redis.Client
	window       time.Duration
	subjectLimit int
	ipLimit      int
}

// PolicySettingsLimiter is deliberately not configurable through C2. It
// protects the policy settings that can disable other rate limit groups.
type PolicySettingsLimiter struct {
	rdb          *redis.Client
	window       time.Duration
	subjectLimit int
	ipLimit      int
}

func NewLoginLimiter(rdb *redis.Client, managers ...*settings.Manager) *LoginLimiter {
	return &LoginLimiter{rdb: rdb, settings: firstSettingsManager(managers)}
}

func NewAccountActionLimiter(rdb *redis.Client, managers ...*settings.Manager) *AccountActionLimiter {
	return &AccountActionLimiter{rdb: rdb, settings: firstSettingsManager(managers)}
}

func NewMailSettingsLimiter(rdb *redis.Client, managers ...*settings.Manager) *MailSettingsLimiter {
	return &MailSettingsLimiter{rdb: rdb, settings: firstSettingsManager(managers)}
}

func NewMediaMutationLimiter(rdb *redis.Client, managers ...*settings.Manager) *MediaMutationLimiter {
	return &MediaMutationLimiter{rdb: rdb, settings: firstSettingsManager(managers)}
}

func NewOperationsSettingsLimiter(rdb *redis.Client) *OperationsSettingsLimiter {
	return &OperationsSettingsLimiter{rdb: rdb, window: 15 * time.Minute, subjectLimit: 30, ipLimit: 100}
}

func NewPolicySettingsLimiter(rdb *redis.Client) *PolicySettingsLimiter {
	return &PolicySettingsLimiter{rdb: rdb, window: 15 * time.Minute, subjectLimit: 30, ipLimit: 100}
}

func firstSettingsManager(managers []*settings.Manager) *settings.Manager {
	if len(managers) == 0 {
		return nil
	}
	return managers[0]
}

func protectionSnapshot(manager *settings.Manager) settings.Versioned[settings.Protection] {
	if manager == nil {
		return settings.Versioned[settings.Protection]{Value: settings.DefaultProtection()}
	}
	return manager.ProtectionSnapshot()
}

func rateLimitNamespace(group string, revision int64) string {
	return fmt.Sprintf("nyauth:%s-limit:r%d", group, revision)
}

func limitDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (l *LoginLimiter) Reserve(ctx context.Context, ip, username string) (bool, time.Duration, error) {
	snapshot := protectionSnapshot(l.settings)
	policy := snapshot.Value.Login
	if !policy.Enabled {
		return true, 0, nil
	}
	prefix := rateLimitNamespace("login", snapshot.Revision)
	keys := []string{prefix + ":identity:" + limitDigest(username), prefix + ":ip:" + limitDigest(ip)}
	values, err := loginLimitScript.Run(ctx, l.rdb, keys, policy.IdentityLimit, policy.IPLimit, snapshot.Value.LoginWindow().Milliseconds()).Slice()
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
func (l *LoginLimiter) ResetIdentity(ctx context.Context, _ string, username string) error {
	snapshot := protectionSnapshot(l.settings)
	if !snapshot.Value.Login.Enabled {
		return nil
	}
	return l.rdb.Del(ctx, rateLimitNamespace("login", snapshot.Revision)+":identity:"+limitDigest(username)).Err()
}

func (l *LoginLimiter) ReserveIP(ctx context.Context, ip string) (bool, time.Duration, error) {
	snapshot := protectionSnapshot(l.settings)
	policy := snapshot.Value.Login
	if !policy.Enabled {
		return true, 0, nil
	}
	return reserveSingleLimit(
		ctx, l.rdb, rateLimitNamespace("login", snapshot.Revision)+":ip:"+limitDigest(ip),
		policy.IPLimit, snapshot.Value.LoginWindow(),
	)
}

func (l *LoginLimiter) ReservePasskeyCeremony(ctx context.Context, ip string) (bool, time.Duration, error) {
	snapshot := protectionSnapshot(l.settings)
	policy := snapshot.Value.Login
	if !policy.Enabled {
		return true, 0, nil
	}
	limit := policy.PasskeyCeremonyIPLimit
	if l.ceremonyLimitTestOverride > 0 {
		limit = l.ceremonyLimitTestOverride
	}
	return reserveSingleLimit(
		ctx, l.rdb, rateLimitNamespace("passkey-ceremony", snapshot.Revision)+":ip:"+limitDigest(ip),
		limit, snapshot.Value.LoginWindow(),
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

func (l *AccountActionLimiter) Reserve(ctx context.Context, operation securityaction.AccountOperation, ip, subject string) (bool, time.Duration, error) {
	bucket, ok := securityaction.Bucket(operation)
	if !ok {
		return false, 0, fmt.Errorf("invalid account rate limit operation")
	}
	snapshot := protectionSnapshot(l.settings)
	policy := snapshot.Value.Account
	if !policy.Enabled {
		return true, 0, nil
	}
	return reserveSubjectIPLimit(
		ctx, l.rdb, rateLimitNamespace("account", snapshot.Revision), bucket, ip, subject,
		policy.SubjectLimit, policy.IPLimit, snapshot.Value.AccountWindow(),
	)
}

func (l *MailSettingsLimiter) Reserve(ctx context.Context, operation securityaction.MailOperation, ip, subject string) (bool, time.Duration, error) {
	bucket, ok := securityaction.Bucket(operation)
	if !ok {
		return false, 0, fmt.Errorf("invalid mail settings rate limit operation")
	}
	snapshot := protectionSnapshot(l.settings)
	policy := snapshot.Value.Mail
	if !policy.Enabled {
		return true, 0, nil
	}
	var subjectLimit int
	switch operation.LimitProfile() {
	case securityaction.MailLimitSave:
		subjectLimit = policy.SaveLimit
	case securityaction.MailLimitTest:
		subjectLimit = policy.TestLimit
	case securityaction.MailLimitActivate:
		subjectLimit = policy.ActivateLimit
	case securityaction.MailLimitRollback:
		subjectLimit = policy.RollbackLimit
	case securityaction.MailLimitDisable:
		subjectLimit = policy.DisableLimit
	default:
		return false, 0, fmt.Errorf("invalid mail settings rate limit profile")
	}
	return reserveSubjectIPLimit(
		ctx, l.rdb, rateLimitNamespace("mail-settings", snapshot.Revision), bucket, ip, subject,
		subjectLimit, policy.IPLimit, snapshot.Value.MailWindow(),
	)
}

func (l *MediaMutationLimiter) Reserve(ctx context.Context, operation securityaction.MediaOperation, ip, subject string) (bool, time.Duration, error) {
	bucket, ok := securityaction.Bucket(operation)
	if !ok {
		return false, 0, fmt.Errorf("invalid media rate limit operation")
	}
	snapshot := protectionSnapshot(l.settings)
	policy := snapshot.Value.Avatar
	if !policy.Enabled {
		return true, 0, nil
	}
	return reserveSubjectIPLimit(
		ctx, l.rdb, rateLimitNamespace("avatar", snapshot.Revision), bucket, ip, subject,
		policy.UserLimit, policy.IPLimit, snapshot.Value.AvatarWindow(),
	)
}

func (l *OperationsSettingsLimiter) Reserve(ctx context.Context, ip, subject string) (bool, time.Duration, error) {
	return reserveSubjectIPLimit(
		ctx, l.rdb, "nyauth:operations-settings-limit", "update", ip, subject,
		l.subjectLimit, l.ipLimit, l.window,
	)
}

func (l *PolicySettingsLimiter) Reserve(ctx context.Context, ip, subject string) (bool, time.Duration, error) {
	return reserveSubjectIPLimit(
		ctx, l.rdb, "nyauth:policy-settings-limit", "update", ip, subject,
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
		keyPrefix + ":subject:" + action + ":" + limitDigest(subject),
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
