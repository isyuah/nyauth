package deviceauthorization

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	GrantType       = "urn:ietf:params:oauth:grant-type:device_code"
	DefaultTTL      = 10 * time.Minute
	DefaultInterval = 5 * time.Second
	SlowDownStep    = 5 * time.Second

	recordPrefix   = "nyauth:device-authorization:device:"
	userCodePrefix = "nyauth:device-authorization:user:"
	limitPrefix    = "nyauth:device-authorization:limit:"
)

var (
	ErrNotFound             = errors.New("device authorization not found or expired")
	ErrValueMismatch        = errors.New("device authorization value no longer matches")
	ErrAuthorizationPending = errors.New("device authorization is pending")
	ErrSlowDown             = errors.New("device authorization polling is too frequent")
	ErrAccessDenied         = errors.New("device authorization was denied")
	ErrRateLimited          = errors.New("device authorization rate limit exceeded")
)

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
)

type Record struct {
	RecordVersion               string              `json:"record_version"`
	DeviceID                    string              `json:"device_id"`
	UserCodeDigest              string              `json:"user_code_digest"`
	ClientID                    string              `json:"client_id"`
	Scopes                      []string            `json:"scopes"`
	OptionalScopes              []string            `json:"optional_scopes,omitempty"`
	ScopeClaims                 map[string][]string `json:"scope_claims,omitempty"`
	ClientIdentityRevision      int64               `json:"client_identity_revision"`
	ClientAuthorizationRevision int64               `json:"client_authorization_revision"`
	Status                      Status              `json:"status"`
	CreatedAtUnixMilli          int64               `json:"created_at_unix_milli"`
	ExpiresAtUnixMilli          int64               `json:"expires_at_unix_milli"`
	IntervalSeconds             int                 `json:"interval_seconds"`
	NextPollAtUnixMilli         int64               `json:"next_poll_at_unix_milli"`
	UserID                      string              `json:"user_id,omitempty"`
	AuthVersion                 int64               `json:"auth_version,omitempty"`
	GrantedScopes               []string            `json:"granted_scopes,omitempty"`
	AllowedClaims               []string            `json:"allowed_claims,omitempty"`
	AuthorizationIssuedAt       int64               `json:"authorization_issued_at,omitempty"`
	AuthenticationContext       string              `json:"acr,omitempty"`
	AuthenticationMethods       []string            `json:"amr,omitempty"`
	AuthenticationTime          int64               `json:"auth_time,omitempty"`
}

type CreateInput struct {
	ClientID                    string
	Scopes                      []string
	OptionalScopes              []string
	ScopeClaims                 map[string][]string
	ClientIdentityRevision      int64
	ClientAuthorizationRevision int64
	TTL                         time.Duration
	Interval                    time.Duration
}

type Created struct {
	DeviceCode string
	UserCode   string
	Record     *Record
}

type Store struct {
	rdb *redis.Client
	now func() time.Time
}

func NewStore(rdb *redis.Client) *Store {
	return &Store{rdb: rdb, now: func() time.Time { return time.Now().UTC() }}
}

var createScript = redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 1 or redis.call("EXISTS", KEYS[2]) == 1 then
  return 0
end
redis.call("SET", KEYS[1], ARGV[1], "PX", ARGV[2])
redis.call("SET", KEYS[2], ARGV[3], "PX", ARGV[2])
return 1
`)

var pollScript = redis.NewScript(`
local raw = redis.call("GET", KEYS[1])
if not raw then return {0, ""} end
local value = cjson.decode(raw)
if value["client_id"] ~= ARGV[1] then return {-1, ""} end
if value["status"] == "denied" then
  redis.call("DEL", KEYS[1])
  return {3, ""}
end
if value["status"] == "approved" then return {4, raw} end
if value["status"] ~= "pending" then return {-1, ""} end
local now = tonumber(ARGV[2])
local interval = tonumber(value["interval_seconds"])
if now < tonumber(value["next_poll_at_unix_milli"]) then
  interval = interval + tonumber(ARGV[3])
  value["interval_seconds"] = interval
  value["next_poll_at_unix_milli"] = now + interval * 1000
  local ttl = redis.call("PTTL", KEYS[1])
  if ttl <= 0 then redis.call("DEL", KEYS[1]); return {0, ""} end
  redis.call("SET", KEYS[1], cjson.encode(value), "PX", ttl)
  return {2, tostring(interval)}
end
value["next_poll_at_unix_milli"] = now + interval * 1000
local ttl = redis.call("PTTL", KEYS[1])
if ttl <= 0 then redis.call("DEL", KEYS[1]); return {0, ""} end
redis.call("SET", KEYS[1], cjson.encode(value), "PX", ttl)
return {1, tostring(interval)}
`)

var decideScript = redis.NewScript(`
local raw = redis.call("GET", KEYS[1])
if not raw then return 0 end
local value = cjson.decode(raw)
if value["record_version"] ~= ARGV[1] or value["status"] ~= "pending" then return -1 end
local replacement = cjson.decode(ARGV[2])
if replacement["record_version"] ~= value["record_version"] or
   replacement["device_id"] ~= value["device_id"] or
   replacement["user_code_digest"] ~= value["user_code_digest"] or
   (replacement["status"] ~= "approved" and replacement["status"] ~= "denied") then
  return -1
end
local ttl = redis.call("PTTL", KEYS[1])
if ttl <= 0 then redis.call("DEL", KEYS[1], KEYS[2]); return 0 end
redis.call("SET", KEYS[1], ARGV[2], "PX", ttl)
redis.call("DEL", KEYS[2])
return 1
`)

var consumeScript = redis.NewScript(`
local raw = redis.call("GET", KEYS[1])
if not raw then return 0 end
local value = cjson.decode(raw)
if value["record_version"] ~= ARGV[1] or value["status"] ~= "approved" then return -1 end
redis.call("DEL", KEYS[1], KEYS[2])
return 1
`)

var limitScript = redis.NewScript(`
local subject = redis.call("INCR", KEYS[1])
if subject == 1 then redis.call("PEXPIRE", KEYS[1], ARGV[1]) end
local ip = redis.call("INCR", KEYS[2])
if ip == 1 then redis.call("PEXPIRE", KEYS[2], ARGV[1]) end
local ttl = math.max(redis.call("PTTL", KEYS[1]), redis.call("PTTL", KEYS[2]))
if subject > tonumber(ARGV[2]) or ip > tonumber(ARGV[3]) then return {0, ttl} end
return {1, ttl}
`)

func (s *Store) Create(ctx context.Context, input CreateInput) (*Created, error) {
	if s == nil || s.rdb == nil || strings.TrimSpace(input.ClientID) == "" {
		return nil, errors.New("invalid device authorization store input")
	}
	ttl := input.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	interval := input.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	if interval < time.Second {
		interval = time.Second
	}
	for attempt := 0; attempt < 8; attempt++ {
		deviceCode, err := randomBase64URL(32)
		if err != nil {
			return nil, fmt.Errorf("generating device code: %w", err)
		}
		userCode, err := randomUserCode()
		if err != nil {
			return nil, fmt.Errorf("generating user code: %w", err)
		}
		version, err := randomBase64URL(18)
		if err != nil {
			return nil, fmt.Errorf("generating record version: %w", err)
		}
		now := s.now()
		deviceID := digest(deviceCode)
		userDigest := digest(NormalizeUserCode(userCode))
		record := &Record{
			RecordVersion: version, DeviceID: deviceID, UserCodeDigest: userDigest,
			ClientID: input.ClientID, Scopes: append([]string(nil), input.Scopes...),
			OptionalScopes: append([]string(nil), input.OptionalScopes...), ScopeClaims: cloneClaims(input.ScopeClaims),
			ClientIdentityRevision: input.ClientIdentityRevision, ClientAuthorizationRevision: input.ClientAuthorizationRevision,
			Status: StatusPending, CreatedAtUnixMilli: now.UnixMilli(), ExpiresAtUnixMilli: now.Add(ttl).UnixMilli(),
			IntervalSeconds: int(interval.Round(time.Second) / time.Second), NextPollAtUnixMilli: now.Add(interval).UnixMilli(),
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, fmt.Errorf("encoding device authorization: %w", err)
		}
		result, err := createScript.Run(ctx, s.rdb, []string{recordKey(deviceID), userCodeKey(userDigest)}, encoded, ttl.Milliseconds(), deviceID).Int()
		if err != nil {
			return nil, fmt.Errorf("storing device authorization: %w", err)
		}
		if result == 1 {
			return &Created{DeviceCode: deviceCode, UserCode: userCode, Record: record}, nil
		}
	}
	return nil, errors.New("could not allocate a unique device authorization code")
}

func (s *Store) FindPendingByUserCode(ctx context.Context, userCode string) (*Record, error) {
	normalized := NormalizeUserCode(userCode)
	if len(normalized) != 8 {
		return nil, ErrNotFound
	}
	deviceID, err := s.rdb.Get(ctx, userCodeKey(digest(normalized))).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("resolving user code: %w", err)
	}
	record, err := s.getByID(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	if record.Status != StatusPending || record.UserCodeDigest != digest(normalized) {
		return nil, ErrNotFound
	}
	return record, nil
}

func (s *Store) GetPending(ctx context.Context, deviceID, version string) (*Record, error) {
	record, err := s.getByID(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	if record.Status != StatusPending || record.RecordVersion != version {
		return nil, ErrValueMismatch
	}
	return record, nil
}

func (s *Store) Approve(ctx context.Context, current *Record, userID string, authVersion int64, scopes, claims []string, authorizationIssuedAt int64) error {
	return s.ApproveWithAuthentication(ctx, current, userID, authVersion, scopes, claims, authorizationIssuedAt, "", nil, 0)
}

func (s *Store) ApproveWithAuthentication(ctx context.Context, current *Record, userID string, authVersion int64, scopes, claims []string, authorizationIssuedAt int64, authenticationContext string, authenticationMethods []string, authenticationTime int64) error {
	if current == nil || userID == "" || authVersion <= 0 || authorizationIssuedAt <= 0 {
		return errors.New("invalid device authorization approval")
	}
	replacement := *current
	replacement.Status = StatusApproved
	replacement.UserID = userID
	replacement.AuthVersion = authVersion
	replacement.GrantedScopes = append([]string(nil), scopes...)
	replacement.AllowedClaims = append([]string(nil), claims...)
	replacement.AuthorizationIssuedAt = authorizationIssuedAt
	replacement.AuthenticationContext = authenticationContext
	replacement.AuthenticationMethods = append([]string(nil), authenticationMethods...)
	replacement.AuthenticationTime = authenticationTime
	encoded, err := json.Marshal(&replacement)
	if err != nil {
		return err
	}
	return s.runDecision(ctx, current, encoded)
}

func (s *Store) Deny(ctx context.Context, current *Record) error {
	if current == nil {
		return ErrNotFound
	}
	replacement := *current
	replacement.Status = StatusDenied
	encoded, err := json.Marshal(&replacement)
	if err != nil {
		return err
	}
	return s.runDecision(ctx, current, encoded)
}

func (s *Store) runDecision(ctx context.Context, current *Record, decision []byte) error {
	result, err := decideScript.Run(ctx, s.rdb, []string{recordKey(current.DeviceID), userCodeKey(current.UserCodeDigest)}, current.RecordVersion, decision).Int()
	if err != nil {
		return fmt.Errorf("updating device authorization: %w", err)
	}
	switch result {
	case 1:
		return nil
	case 0:
		return ErrNotFound
	default:
		return ErrValueMismatch
	}
}

func (s *Store) Poll(ctx context.Context, deviceCode, clientID string) (*Record, time.Duration, error) {
	deviceID := digest(deviceCode)
	result, err := pollScript.Run(ctx, s.rdb, []string{recordKey(deviceID)}, clientID, s.now().UnixMilli(), int(SlowDownStep/time.Second)).Slice()
	if err != nil {
		return nil, 0, fmt.Errorf("polling device authorization: %w", err)
	}
	if len(result) != 2 {
		return nil, 0, errors.New("invalid device authorization poll result")
	}
	code, err := toInt64(result[0])
	if err != nil {
		return nil, 0, errors.New("invalid device authorization poll status")
	}
	switch code {
	case 0, -1:
		return nil, 0, ErrNotFound
	case 1:
		return nil, durationFromResult(result[1]), ErrAuthorizationPending
	case 2:
		return nil, durationFromResult(result[1]), ErrSlowDown
	case 3:
		return nil, 0, ErrAccessDenied
	case 4:
		raw, ok := result[1].(string)
		if !ok {
			return nil, 0, errors.New("invalid approved device authorization")
		}
		var record Record
		if err := json.Unmarshal([]byte(raw), &record); err != nil {
			return nil, 0, fmt.Errorf("decoding approved device authorization: %w", err)
		}
		return &record, time.Duration(record.IntervalSeconds) * time.Second, nil
	default:
		return nil, 0, errors.New("unknown device authorization poll status")
	}
}

func (s *Store) ConsumeApproved(ctx context.Context, current *Record) error {
	if current == nil {
		return ErrNotFound
	}
	result, err := consumeScript.Run(ctx, s.rdb, []string{recordKey(current.DeviceID), userCodeKey(current.UserCodeDigest)}, current.RecordVersion).Int()
	if err != nil {
		return fmt.Errorf("consuming device authorization: %w", err)
	}
	if result == 1 {
		return nil
	}
	if result == 0 {
		return ErrNotFound
	}
	return ErrValueMismatch
}

func (s *Store) ReserveInitiation(ctx context.Context, clientID, ip string) (time.Duration, error) {
	return s.reserve(ctx, "init", clientID, ip, time.Minute, 30, 120)
}

func (s *Store) ReserveVerification(ctx context.Context, userID, ip string) (time.Duration, error) {
	return s.reserve(ctx, "verify", userID, ip, 10*time.Minute, 10, 30)
}

func (s *Store) reserve(ctx context.Context, action, subject, ip string, window time.Duration, subjectLimit, ipLimit int) (time.Duration, error) {
	result, err := limitScript.Run(ctx, s.rdb, []string{
		limitPrefix + action + ":subject:" + digest(subject),
		limitPrefix + action + ":ip:" + digest(ip),
	}, window.Milliseconds(), subjectLimit, ipLimit).Slice()
	if err != nil {
		return 0, fmt.Errorf("reserving device authorization rate limit: %w", err)
	}
	if len(result) != 2 {
		return 0, errors.New("invalid device authorization rate limit result")
	}
	allowed, err := toInt64(result[0])
	if err != nil {
		return 0, errors.New("invalid device authorization rate limit status")
	}
	retry := time.Duration(durationMillis(result[1])) * time.Millisecond
	if allowed != 1 {
		return retry, ErrRateLimited
	}
	return 0, nil
}

func (s *Store) getByID(ctx context.Context, deviceID string) (*Record, error) {
	raw, err := s.rdb.Get(ctx, recordKey(deviceID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting device authorization: %w", err)
	}
	var record Record
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("decoding device authorization: %w", err)
	}
	if record.DeviceID != deviceID || record.RecordVersion == "" || record.ExpiresAtUnixMilli <= s.now().UnixMilli() {
		return nil, ErrNotFound
	}
	return &record, nil
}

func NormalizeUserCode(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	return strings.NewReplacer("-", "", " ", "", "\t", "", "\r", "", "\n", "").Replace(value)
}

func randomUserCode() (string, error) {
	const alphabet = "23456789BCDFGHJKMNPQRTVWXY"
	raw := make([]byte, 8)
	for index := range raw {
		value, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		raw[index] = alphabet[value.Int64()]
	}
	return string(raw[:4]) + "-" + string(raw[4:]), nil
}

func randomBase64URL(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func recordKey(deviceID string) string     { return recordPrefix + deviceID }
func userCodeKey(codeDigest string) string { return userCodePrefix + codeDigest }

func cloneClaims(input map[string][]string) map[string][]string {
	if input == nil {
		return nil
	}
	result := make(map[string][]string, len(input))
	for key, values := range input {
		result[key] = append([]string(nil), values...)
	}
	return result
}

func toInt64(value any) (int64, error) {
	switch typed := value.(type) {
	case int64:
		return typed, nil
	case string:
		var result int64
		_, err := fmt.Sscan(typed, &result)
		return result, err
	default:
		return 0, fmt.Errorf("unexpected integer type %T", value)
	}
}

func durationFromResult(value any) time.Duration {
	seconds, _ := toInt64(value)
	return time.Duration(seconds) * time.Second
}

func durationMillis(value any) int64 {
	result, _ := toInt64(value)
	if result < 0 {
		return 0
	}
	return result
}
