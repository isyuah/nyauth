package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix                  = "nyauth:"
	sessionPrefix              = keyPrefix + "session:"
	userSessionsPrefix         = keyPrefix + "user-sessions:"
	codePrefix                 = keyPrefix + "code:"
	codeUsedPrefix             = keyPrefix + "code-used:"
	tokenPrefix                = keyPrefix + "token:"
	refreshPrefix              = keyPrefix + "refresh:"
	refreshUsedPrefix          = keyPrefix + "refresh-used:"
	refreshFamilyPrefix        = keyPrefix + "refresh-family:"
	refreshRevokedPrefix       = keyPrefix + "refresh-revoked:"
	userRefreshFamiliesPrefix  = keyPrefix + "user-refresh-families:"
	csrfPrefix                 = keyPrefix + "csrf:"
	consentPrefix              = keyPrefix + "consent:"
	authorizationClockPrefix   = keyPrefix + "authorization-clock:"
	authorizationRevokedPrefix = keyPrefix + "authorization-revoked:"
	allSessionsKey             = keyPrefix + "sessions"
)

var (
	ErrNotFound               = errors.New("session value not found or expired")
	ErrValueMismatch          = errors.New("session value no longer matches")
	ErrAuthorizationCodeReuse = errors.New("authorization code reuse detected")
	ErrConsentUserMismatch    = errors.New("consent does not belong to current user")
	ErrRefreshTokenReuse      = errors.New("refresh token reuse detected; token family revoked")
	ErrRefreshFamilyRevoked   = errors.New("refresh token family is revoked")
	ErrTokenBindingMismatch   = errors.New("stored token binding does not match")
	ErrInvalidTokenData       = errors.New("invalid stored token data")
)

type Store struct{ rdb *redis.Client }

func NewStore(rdb *redis.Client) *Store { return &Store{rdb: rdb} }

type AuthorizationData struct {
	RecordVersion         string   `json:"record_version"`
	ClientID              string   `json:"client_id"`
	UserID                string   `json:"user_id"`
	RedirectURI           string   `json:"redirect_uri"`
	Scopes                []string `json:"scopes"`
	CodeChallenge         string   `json:"code_challenge"`
	ChallengeMethod       string   `json:"code_challenge_method"`
	Nonce                 string   `json:"nonce,omitempty"`
	AuthVersion           int64    `json:"auth_version,omitempty"`
	AuthorizationIssuedAt int64    `json:"authorization_issued_at,omitempty"`
}
type TokenData struct {
	ClientID              string   `json:"client_id"`
	UserID                string   `json:"user_id"`
	Scopes                []string `json:"scopes"`
	TokenUse              string   `json:"token_use"`
	AuthVersion           int64    `json:"auth_version,omitempty"`
	FamilyID              string   `json:"family_id,omitempty"`
	FamilyKey             string   `json:"family_key,omitempty"`
	UserKey               string   `json:"user_key,omitempty"`
	AuthorizationIssuedAt int64    `json:"authorization_issued_at,omitempty"`
}
type SessionData struct {
	PublicID        string    `json:"public_id"`
	UserID          string    `json:"user_id"`
	Username        string    `json:"username"`
	AuthVersion     int64     `json:"auth_version"`
	SessionVersion  int64     `json:"session_version"`
	CSRFToken       string    `json:"csrf_token"`
	UserKey         string    `json:"user_key,omitempty"`
	IPAddress       string    `json:"ip_address,omitempty"`
	UserAgent       string    `json:"user_agent,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
}
type ConsentData struct {
	ClientID        string   `json:"client_id"`
	UserID          string   `json:"user_id"`
	RedirectURI     string   `json:"redirect_uri"`
	Scopes          []string `json:"scopes"`
	State           string   `json:"state"`
	CodeChallenge   string   `json:"code_challenge"`
	ChallengeMethod string   `json:"code_challenge_method"`
	Nonce           string   `json:"nonce,omitempty"`
	AuthVersion     int64    `json:"auth_version,omitempty"`
}

var consumeMatchingScript = redis.NewScript(`
local current = redis.call("GET", KEYS[1])
if not current then
    local used = redis.call("GET", KEYS[2])
    if not used then return {0, ""} end
    local usedValue = cjson.decode(used)
    if usedValue["record_version"] ~= ARGV[1] then return {-1, ""} end
    return {-2, used}
end
local value = cjson.decode(current)
if value["record_version"] ~= ARGV[1] then return {-1, ""} end
redis.call("SET", KEYS[2], current, "PX", ARGV[2])
redis.call("DEL", KEYS[1])
return {1, current}
`)
var consumeConsentScript = redis.NewScript(`
local current = redis.call("GET", KEYS[1])
if not current then return {0, ""} end
local value = cjson.decode(current)
if value["user_id"] ~= ARGV[1] then return {-1, ""} end
redis.call("DEL", KEYS[1])
return {1, current}
`)
var rotateRefreshScript = redis.NewScript(`
local ttl = ARGV[1]
local familyPrefix = ARGV[2]
local revokedPrefix = ARGV[3]
local expected = ARGV[4]
local userFamilies = KEYS[4]

local function revokeFamily(encoded)
    local value = cjson.decode(encoded)
    local familyKey = value["family_key"]
    if not familyKey or familyKey == "" then return {-2, ""} end
    local familySet = familyPrefix .. familyKey
    local members = redis.call("SMEMBERS", familySet)
    for _, member in ipairs(members) do redis.call("DEL", member) end
    redis.call("DEL", familySet)
    redis.call("SREM", userFamilies, familyKey)
    if redis.call("SCARD", userFamilies) == 0 then redis.call("DEL", userFamilies) end
    redis.call("SET", revokedPrefix .. familyKey, "1", "PX", ttl)
    return {-1, encoded}
end

local current = redis.call("GET", KEYS[1])
if not current then
    local used = redis.call("GET", KEYS[3])
    if not used then return {0, ""} end
    if used ~= expected then return {-3, ""} end
    return revokeFamily(used)
end
if current ~= expected then return {-3, ""} end
local value = cjson.decode(current)
local familyKey = value["family_key"]
if not familyKey or familyKey == "" then return {-2, ""} end
local familySet = familyPrefix .. familyKey
if redis.call("EXISTS", revokedPrefix .. familyKey) == 1 then
    return revokeFamily(current)
end
redis.call("SET", KEYS[2], current, "PX", ttl)
redis.call("SADD", familySet, KEYS[2])
redis.call("SREM", familySet, KEYS[1])
redis.call("PEXPIRE", familySet, ttl)
redis.call("SADD", userFamilies, familyKey)
local userFamiliesTTL = redis.call("PTTL", userFamilies)
if userFamiliesTTL < tonumber(ttl) then redis.call("PEXPIRE", userFamilies, ttl) end
redis.call("DEL", KEYS[1])
redis.call("SET", KEYS[3], current, "PX", ttl)
return {1, current}
`)
var rotateRefreshWithAccessScript = redis.NewScript(`
local refreshTTL = ARGV[1]
local accessTTL = ARGV[2]
local familyPrefix = ARGV[3]
local revokedPrefix = ARGV[4]
local expected = ARGV[5]
local access = ARGV[6]
local userFamilies = KEYS[5]

local function revokeFamily(encoded)
    local value = cjson.decode(encoded)
    local familyKey = value["family_key"]
    if not familyKey or familyKey == "" then return {-2, ""} end
    local familySet = familyPrefix .. familyKey
    local members = redis.call("SMEMBERS", familySet)
    for _, member in ipairs(members) do redis.call("DEL", member) end
    redis.call("DEL", familySet)
    redis.call("SREM", userFamilies, familyKey)
    if redis.call("SCARD", userFamilies) == 0 then redis.call("DEL", userFamilies) end
    redis.call("SET", revokedPrefix .. familyKey, "1", "PX", refreshTTL)
    return {-1, encoded}
end

local current = redis.call("GET", KEYS[1])
if not current then
    local used = redis.call("GET", KEYS[3])
    if not used then return {0, ""} end
    if used ~= expected then return {-3, ""} end
    return revokeFamily(used)
end
if current ~= expected then return {-3, ""} end
local value = cjson.decode(current)
local familyKey = value["family_key"]
if not familyKey or familyKey == "" then return {-2, ""} end
local familySet = familyPrefix .. familyKey
if redis.call("EXISTS", revokedPrefix .. familyKey) == 1 then
    return revokeFamily(current)
end

redis.call("SET", KEYS[2], current, "PX", refreshTTL)
redis.call("SET", KEYS[4], access, "PX", accessTTL)
redis.call("SADD", familySet, KEYS[2], KEYS[4])
redis.call("SREM", familySet, KEYS[1])
local familyTTL = math.max(tonumber(refreshTTL), tonumber(accessTTL))
redis.call("PEXPIRE", familySet, familyTTL)
redis.call("SADD", userFamilies, familyKey)
local userFamiliesTTL = redis.call("PTTL", userFamilies)
if userFamiliesTTL < tonumber(refreshTTL) then redis.call("PEXPIRE", userFamilies, refreshTTL) end
redis.call("DEL", KEYS[1])
redis.call("SET", KEYS[3], current, "PX", refreshTTL)
return {1, current}
`)
var revokeRefreshForClientScript = redis.NewScript(`
local ttl = ARGV[1]
local familyPrefix = ARGV[2]
local revokedPrefix = ARGV[3]
local expectedClient = ARGV[4]
local userFamiliesPrefix = ARGV[5]
local encoded = redis.call("GET", KEYS[1])
if not encoded then encoded = redis.call("GET", KEYS[2]) end
if not encoded then return 0 end
local value = cjson.decode(encoded)
if value["client_id"] ~= expectedClient or value["token_use"] ~= "refresh" then return -1 end
local familyKey = value["family_key"]
local userKey = value["user_key"]
if not familyKey or familyKey == "" or not userKey or userKey == "" then return -2 end
local familySet = familyPrefix .. familyKey
local userFamilies = userFamiliesPrefix .. userKey
local members = redis.call("SMEMBERS", familySet)
for _, member in ipairs(members) do redis.call("DEL", member) end
redis.call("DEL", familySet)
redis.call("SREM", userFamilies, familyKey)
if redis.call("SCARD", userFamilies) == 0 then redis.call("DEL", userFamilies) end
redis.call("SET", revokedPrefix .. familyKey, "1", "PX", ttl)
return 1
`)
var saveFamilyTokenScript = redis.NewScript(`
if redis.call("EXISTS", KEYS[3]) == 1 then return 0 end
redis.call("SET", KEYS[1], ARGV[1], "PX", ARGV[2])
redis.call("SADD", KEYS[2], KEYS[1])
local currentTTL = redis.call("PTTL", KEYS[2])
if currentTTL < tonumber(ARGV[2]) then redis.call("PEXPIRE", KEYS[2], ARGV[2]) end
return 1
`)
var revokeFamilyScript = redis.NewScript(`
local members = redis.call("SMEMBERS", KEYS[1])
for _, member in ipairs(members) do redis.call("DEL", member) end
redis.call("DEL", KEYS[1])
redis.call("SET", KEYS[2], "1", "PX", ARGV[1])
return #members
`)
var revokeUserRefreshFamiliesScript = redis.NewScript(`
local families = redis.call("SMEMBERS", KEYS[1])
for _, familyKey in ipairs(families) do
    local familySet = ARGV[1] .. familyKey
    local members = redis.call("SMEMBERS", familySet)
    for _, member in ipairs(members) do redis.call("DEL", member) end
    redis.call("DEL", familySet)
    redis.call("SET", ARGV[2] .. familyKey, "1", "PX", ARGV[3])
end
redis.call("DEL", KEYS[1])
return #families
`)
var revokeUserRefreshFamiliesBeforeAuthVersionScript = redis.NewScript(`
local families = redis.call("SMEMBERS", KEYS[1])
local revoked = 0
local minimumAuthVersion = tonumber(ARGV[3])
for _, familyKey in ipairs(families) do
    local familySet = ARGV[1] .. familyKey
    local members = redis.call("SMEMBERS", familySet)
    local removeFamily = false
    if #members == 0 then
        redis.call("DEL", familySet)
        redis.call("SREM", KEYS[1], familyKey)
    else
        for _, member in ipairs(members) do
            local encoded = redis.call("GET", member)
            if encoded then
                local decoded, value = pcall(cjson.decode, encoded)
                local authVersion = decoded and type(value) == "table" and tonumber(value["auth_version"])
                if not authVersion or authVersion < minimumAuthVersion then
                    removeFamily = true
                    break
                end
            else
                redis.call("SREM", familySet, member)
            end
        end
        if removeFamily then
            members = redis.call("SMEMBERS", familySet)
            for _, member in ipairs(members) do redis.call("DEL", member) end
            redis.call("DEL", familySet)
            redis.call("SREM", KEYS[1], familyKey)
            redis.call("SET", ARGV[2] .. familyKey, "1", "PX", ARGV[4])
            revoked = revoked + 1
        elseif redis.call("SCARD", familySet) == 0 then
            redis.call("DEL", familySet)
            redis.call("SREM", KEYS[1], familyKey)
        end
    end
end
if redis.call("SCARD", KEYS[1]) == 0 then redis.call("DEL", KEYS[1]) end
return revoked
`)
var deleteSessionScript = redis.NewScript(`
local current = redis.call("GET", KEYS[1])
if not current then return 0 end
local value = cjson.decode(current)
local userSet = ARGV[1] .. value["user_key"]
redis.call("DEL", KEYS[1])
redis.call("SREM", userSet, KEYS[1])
redis.call("ZREM", ARGV[2], KEYS[1])
if redis.call("SCARD", userSet) == 0 then redis.call("DEL", userSet) end
return 1
`)
var saveSessionScript = redis.NewScript(`
redis.call("SET", KEYS[1], ARGV[1], "PX", ARGV[2])
redis.call("SADD", KEYS[2], KEYS[1])
local currentTTL = redis.call("PTTL", KEYS[2])
if currentTTL < tonumber(ARGV[2]) then redis.call("PEXPIRE", KEYS[2], ARGV[2]) end
local redisTime = redis.call("TIME")
local now = (tonumber(redisTime[1]) * 1000) + math.floor(tonumber(redisTime[2]) / 1000)
redis.call("ZADD", KEYS[3], now + tonumber(ARGV[2]), KEYS[1])
return 1
`)
var updateSessionScript = redis.NewScript(`
local current = redis.call("GET", KEYS[1])
if not current then return 0 end
local value = cjson.decode(current)
if value["user_key"] ~= ARGV[3] then return -1 end
if tonumber(value["auth_version"]) ~= tonumber(ARGV[4]) then return -1 end
if tonumber(value["session_version"]) ~= tonumber(ARGV[5]) then return -1 end
redis.call("SET", KEYS[1], ARGV[1], "PX", ARGV[2])
redis.call("SADD", KEYS[2], KEYS[1])
local currentTTL = redis.call("PTTL", KEYS[2])
if currentTTL < tonumber(ARGV[2]) then redis.call("PEXPIRE", KEYS[2], ARGV[2]) end
local redisTime = redis.call("TIME")
local now = (tonumber(redisTime[1]) * 1000) + math.floor(tonumber(redisTime[2]) / 1000)
redis.call("ZADD", KEYS[3], now + tonumber(ARGV[2]), KEYS[1])
return 1
`)
var deleteOtherSessionsScript = redis.NewScript(`
local members = redis.call("SMEMBERS", KEYS[1])
local deleted = 0
for _, member in ipairs(members) do
    if member ~= ARGV[1] then
        redis.call("DEL", member)
        redis.call("SREM", KEYS[1], member)
        redis.call("ZREM", ARGV[2], member)
        deleted = deleted + 1
    end
end
if redis.call("SCARD", KEYS[1]) == 0 then redis.call("DEL", KEYS[1]) end
return deleted
`)
var deleteSessionsBeforeSecurityVersionScript = redis.NewScript(`
local members = redis.call("SMEMBERS", KEYS[1])
local deleted = 0
local minimumAuthVersion = tonumber(ARGV[1])
local minimumSessionVersion = tonumber(ARGV[2])
for _, member in ipairs(members) do
    local encoded = redis.call("GET", member)
    if not encoded then
        redis.call("SREM", KEYS[1], member)
        redis.call("ZREM", ARGV[3], member)
    else
        local decoded, value = pcall(cjson.decode, encoded)
        local validValue = decoded and type(value) == "table"
        local remove = not validValue
        if validValue then
            local authVersion = tonumber(value["auth_version"])
            local sessionVersion = tonumber(value["session_version"])
            remove = not authVersion or not sessionVersion or value["user_key"] ~= ARGV[4]
                or authVersion < minimumAuthVersion or sessionVersion < minimumSessionVersion
        end
        if remove then
            redis.call("DEL", member)
            redis.call("SREM", KEYS[1], member)
            redis.call("ZREM", ARGV[3], member)
            deleted = deleted + 1
        end
    end
end
if redis.call("SCARD", KEYS[1]) == 0 then redis.call("DEL", KEYS[1]) end
return deleted
`)
var deleteSessionByPublicIDScript = redis.NewScript(`
local members = redis.call("SMEMBERS", KEYS[1])
for _, member in ipairs(members) do
    local encoded = redis.call("GET", member)
    if not encoded then
        redis.call("SREM", KEYS[1], member)
    else
        local value = cjson.decode(encoded)
        if value["public_id"] == ARGV[1] then
            redis.call("DEL", member)
            redis.call("SREM", KEYS[1], member)
            redis.call("ZREM", KEYS[2], member)
            if redis.call("SCARD", KEYS[1]) == 0 then redis.call("DEL", KEYS[1]) end
            return 1
        end
    end
end
if redis.call("SCARD", KEYS[1]) == 0 then redis.call("DEL", KEYS[1]) end
return 0
`)
var countActiveSessionsScript = redis.NewScript(`
local redisTime = redis.call("TIME")
local now = (tonumber(redisTime[1]) * 1000) + math.floor(tonumber(redisTime[2]) / 1000)
redis.call("ZREMRANGEBYSCORE", KEYS[1], "-inf", now)
return redis.call("ZCARD", KEYS[1])
`)
var touchSessionScript = redis.NewScript(`
local encoded = redis.call("GET", KEYS[1])
if not encoded then return 0 end
local value = cjson.decode(encoded)
value["last_seen_at"] = ARGV[1]
redis.call("SET", KEYS[1], cjson.encode(value), "KEEPTTL")
return 1
`)

func (s *Store) SaveAuthorizationCode(ctx context.Context, code string, data *AuthorizationData, ttl time.Duration) error {
	if data == nil {
		return ErrInvalidTokenData
	}
	version, err := randomSecret(16)
	if err != nil {
		return fmt.Errorf("generating authorization code record version: %w", err)
	}
	data.RecordVersion = version
	return s.setJSON(ctx, secretKey(codePrefix, code), data, ttl)
}
func (s *Store) GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationData, error) {
	var value AuthorizationData
	if err := s.getJSON(ctx, secretKey(codePrefix, code), &value); err == nil {
		return &value, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err := s.getJSON(ctx, secretKey(codeUsedPrefix, code), &value); err != nil {
		return nil, err
	}
	return &value, ErrAuthorizationCodeReuse
}
func (s *Store) ConsumeAuthorizationCodeIfMatch(ctx context.Context, code string, expected *AuthorizationData, usedTTL time.Duration) (*AuthorizationData, error) {
	if expected == nil || expected.RecordVersion == "" {
		return nil, ErrInvalidTokenData
	}
	usedMillis, err := ttlMilliseconds(usedTTL)
	if err != nil {
		return nil, err
	}
	values, err := consumeMatchingScript.Run(ctx, s.rdb, []string{
		secretKey(codePrefix, code), secretKey(codeUsedPrefix, code),
	}, expected.RecordVersion, usedMillis).Slice()
	if err != nil {
		return nil, err
	}
	status, payload, err := scriptResult(values)
	if err != nil {
		return nil, err
	}
	switch status {
	case 0:
		return nil, ErrNotFound
	case -1:
		return nil, ErrValueMismatch
	case -2:
		return nil, ErrAuthorizationCodeReuse
	case 1:
	default:
		return nil, fmt.Errorf("unexpected authorization code result %d", status)
	}
	var value AuthorizationData
	if err := json.Unmarshal([]byte(payload), &value); err != nil {
		return nil, err
	}
	return &value, nil
}
func (s *Store) ConsumeAuthorizationCode(ctx context.Context, code string) (*AuthorizationData, error) {
	data, err := s.rdb.GetDel(ctx, secretKey(codePrefix, code)).Bytes()
	if err != nil {
		return nil, mapRedisNil(err)
	}
	var value AuthorizationData
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Store) SaveToken(ctx context.Context, tokenID string, data *TokenData, ttl time.Duration) error {
	return s.setJSON(ctx, secretKey(tokenPrefix, tokenID), data, ttl)
}
func (s *Store) SaveTokenForRefreshFamily(ctx context.Context, tokenID string, data *TokenData, familyKey string, ttl time.Duration) error {
	if familyKey == "" {
		return ErrInvalidTokenData
	}
	ms, err := ttlMilliseconds(ttl)
	if err != nil {
		return err
	}
	data.FamilyKey = familyKey
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	result, err := saveFamilyTokenScript.Run(ctx, s.rdb, []string{
		secretKey(tokenPrefix, tokenID), refreshFamilyPrefix + familyKey, refreshRevokedPrefix + familyKey,
	}, encoded, ms).Int()
	if err != nil {
		return err
	}
	if result == 0 {
		return ErrRefreshFamilyRevoked
	}
	return nil
}
func (s *Store) GetToken(ctx context.Context, tokenID string) (*TokenData, error) {
	var value TokenData
	if err := s.getJSON(ctx, secretKey(tokenPrefix, tokenID), &value); err != nil {
		return nil, err
	}
	return &value, nil
}
func (s *Store) RevokeToken(ctx context.Context, tokenID string) error {
	count, err := s.rdb.Del(ctx, secretKey(tokenPrefix, tokenID)).Result()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SaveRefreshToken(ctx context.Context, token string, data *TokenData, ttl time.Duration) error {
	if data == nil || data.UserID == "" {
		return ErrInvalidTokenData
	}
	if data.FamilyID == "" {
		familyID, err := randomSecret(32)
		if err != nil {
			return err
		}
		data.FamilyID = familyID
	}
	if data.FamilyKey == "" {
		data.FamilyKey = digest(data.FamilyID)
	}
	data.UserKey = digest(data.UserID)
	data.TokenUse = "refresh"
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	tokenKey := secretKey(refreshPrefix, token)
	familySet := refreshFamilyPrefix + data.FamilyKey
	userFamilies := userRefreshFamiliesPrefix + digest(data.UserID)
	_, err = s.rdb.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, tokenKey, encoded, ttl)
		pipe.SAdd(ctx, familySet, tokenKey)
		pipe.Expire(ctx, familySet, ttl)
		pipe.SAdd(ctx, userFamilies, data.FamilyKey)
		pipe.Expire(ctx, userFamilies, ttl)
		return nil
	})
	return err
}
func (s *Store) GetRefreshToken(ctx context.Context, token string) (*TokenData, error) {
	var value TokenData
	if err := s.getJSON(ctx, secretKey(refreshPrefix, token), &value); err != nil {
		return nil, err
	}
	return &value, nil
}
func (s *Store) GetRefreshTokenState(ctx context.Context, token string) (*TokenData, bool, error) {
	digestValue := digest(token)
	var value TokenData
	if err := s.getJSON(ctx, refreshPrefix+digestValue, &value); err == nil {
		return &value, false, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}
	if err := s.getJSON(ctx, refreshUsedPrefix+digestValue, &value); err != nil {
		return nil, false, err
	}
	return &value, true, nil
}
func (s *Store) RotateRefreshToken(ctx context.Context, oldToken, newToken string, expected *TokenData, ttl time.Duration) (*TokenData, error) {
	if expected == nil || expected.UserID == "" || expected.FamilyKey == "" || oldToken == "" || newToken == "" || oldToken == newToken {
		return nil, ErrInvalidTokenData
	}
	ms, err := ttlMilliseconds(ttl)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(expected)
	if err != nil {
		return nil, err
	}
	oldDigest := digest(oldToken)
	values, err := rotateRefreshScript.Run(ctx, s.rdb, []string{
		refreshPrefix + oldDigest,
		secretKey(refreshPrefix, newToken),
		refreshUsedPrefix + oldDigest,
		userRefreshFamiliesPrefix + digest(expected.UserID),
	}, ms, refreshFamilyPrefix, refreshRevokedPrefix, encoded).Slice()
	if err != nil {
		return nil, err
	}
	return decodeRefreshRotationResult(values)
}

// RotateRefreshTokenAndStoreAccess commits a refresh rotation and the access
// token metadata derived from it in one Redis operation. No successful
// rotation is exposed without its access metadata, and a concurrent reuse can
// revoke both records as one family.
func (s *Store) RotateRefreshTokenAndStoreAccess(ctx context.Context, oldToken, newToken, accessTokenID string, expected, access *TokenData, refreshTTL, accessTTL time.Duration) (*TokenData, error) {
	if expected == nil || access == nil || expected.UserID == "" || expected.ClientID == "" || expected.FamilyKey == "" ||
		expected.TokenUse != "refresh" || !equalTokenScopes(access.Scopes, expected.Scopes) ||
		oldToken == "" || newToken == "" || oldToken == newToken || accessTokenID == "" ||
		access.UserID != expected.UserID || access.ClientID != expected.ClientID || access.AuthVersion != expected.AuthVersion ||
		access.AuthorizationIssuedAt != expected.AuthorizationIssuedAt {
		return nil, ErrInvalidTokenData
	}
	refreshMillis, err := ttlMilliseconds(refreshTTL)
	if err != nil {
		return nil, err
	}
	accessMillis, err := ttlMilliseconds(accessTTL)
	if err != nil {
		return nil, err
	}
	expectedPayload, err := json.Marshal(expected)
	if err != nil {
		return nil, err
	}
	access.TokenUse = "access"
	access.FamilyKey = expected.FamilyKey
	accessPayload, err := json.Marshal(access)
	if err != nil {
		return nil, err
	}
	oldDigest := digest(oldToken)
	values, err := rotateRefreshWithAccessScript.Run(ctx, s.rdb, []string{
		refreshPrefix + oldDigest,
		secretKey(refreshPrefix, newToken),
		refreshUsedPrefix + oldDigest,
		secretKey(tokenPrefix, accessTokenID),
		userRefreshFamiliesPrefix + digest(expected.UserID),
	}, refreshMillis, accessMillis, refreshFamilyPrefix, refreshRevokedPrefix, expectedPayload, accessPayload).Slice()
	if err != nil {
		return nil, err
	}
	return decodeRefreshRotationResult(values)
}

func equalTokenScopes(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func decodeRefreshRotationResult(values []interface{}) (*TokenData, error) {
	status, payload, err := scriptResult(values)
	if err != nil {
		return nil, err
	}
	switch status {
	case 0:
		return nil, ErrNotFound
	case -1:
		return nil, ErrRefreshTokenReuse
	case -2:
		return nil, ErrInvalidTokenData
	case -3:
		return nil, ErrTokenBindingMismatch
	case 1:
	default:
		return nil, fmt.Errorf("unexpected refresh rotation result %d", status)
	}
	var value TokenData
	if err := json.Unmarshal([]byte(payload), &value); err != nil {
		return nil, err
	}
	return &value, nil
}
func (s *Store) RevokeRefreshTokenForClient(ctx context.Context, token, clientID string, ttl time.Duration) error {
	ms, err := ttlMilliseconds(ttl)
	if err != nil {
		return err
	}
	digestValue := digest(token)
	result, err := revokeRefreshForClientScript.Run(ctx, s.rdb, []string{
		refreshPrefix + digestValue, refreshUsedPrefix + digestValue,
	}, ms, refreshFamilyPrefix, refreshRevokedPrefix, clientID, userRefreshFamiliesPrefix).Int()
	if err != nil {
		return err
	}
	switch result {
	case 0:
		return ErrNotFound
	case -1:
		return ErrTokenBindingMismatch
	case -2:
		return ErrInvalidTokenData
	case 1:
		return nil
	default:
		return fmt.Errorf("unexpected refresh revocation result %d", result)
	}
}
func (s *Store) RevokeRefreshFamily(ctx context.Context, familyID string, ttl time.Duration) error {
	return s.revokeFamilyKey(ctx, digest(familyID), ttl)
}

// RevokeRefreshFamiliesForUser atomically deletes every current refresh token
// and family-bound access-token record for a user. Revocation markers remain
// for the supplied TTL so a concurrent writer cannot resurrect a family.
func (s *Store) RevokeRefreshFamiliesForUser(ctx context.Context, userID string, ttl time.Duration) (int64, error) {
	if userID == "" {
		return 0, ErrInvalidTokenData
	}
	ms, err := ttlMilliseconds(ttl)
	if err != nil {
		return 0, err
	}
	count, err := revokeUserRefreshFamiliesScript.Run(ctx, s.rdb, []string{
		userRefreshFamiliesPrefix + digest(userID),
	}, refreshFamilyPrefix, refreshRevokedPrefix, ms).Int64()
	if err != nil {
		return 0, err
	}
	return count, nil
}

// RevokeRefreshFamiliesBeforeAuthVersion removes only token families issued
// before the committed PostgreSQL auth generation. A user who signs in again
// while durable cleanup is pending keeps the newly issued family.
func (s *Store) RevokeRefreshFamiliesBeforeAuthVersion(ctx context.Context, userID string, minimumAuthVersion int64, ttl time.Duration) (int64, error) {
	if userID == "" || minimumAuthVersion <= 0 {
		return 0, ErrInvalidTokenData
	}
	ms, err := ttlMilliseconds(ttl)
	if err != nil {
		return 0, err
	}
	return revokeUserRefreshFamiliesBeforeAuthVersionScript.Run(ctx, s.rdb, []string{
		userRefreshFamiliesPrefix + digest(userID),
	}, refreshFamilyPrefix, refreshRevokedPrefix, minimumAuthVersion, ms).Int64()
}
func (s *Store) revokeFamilyKey(ctx context.Context, familyKey string, ttl time.Duration) error {
	ms, err := ttlMilliseconds(ttl)
	if err != nil {
		return err
	}
	return revokeFamilyScript.Run(ctx, s.rdb, []string{refreshFamilyPrefix + familyKey, refreshRevokedPrefix + familyKey}, ms).Err()
}

func (s *Store) SaveCSRFState(ctx context.Context, state string, data map[string]string, ttl time.Duration) error {
	return s.setJSON(ctx, secretKey(csrfPrefix, state), data, ttl)
}
func (s *Store) ConsumeCSRFState(ctx context.Context, state string) (map[string]string, error) {
	data, err := s.rdb.GetDel(ctx, secretKey(csrfPrefix, state)).Bytes()
	if err != nil {
		return nil, mapRedisNil(err)
	}
	var value map[string]string
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return value, nil
}
func (s *Store) Ping(ctx context.Context) error { return s.rdb.Ping(ctx).Err() }

var authorizationIssueTimeScript = redis.NewScript(`
local now = redis.call("TIME")
local micros = (tonumber(now[1]) * 1000000) + tonumber(now[2])
local current = redis.call("GET", KEYS[1])
if current and tonumber(current) >= micros then micros = tonumber(current) + 1 end
local revoked = redis.call("GET", KEYS[2])
if revoked and tonumber(revoked) >= micros then micros = tonumber(revoked) + 1 end
redis.call("SET", KEYS[1], string.format("%.0f", micros), "PX", ARGV[1])
return string.format("%.0f", micros)
`)

// AuthorizationIssueTime allocates a monotonically increasing logical time
// for a user/client grant. The Redis clock is combined with the previous
// logical value so ordering remains safe across instances, equal timestamps,
// and wall-clock rollback.
func (s *Store) AuthorizationIssueTime(ctx context.Context, userID, clientID string, ttl time.Duration) (int64, error) {
	ms, err := ttlMilliseconds(ttl)
	if err != nil {
		return 0, err
	}
	value, err := authorizationIssueTimeScript.Run(ctx, s.rdb, []string{
		authorizationClockKey(userID, clientID), authorizationRevocationKey(userID, clientID),
	}, ms).Text()
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(value, 10, 64)
}

var revokeAuthorizationScript = redis.NewScript(`
local now = redis.call("TIME")
local micros = (tonumber(now[1]) * 1000000) + tonumber(now[2])
local current = redis.call("GET", KEYS[1])
if current and tonumber(current) >= micros then micros = tonumber(current) + 1 end
local revoked = redis.call("GET", KEYS[2])
if revoked and tonumber(revoked) >= micros then micros = tonumber(revoked) + 1 end
redis.call("SET", KEYS[1], string.format("%.0f", micros), "PX", ARGV[1])
redis.call("SET", KEYS[2], string.format("%.0f", micros), "PX", ARGV[1])
return string.format("%.0f", micros)
`)

func (s *Store) RevokeUserClientAuthorization(ctx context.Context, userID, clientID string, ttl time.Duration) (int64, error) {
	ms, err := ttlMilliseconds(ttl)
	if err != nil {
		return 0, err
	}
	value, err := revokeAuthorizationScript.Run(ctx, s.rdb, []string{
		authorizationClockKey(userID, clientID), authorizationRevocationKey(userID, clientID),
	}, ms).Text()
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(value, 10, 64)
}

func (s *Store) IsUserClientAuthorizationRevoked(ctx context.Context, userID, clientID string, authorizationIssuedAt int64) (bool, error) {
	value, err := s.rdb.Get(ctx, authorizationRevocationKey(userID, clientID)).Int64()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return authorizationIssuedAt <= value, nil
}

func authorizationRevocationKey(userID, clientID string) string {
	return authorizationRevokedPrefix + digest(userID+"\x00"+clientID)
}

func authorizationClockKey(userID, clientID string) string {
	return authorizationClockPrefix + digest(userID+"\x00"+clientID)
}

func (s *Store) SaveSession(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error {
	if data.CSRFToken == "" {
		token, err := randomSecret(32)
		if err != nil {
			return err
		}
		data.CSRFToken = token
	}
	if data.PublicID == "" {
		publicID, err := randomSecret(16)
		if err != nil {
			return err
		}
		data.PublicID = publicID
	}
	now := time.Now().UTC()
	if data.CreatedAt.IsZero() {
		data.CreatedAt = now
	}
	if data.LastSeenAt.IsZero() {
		data.LastSeenAt = data.CreatedAt
	}
	if data.AuthenticatedAt.IsZero() {
		data.AuthenticatedAt = data.CreatedAt
	}
	data.UserKey = digest(data.UserID)
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	ttlMillis, err := ttlMilliseconds(ttl)
	if err != nil {
		return err
	}
	sessionKey := secretKey(sessionPrefix, sessionID)
	userSet := userSessionsPrefix + data.UserKey
	return saveSessionScript.Run(ctx, s.rdb, []string{sessionKey, userSet, allSessionsKey}, encoded, ttlMillis).Err()
}

// UpdateSession refreshes an existing session atomically without recreating or
// upgrading a session that was concurrently revoked. The stored user binding
// and both expected security versions must still match.
func (s *Store) UpdateSession(
	ctx context.Context,
	sessionID string,
	data *SessionData,
	expectedAuthVersion, expectedSessionVersion int64,
	ttl time.Duration,
) error {
	if sessionID == "" || data == nil || data.UserID == "" || data.CSRFToken == "" || data.PublicID == "" {
		return ErrInvalidTokenData
	}
	data.UserKey = digest(data.UserID)
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	ttlMillis, err := ttlMilliseconds(ttl)
	if err != nil {
		return err
	}
	sessionKey := secretKey(sessionPrefix, sessionID)
	userSet := userSessionsPrefix + data.UserKey
	result, err := updateSessionScript.Run(
		ctx, s.rdb, []string{sessionKey, userSet, allSessionsKey},
		encoded, ttlMillis, data.UserKey, expectedAuthVersion, expectedSessionVersion,
	).Int()
	if err != nil {
		return err
	}
	switch result {
	case 0:
		return ErrNotFound
	case -1:
		return ErrValueMismatch
	case 1:
		return nil
	default:
		return fmt.Errorf("unexpected session update result %d", result)
	}
}
func (s *Store) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	var value SessionData
	if err := s.getJSON(ctx, secretKey(sessionPrefix, sessionID), &value); err != nil {
		return nil, err
	}
	return &value, nil
}
func (s *Store) DeleteSession(ctx context.Context, sessionID string) error {
	result, err := deleteSessionScript.Run(ctx, s.rdb, []string{secretKey(sessionPrefix, sessionID)}, userSessionsPrefix, allSessionsKey).Int()
	if err != nil {
		return err
	}
	if result == 0 {
		return ErrNotFound
	}
	return nil
}
func (s *Store) DeleteOtherUserSessions(ctx context.Context, userID, currentSessionID string) (int64, error) {
	keep := ""
	if currentSessionID != "" {
		keep = secretKey(sessionPrefix, currentSessionID)
	}
	return deleteOtherSessionsScript.Run(ctx, s.rdb, []string{userSessionsPrefix + digest(userID)}, keep, allSessionsKey).Int64()
}
func (s *Store) DeleteUserSessions(ctx context.Context, userID string) (int64, error) {
	return s.DeleteOtherUserSessions(ctx, userID, "")
}

// DeleteUserSessionsBeforeVersion removes only stale browser sessions after
// PostgreSQL has committed a newer authoritative generation. Sessions created
// concurrently at the committed generation are preserved.
func (s *Store) DeleteUserSessionsBeforeVersion(ctx context.Context, userID string, minimumVersion int64) (int64, error) {
	if minimumVersion <= 0 {
		return 0, fmt.Errorf("session version must be positive")
	}
	return s.DeleteUserSessionsBeforeSecurityVersion(ctx, userID, 1, minimumVersion)
}

// DeleteUserSessionsBeforeSecurityVersion removes sessions issued before
// either committed security generation while preserving sessions created
// after the PostgreSQL mutation that scheduled cleanup.
func (s *Store) DeleteUserSessionsBeforeSecurityVersion(ctx context.Context, userID string, minimumAuthVersion, minimumSessionVersion int64) (int64, error) {
	if userID == "" || minimumAuthVersion <= 0 || minimumSessionVersion <= 0 {
		return 0, fmt.Errorf("security versions and user ID must be valid")
	}
	userKey := digest(userID)
	return deleteSessionsBeforeSecurityVersionScript.Run(
		ctx,
		s.rdb,
		[]string{userSessionsPrefix + userKey},
		minimumAuthVersion,
		minimumSessionVersion,
		allSessionsKey,
		userKey,
	).Int64()
}

func (s *Store) DeleteUserSessionByPublicID(ctx context.Context, userID, publicID string) error {
	if publicID == "" {
		return ErrNotFound
	}
	result, err := deleteSessionByPublicIDScript.Run(ctx, s.rdb, []string{userSessionsPrefix + digest(userID), allSessionsKey}, publicID).Int()
	if err != nil {
		return err
	}
	if result == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListUserSessions(ctx context.Context, userID string) ([]SessionData, error) {
	setKey := userSessionsPrefix + digest(userID)
	members, err := s.rdb.SMembers(ctx, setKey).Result()
	if err != nil {
		return nil, err
	}
	if len(members) == 0 {
		return []SessionData{}, nil
	}
	pipe := s.rdb.Pipeline()
	commands := make([]*redis.StringCmd, len(members))
	for index, member := range members {
		commands[index] = pipe.Get(ctx, member)
	}
	_, _ = pipe.Exec(ctx)
	items := make([]SessionData, 0, len(members))
	stale := make([]any, 0)
	for index, command := range commands {
		encoded, commandErr := command.Bytes()
		if errors.Is(commandErr, redis.Nil) {
			stale = append(stale, members[index])
			continue
		}
		if commandErr != nil {
			return nil, commandErr
		}
		var item SessionData
		if err := json.Unmarshal(encoded, &item); err != nil {
			return nil, fmt.Errorf("decoding session metadata: %w", err)
		}
		items = append(items, item)
	}
	if len(stale) > 0 {
		_ = s.rdb.SRem(ctx, setKey, stale...).Err()
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return items, nil
}

func (s *Store) TouchSession(ctx context.Context, sessionID string, seenAt time.Time) error {
	result, err := touchSessionScript.Run(ctx, s.rdb, []string{secretKey(sessionPrefix, sessionID)}, seenAt.UTC().Format(time.RFC3339Nano)).Int()
	if err != nil {
		return err
	}
	if result == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CountActiveSessions(ctx context.Context) (int64, error) {
	return countActiveSessionsScript.Run(ctx, s.rdb, []string{allSessionsKey}).Int64()
}

func (s *Store) SaveConsent(ctx context.Context, challenge string, data *ConsentData, ttl time.Duration) error {
	return s.setJSON(ctx, secretKey(consentPrefix, challenge), data, ttl)
}
func (s *Store) GetConsent(ctx context.Context, challenge string) (*ConsentData, error) {
	var value ConsentData
	if err := s.getJSON(ctx, secretKey(consentPrefix, challenge), &value); err != nil {
		return nil, err
	}
	return &value, nil
}
func (s *Store) ConsumeConsentForUser(ctx context.Context, challenge, userID string) (*ConsentData, error) {
	values, err := consumeConsentScript.Run(ctx, s.rdb, []string{secretKey(consentPrefix, challenge)}, userID).Slice()
	if err != nil {
		return nil, err
	}
	status, payload, err := scriptResult(values)
	if err != nil {
		return nil, err
	}
	switch status {
	case 0:
		return nil, ErrNotFound
	case -1:
		return nil, ErrConsentUserMismatch
	case 1:
	default:
		return nil, fmt.Errorf("unexpected consent result %d", status)
	}
	var value ConsentData
	if err := json.Unmarshal([]byte(payload), &value); err != nil {
		return nil, err
	}
	return &value, nil
}
func (s *Store) ConsumeConsent(ctx context.Context, challenge string) (*ConsentData, error) {
	data, err := s.rdb.GetDel(ctx, secretKey(consentPrefix, challenge)).Bytes()
	if err != nil {
		return nil, mapRedisNil(err)
	}
	var value ConsentData
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Store) setJSON(ctx context.Context, key string, value any, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("TTL must be positive")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, key, encoded, ttl).Err()
}
func (s *Store) getJSON(ctx context.Context, key string, target any) error {
	data, err := s.rdb.Get(ctx, key).Bytes()
	if err != nil {
		return mapRedisNil(err)
	}
	return json.Unmarshal(data, target)
}
func secretKey(prefix, secret string) string { return prefix + digest(secret) }
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func randomSecret(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
func mapRedisNil(err error) error {
	if errors.Is(err, redis.Nil) {
		return ErrNotFound
	}
	return err
}
func ttlMilliseconds(ttl time.Duration) (int64, error) {
	if ttl < time.Millisecond {
		return 0, fmt.Errorf("TTL must be at least 1ms")
	}
	return ttl.Milliseconds(), nil
}
func scriptResult(values []any) (int64, string, error) {
	if len(values) != 2 {
		return 0, "", fmt.Errorf("unexpected script result length %d", len(values))
	}
	status, ok := values[0].(int64)
	if !ok {
		return 0, "", fmt.Errorf("unexpected script status %T", values[0])
	}
	payload, ok := values[1].(string)
	if !ok {
		return 0, "", fmt.Errorf("unexpected script payload %T", values[1])
	}
	return status, payload, nil
}
