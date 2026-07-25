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
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix            = "nyauth:"
	sessionPrefix        = keyPrefix + "session:"
	userSessionsPrefix   = keyPrefix + "user-sessions:"
	codePrefix           = keyPrefix + "code:"
	tokenPrefix          = keyPrefix + "token:"
	refreshPrefix        = keyPrefix + "refresh:"
	refreshUsedPrefix    = keyPrefix + "refresh-used:"
	refreshFamilyPrefix  = keyPrefix + "refresh-family:"
	refreshRevokedPrefix = keyPrefix + "refresh-revoked:"
	csrfPrefix           = keyPrefix + "csrf:"
	consentPrefix        = keyPrefix + "consent:"
)

var (
	ErrNotFound             = errors.New("session value not found or expired")
	ErrValueMismatch        = errors.New("session value no longer matches")
	ErrConsentUserMismatch  = errors.New("consent does not belong to current user")
	ErrRefreshTokenReuse    = errors.New("refresh token reuse detected; token family revoked")
	ErrRefreshFamilyRevoked = errors.New("refresh token family is revoked")
	ErrTokenBindingMismatch = errors.New("stored token binding does not match")
	ErrInvalidTokenData     = errors.New("invalid stored token data")
)

type Store struct{ rdb *redis.Client }

func NewStore(rdb *redis.Client) *Store { return &Store{rdb: rdb} }

type AuthorizationData struct {
	ClientID        string   `json:"client_id"`
	UserID          string   `json:"user_id"`
	RedirectURI     string   `json:"redirect_uri"`
	Scopes          []string `json:"scopes"`
	CodeChallenge   string   `json:"code_challenge"`
	ChallengeMethod string   `json:"code_challenge_method"`
	Nonce           string   `json:"nonce,omitempty"`
	AuthVersion     int64    `json:"auth_version,omitempty"`
}
type TokenData struct {
	ClientID    string   `json:"client_id"`
	UserID      string   `json:"user_id"`
	Scopes      []string `json:"scopes"`
	TokenUse    string   `json:"token_use"`
	AuthVersion int64    `json:"auth_version,omitempty"`
	FamilyID    string   `json:"family_id,omitempty"`
	FamilyKey   string   `json:"family_key,omitempty"`
}
type SessionData struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	AuthVersion int64  `json:"auth_version"`
	CSRFToken   string `json:"csrf_token"`
	UserKey     string `json:"user_key,omitempty"`
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
if not current then return {0, ""} end
if current ~= ARGV[1] then return {-1, ""} end
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

local function revokeFamily(encoded)
    local value = cjson.decode(encoded)
    local familyKey = value["family_key"]
    if not familyKey or familyKey == "" then return {-2, ""} end
    local familySet = familyPrefix .. familyKey
    local members = redis.call("SMEMBERS", familySet)
    for _, member in ipairs(members) do redis.call("DEL", member) end
    redis.call("DEL", familySet)
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
redis.call("DEL", KEYS[1])
redis.call("SET", KEYS[3], current, "PX", ttl)
return {1, current}
`)
var revokeRefreshForClientScript = redis.NewScript(`
local ttl = ARGV[1]
local familyPrefix = ARGV[2]
local revokedPrefix = ARGV[3]
local expectedClient = ARGV[4]
local encoded = redis.call("GET", KEYS[1])
if not encoded then encoded = redis.call("GET", KEYS[2]) end
if not encoded then return 0 end
local value = cjson.decode(encoded)
if value["client_id"] ~= expectedClient or value["token_use"] ~= "refresh" then return -1 end
local familyKey = value["family_key"]
if not familyKey or familyKey == "" then return -2 end
local familySet = familyPrefix .. familyKey
local members = redis.call("SMEMBERS", familySet)
for _, member in ipairs(members) do redis.call("DEL", member) end
redis.call("DEL", familySet)
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
var deleteSessionScript = redis.NewScript(`
local current = redis.call("GET", KEYS[1])
if not current then return 0 end
local value = cjson.decode(current)
local userSet = ARGV[1] .. value["user_key"]
redis.call("DEL", KEYS[1])
redis.call("SREM", userSet, KEYS[1])
if redis.call("SCARD", userSet) == 0 then redis.call("DEL", userSet) end
return 1
`)
var deleteOtherSessionsScript = redis.NewScript(`
local members = redis.call("SMEMBERS", KEYS[1])
local deleted = 0
for _, member in ipairs(members) do
    if member ~= ARGV[1] then
        redis.call("DEL", member)
        redis.call("SREM", KEYS[1], member)
        deleted = deleted + 1
    end
end
if redis.call("SCARD", KEYS[1]) == 0 then redis.call("DEL", KEYS[1]) end
return deleted
`)

func (s *Store) SaveAuthorizationCode(ctx context.Context, code string, data *AuthorizationData, ttl time.Duration) error {
	return s.setJSON(ctx, secretKey(codePrefix, code), data, ttl)
}
func (s *Store) GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationData, error) {
	var value AuthorizationData
	if err := s.getJSON(ctx, secretKey(codePrefix, code), &value); err != nil {
		return nil, err
	}
	return &value, nil
}
func (s *Store) ConsumeAuthorizationCodeIfMatch(ctx context.Context, code string, expected *AuthorizationData) (*AuthorizationData, error) {
	encoded, err := json.Marshal(expected)
	if err != nil {
		return nil, err
	}
	values, err := consumeMatchingScript.Run(ctx, s.rdb, []string{secretKey(codePrefix, code)}, encoded).Slice()
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
	data.TokenUse = "refresh"
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	tokenKey := secretKey(refreshPrefix, token)
	familySet := refreshFamilyPrefix + data.FamilyKey
	_, err = s.rdb.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, tokenKey, encoded, ttl)
		pipe.SAdd(ctx, familySet, tokenKey)
		pipe.Expire(ctx, familySet, ttl)
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
	ms, err := ttlMilliseconds(ttl)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(expected)
	if err != nil {
		return nil, err
	}
	oldDigest := digest(oldToken)
	values, err := rotateRefreshScript.Run(ctx, s.rdb, []string{refreshPrefix + oldDigest, secretKey(refreshPrefix, newToken), refreshUsedPrefix + oldDigest}, ms, refreshFamilyPrefix, refreshRevokedPrefix, encoded).Slice()
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
	}, ms, refreshFamilyPrefix, refreshRevokedPrefix, clientID).Int()
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

func (s *Store) SaveSession(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error {
	if data.CSRFToken == "" {
		token, err := randomSecret(32)
		if err != nil {
			return err
		}
		data.CSRFToken = token
	}
	data.UserKey = digest(data.UserID)
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	sessionKey := secretKey(sessionPrefix, sessionID)
	userSet := userSessionsPrefix + data.UserKey
	_, err = s.rdb.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, sessionKey, encoded, ttl)
		pipe.SAdd(ctx, userSet, sessionKey)
		pipe.Expire(ctx, userSet, ttl)
		return nil
	})
	return err
}
func (s *Store) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	var value SessionData
	if err := s.getJSON(ctx, secretKey(sessionPrefix, sessionID), &value); err != nil {
		return nil, err
	}
	return &value, nil
}
func (s *Store) DeleteSession(ctx context.Context, sessionID string) error {
	result, err := deleteSessionScript.Run(ctx, s.rdb, []string{secretKey(sessionPrefix, sessionID)}, userSessionsPrefix).Int()
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
	return deleteOtherSessionsScript.Run(ctx, s.rdb, []string{userSessionsPrefix + digest(userID)}, keep).Int64()
}
func (s *Store) DeleteUserSessions(ctx context.Context, userID string) (int64, error) {
	return s.DeleteOtherUserSessions(ctx, userID, "")
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
