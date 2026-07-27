package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const webAuthnCeremonyPrefix = keyPrefix + "webauthn-ceremony:"

var consumeWebAuthnAndMFAPendingScript = redis.NewScript(`
local ceremony = redis.call("GET", KEYS[1])
local pending = redis.call("GET", KEYS[2])
if not ceremony or not pending then return 0 end
if ceremony ~= ARGV[1] or pending ~= ARGV[2] then return -1 end
redis.call("DEL", KEYS[1], KEYS[2])
return 1
`)

// WebAuthnCeremonyData is the server-owned state binding one browser
// WebAuthn ceremony to its purpose and, where applicable, the authenticated
// session or MFA challenge that initiated it. SessionData is the exact
// msgpack representation returned by go-webauthn.
type WebAuthnCeremonyData struct {
	SessionData    []byte    `json:"session_data"`
	Purpose        string    `json:"purpose"`
	UserID         string    `json:"user_id,omitempty"`
	Username       string    `json:"username,omitempty"`
	AuthVersion    int64     `json:"auth_version,omitempty"`
	SessionVersion int64     `json:"session_version,omitempty"`
	SessionDigest  string    `json:"session_digest,omitempty"`
	ParentDigest   string    `json:"parent_digest,omitempty"`
	CredentialName string    `json:"credential_name,omitempty"`
	ReturnTo       string    `json:"return_to,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func (s *Store) SaveWebAuthnCeremony(ctx context.Context, token string, data *WebAuthnCeremonyData, ttl time.Duration) error {
	if token == "" || data == nil || len(data.SessionData) == 0 || data.Purpose == "" {
		return ErrInvalidTokenData
	}
	if ttl <= 0 {
		return fmt.Errorf("WebAuthn ceremony TTL must be positive")
	}
	now := time.Now().UTC()
	if data.CreatedAt.IsZero() {
		data.CreatedAt = now
	}
	data.ExpiresAt = data.CreatedAt.Add(ttl)
	return s.setJSON(ctx, secretKey(webAuthnCeremonyPrefix, token), data, ttl)
}

func (s *Store) GetWebAuthnCeremony(ctx context.Context, token string) (*WebAuthnCeremonyData, error) {
	var value WebAuthnCeremonyData
	if err := s.getJSON(ctx, secretKey(webAuthnCeremonyPrefix, token), &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Store) ConsumeWebAuthnCeremony(ctx context.Context, token string) (*WebAuthnCeremonyData, error) {
	encoded, err := s.rdb.GetDel(ctx, secretKey(webAuthnCeremonyPrefix, token)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var value WebAuthnCeremonyData
	if err := json.Unmarshal(encoded, &value); err != nil {
		return nil, fmt.Errorf("decoding WebAuthn ceremony state: %w", err)
	}
	return &value, nil
}

func (s *Store) DeleteWebAuthnCeremony(ctx context.Context, token string) error {
	count, err := s.rdb.Del(ctx, secretKey(webAuthnCeremonyPrefix, token)).Result()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

// ConsumeWebAuthnCeremonyAndMFAPending atomically verifies and removes the
// child WebAuthn ceremony and its parent MFA challenge. A successful Passkey
// assertion can therefore never leave either half independently replayable.
func (s *Store) ConsumeWebAuthnCeremonyAndMFAPending(
	ctx context.Context,
	ceremonyToken string,
	expectedCeremony *WebAuthnCeremonyData,
	pendingToken string,
	expectedPending *MFAPendingData,
) error {
	if ceremonyToken == "" || expectedCeremony == nil || pendingToken == "" || expectedPending == nil {
		return ErrInvalidTokenData
	}
	ceremonyJSON, err := json.Marshal(expectedCeremony)
	if err != nil {
		return fmt.Errorf("encoding expected WebAuthn ceremony: %w", err)
	}
	pendingJSON, err := json.Marshal(expectedPending)
	if err != nil {
		return fmt.Errorf("encoding expected MFA pending state: %w", err)
	}
	result, err := consumeWebAuthnAndMFAPendingScript.Run(
		ctx,
		s.rdb,
		[]string{
			secretKey(webAuthnCeremonyPrefix, ceremonyToken),
			secretKey(mfaPendingPrefix, pendingToken),
		},
		ceremonyJSON,
		pendingJSON,
	).Int()
	if err != nil {
		return err
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
