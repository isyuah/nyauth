package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const mfaPendingPrefix = keyPrefix + "mfa-pending:"

type MFAPendingData struct {
	UserID         string    `json:"user_id"`
	Username       string    `json:"username"`
	AuthVersion    int64     `json:"auth_version"`
	SessionVersion int64     `json:"session_version"`
	Purpose        string    `json:"purpose"`
	PrimaryMethod  string    `json:"primary_method"`
	Provider       string    `json:"provider,omitempty"`
	SessionDigest  string    `json:"session_digest,omitempty"`
	ReturnTo       string    `json:"return_to"`
	CSRFToken      string    `json:"csrf_token"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func (s *Store) SaveMFAPending(ctx context.Context, token string, data *MFAPendingData, ttl time.Duration) error {
	if token == "" || data == nil || data.UserID == "" || data.Username == "" || data.Purpose == "" || data.PrimaryMethod == "" {
		return ErrInvalidTokenData
	}
	if ttl <= 0 {
		return fmt.Errorf("MFA pending TTL must be positive")
	}
	if data.CSRFToken == "" {
		csrfToken, err := randomSecret(32)
		if err != nil {
			return err
		}
		data.CSRFToken = csrfToken
	}
	now := time.Now().UTC()
	if data.CreatedAt.IsZero() {
		data.CreatedAt = now
	}
	data.ExpiresAt = data.CreatedAt.Add(ttl)
	return s.setJSON(ctx, secretKey(mfaPendingPrefix, token), data, ttl)
}

func (s *Store) GetMFAPending(ctx context.Context, token string) (*MFAPendingData, error) {
	var value MFAPendingData
	if err := s.getJSON(ctx, secretKey(mfaPendingPrefix, token), &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Store) ConsumeMFAPending(ctx context.Context, token string) (*MFAPendingData, error) {
	encoded, err := s.rdb.GetDel(ctx, secretKey(mfaPendingPrefix, token)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var value MFAPendingData
	if err := json.Unmarshal(encoded, &value); err != nil {
		return nil, fmt.Errorf("decoding MFA pending state: %w", err)
	}
	return &value, nil
}

func (s *Store) DeleteMFAPending(ctx context.Context, token string) error {
	count, err := s.rdb.Del(ctx, secretKey(mfaPendingPrefix, token)).Result()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}
