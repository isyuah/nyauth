package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const oauthReauthenticationPrefix = keyPrefix + "oauth-reauthentication:"

type OAuthReauthenticationData struct {
	RequestURI string    `json:"request_uri"`
	CreatedAt  time.Time `json:"created_at"`
}

func (s *Store) SaveOAuthReauthentication(ctx context.Context, token string, data *OAuthReauthenticationData, ttl time.Duration) error {
	if token == "" || data == nil || data.RequestURI == "" || data.CreatedAt.IsZero() {
		return ErrInvalidTokenData
	}
	if ttl <= 0 {
		return fmt.Errorf("OAuth reauthentication TTL must be positive")
	}
	return s.setJSON(ctx, secretKey(oauthReauthenticationPrefix, token), data, ttl)
}

func (s *Store) ConsumeOAuthReauthentication(ctx context.Context, token string) (*OAuthReauthenticationData, error) {
	if token == "" {
		return nil, ErrNotFound
	}
	encoded, err := s.rdb.GetDel(ctx, secretKey(oauthReauthenticationPrefix, token)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var value OAuthReauthenticationData
	if err := json.Unmarshal(encoded, &value); err != nil {
		return nil, fmt.Errorf("decoding OAuth reauthentication state: %w", err)
	}
	if value.RequestURI == "" || value.CreatedAt.IsZero() {
		return nil, ErrInvalidTokenData
	}
	return &value, nil
}
