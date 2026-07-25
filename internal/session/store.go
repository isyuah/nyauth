package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix         = "nyauth:"
	sessionPrefix     = keyPrefix + "session:"
	codePrefix        = keyPrefix + "code:"
	tokenPrefix       = keyPrefix + "token:"
	refreshPrefix     = keyPrefix + "refresh:"
	csrfPrefix        = keyPrefix + "csrf:"
	consentPrefix     = keyPrefix + "consent:"
)

// Store manages sessions and short-lived tokens in Redis.
type Store struct {
	rdb *redis.Client
}

// NewStore creates a new session store.
func NewStore(rdb *redis.Client) *Store {
	return &Store{rdb: rdb}
}

// AuthorizationData holds data for an authorization code.
type AuthorizationData struct {
	ClientID     string   `json:"client_id"`
	UserID       string   `json:"user_id"`
	RedirectURI  string   `json:"redirect_uri"`
	Scopes       []string `json:"scopes"`
	CodeChallenge string  `json:"code_challenge,omitempty"`
	ChallengeMethod string `json:"code_challenge_method,omitempty"`
}

// SaveAuthorizationCode stores authorization code data with a TTL.
func (s *Store) SaveAuthorizationCode(ctx context.Context, code string, data *AuthorizationData, ttl time.Duration) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, codePrefix+code, b, ttl).Err()
}

// ConsumeAuthorizationCode retrieves and deletes the authorization code.
func (s *Store) ConsumeAuthorizationCode(ctx context.Context, code string) (*AuthorizationData, error) {
	key := codePrefix + code
	data, err := s.rdb.GetDel(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("authorization code not found or expired")
		}
		return nil, err
	}
	var authData AuthorizationData
	if err := json.Unmarshal(data, &authData); err != nil {
		return nil, err
	}
	return &authData, nil
}

// TokenData holds data for an issued token.
type TokenData struct {
	ClientID string   `json:"client_id"`
	UserID   string   `json:"user_id"`
	Scopes   []string `json:"scopes"`
	TokenUse string   `json:"token_use"` // access, id, refresh
}

// SaveToken stores token metadata.
func (s *Store) SaveToken(ctx context.Context, tokenID string, data *TokenData, ttl time.Duration) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, tokenPrefix+tokenID, b, ttl).Err()
}

// GetToken retrieves token metadata.
func (s *Store) GetToken(ctx context.Context, tokenID string) (*TokenData, error) {
	data, err := s.rdb.Get(ctx, tokenPrefix+tokenID).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("token not found")
		}
		return nil, err
	}
	var td TokenData
	if err := json.Unmarshal(data, &td); err != nil {
		return nil, err
	}
	return &td, nil
}

// RevokeToken deletes a token.
func (s *Store) RevokeToken(ctx context.Context, tokenID string) error {
	return s.rdb.Del(ctx, tokenPrefix+tokenID).Err()
}

// SaveRefreshToken stores refresh token metadata.
func (s *Store) SaveRefreshToken(ctx context.Context, tokenID string, data *TokenData, ttl time.Duration) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, refreshPrefix+tokenID, b, ttl).Err()
}

// GetRefreshToken retrieves refresh token metadata.
func (s *Store) GetRefreshToken(ctx context.Context, tokenID string) (*TokenData, error) {
	data, err := s.rdb.Get(ctx, refreshPrefix+tokenID).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("refresh token not found")
		}
		return nil, err
	}
	var td TokenData
	if err := json.Unmarshal(data, &td); err != nil {
		return nil, err
	}
	return &td, nil
}

// RevokeRefreshToken deletes a refresh token.
func (s *Store) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	return s.rdb.Del(ctx, refreshPrefix+tokenID).Err()
}

// SaveCSRFState stores a CSRF state for OAuth flows.
func (s *Store) SaveCSRFState(ctx context.Context, state string, data map[string]string, ttl time.Duration) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, csrfPrefix+state, b, ttl).Err()
}

// ConsumeCSRFState retrieves and deletes the CSRF state.
func (s *Store) ConsumeCSRFState(ctx context.Context, state string) (map[string]string, error) {
	data, err := s.rdb.GetDel(ctx, csrfPrefix+state).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("state not found or expired")
		}
		return nil, err
	}
	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Ping checks the Redis connection.
func (s *Store) Ping(ctx context.Context) error {
	return s.rdb.Ping(ctx).Err()
}

// SessionData holds user session information.
type SessionData struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
}

// SaveSession stores a user session with a TTL.
func (s *Store) SaveSession(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, sessionPrefix+sessionID, b, ttl).Err()
}

// GetSession retrieves session data.
func (s *Store) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	data, err := s.rdb.Get(ctx, sessionPrefix+sessionID).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found")
		}
		return nil, err
	}
	var sd SessionData
	if err := json.Unmarshal(data, &sd); err != nil {
		return nil, err
	}
	return &sd, nil
}

// DeleteSession removes a session.
func (s *Store) DeleteSession(ctx context.Context, sessionID string) error {
	return s.rdb.Del(ctx, sessionPrefix+sessionID).Err()
}

// ConsentData holds data for a pending consent decision.
type ConsentData struct {
	ClientID    string   `json:"client_id"`
	UserID      string   `json:"user_id"`
	RedirectURI string   `json:"redirect_uri"`
	Scopes      []string `json:"scopes"`
	State       string   `json:"state"`
	CodeChallenge   string `json:"code_challenge,omitempty"`
	ChallengeMethod string `json:"code_challenge_method,omitempty"`
}

// SaveConsent stores consent data with a TTL.
func (s *Store) SaveConsent(ctx context.Context, challenge string, data *ConsentData, ttl time.Duration) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, consentPrefix+challenge, b, ttl).Err()
}

// ConsumeConsent retrieves and deletes consent data.
func (s *Store) ConsumeConsent(ctx context.Context, challenge string) (*ConsentData, error) {
	data, err := s.rdb.GetDel(ctx, consentPrefix+challenge).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("consent challenge not found or expired")
		}
		return nil, err
	}
	var cd ConsentData
	if err := json.Unmarshal(data, &cd); err != nil {
		return nil, err
	}
	return &cd, nil
}

// GetConsent retrieves consent data without deleting (for display).
func (s *Store) GetConsent(ctx context.Context, challenge string) (*ConsentData, error) {
	data, err := s.rdb.Get(ctx, consentPrefix+challenge).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("consent challenge not found or expired")
		}
		return nil, err
	}
	var cd ConsentData
	if err := json.Unmarshal(data, &cd); err != nil {
		return nil, err
	}
	return &cd, nil
}
