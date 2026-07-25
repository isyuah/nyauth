package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/session"
)

// TokenService handles JWT generation and validation.
type TokenService struct {
	jwkManager *JWKManager
	session    *session.Store
	issuer     string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewTokenService creates a new token service.
func NewTokenService(jwkManager *JWKManager, sessionStore *session.Store, issuer string, accessTTL, refreshTTL time.Duration) *TokenService {
	return &TokenService{
		jwkManager: jwkManager,
		session:    sessionStore,
		issuer:     issuer,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

// TokenPair holds an access token and an optional refresh token.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// Claims extends jwt.RegisteredClaims with custom fields.
type Claims struct {
	jwt.RegisteredClaims
	Scope   string `json:"scope,omitempty"`
	AuthCtx string `json:"auth_ctx,omitempty"` // authentication context class
}

// GenerateTokenPair creates an access token and refresh token.
func (ts *TokenService) GenerateTokenPair(ctx context.Context, clientID, userID string, scopes []string) (*TokenPair, error) {
	privateKey, kid, err := ts.jwkManager.GetPrivateKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting signing key: %w", err)
	}

	now := time.Now()
	accessTokenID := uuid.New().String()

	// Build access token
	accessClaims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(ts.accessTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        accessTokenID,
		},
		Scope: joinScopes(scopes),
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = kid
	accessSigned, err := accessToken.SignedString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("signing access token: %w", err)
	}

	// Store token metadata in Redis
	tokenData := &session.TokenData{
		ClientID: clientID,
		UserID:   userID,
		Scopes:   scopes,
		TokenUse: "access",
	}
	if err := ts.session.SaveToken(ctx, accessTokenID, tokenData, ts.accessTTL); err != nil {
		return nil, fmt.Errorf("storing token: %w", err)
	}

	result := &TokenPair{
		AccessToken: accessSigned,
		TokenType:   "Bearer",
		ExpiresIn:   int(ts.accessTTL.Seconds()),
		Scope:       joinScopes(scopes),
	}

	// Generate refresh token if scope includes offline_access or if requested
	if containsScope(scopes, "offline_access") || len(scopes) > 0 {
		refreshTokenID := uuid.New().String()
		refreshData := &session.TokenData{
			ClientID: clientID,
			UserID:   userID,
			Scopes:   scopes,
			TokenUse: "refresh",
		}
		if err := ts.session.SaveRefreshToken(ctx, refreshTokenID, refreshData, ts.refreshTTL); err != nil {
			return nil, fmt.Errorf("storing refresh token: %w", err)
		}
		result.RefreshToken = refreshTokenID
	}

	return result, nil
}

// GenerateIDToken creates an OpenID Connect ID token.
func (ts *TokenService) GenerateIDToken(ctx context.Context, clientID, userID string, scopes []string, nonce string, userInfo map[string]interface{}) (string, error) {
	privateKey, kid, err := ts.jwkManager.GetPrivateKey(ctx)
	if err != nil {
		return "", fmt.Errorf("getting signing key: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": ts.issuer,
		"sub": userID,
		"aud": clientID,
		"exp": now.Add(ts.accessTTL).Unix(),
		"iat": now.Unix(),
		"jti": uuid.New().String(),
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	// Add claims based on scopes
	for k, v := range userInfo {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	return token.SignedString(privateKey)
}

// ValidateAccessToken validates an access token and returns its claims.
func (ts *TokenService) ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	// Parse without validation first to get the kid
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	// Get the kid from header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("token missing kid header")
	}

	// Get the public key for this kid
	publicKey, err := ts.getPublicKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}

	// Parse and validate
	claims := &Claims{}
	parsedToken, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validating token: %w", err)
	}

	if !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Check if token is revoked
	if _, err := ts.session.GetToken(ctx, claims.ID); err != nil {
		return nil, fmt.Errorf("token revoked or not found")
	}

	return claims, nil
}

// RefreshToken issues a new token pair using a refresh token.
func (ts *TokenService) RefreshToken(ctx context.Context, refreshTokenID, clientID string) (*TokenPair, error) {
	data, err := ts.session.GetRefreshToken(ctx, refreshTokenID)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	if data.ClientID != clientID {
		return nil, fmt.Errorf("client mismatch")
	}

	// Revoke old refresh token (rotate)
	_ = ts.session.RevokeRefreshToken(ctx, refreshTokenID)

	// Generate new pair
	return ts.GenerateTokenPair(ctx, data.ClientID, data.UserID, data.Scopes)
}

// RevokeToken revokes an access or refresh token.
func (ts *TokenService) RevokeToken(ctx context.Context, token string) error {
	// Try as refresh token first
	if err := ts.session.RevokeRefreshToken(ctx, token); err == nil {
		return nil
	}
	// Try as access token ID
	return ts.session.RevokeToken(ctx, token)
}

// IntrospectToken returns token metadata (RFC 7662).
func (ts *TokenService) IntrospectToken(ctx context.Context, tokenString string) (map[string]interface{}, error) {
	claims, err := ts.ValidateAccessToken(ctx, tokenString)
	if err != nil {
		return map[string]interface{}{"active": false}, nil
	}

	return map[string]interface{}{
		"active":    true,
		"sub":       claims.Subject,
		"client_id": claims.Audience,
		"scope":     claims.Scope,
		"exp":       claims.ExpiresAt.Unix(),
		"iat":       claims.IssuedAt.Unix(),
		"jti":       claims.ID,
		"iss":       claims.Issuer,
		"token_type": "Bearer",
	}, nil
}

func (ts *TokenService) getPublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	keys, err := ts.jwkManager.ListActivePublicKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if k.Kid == kid {
			block, _ := pem.Decode([]byte(k.PublicKey))
			if block == nil {
				return nil, fmt.Errorf("failed to decode PEM")
			}
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rsaPub, ok := pub.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("not an RSA public key")
			}
			return rsaPub, nil
		}
	}
	return nil, fmt.Errorf("key %s not found", kid)
}

func joinScopes(scopes []string) string {
	result := ""
	for i, s := range scopes {
		if i > 0 {
			result += " "
		}
		result += s
	}
	return result
}

func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}
