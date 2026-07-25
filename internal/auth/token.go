package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	internalcrypto "github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

const jwtClockSkew = 2 * time.Minute

var (
	ErrInvalidToken   = errors.New("invalid token")
	ErrClientMismatch = errors.New("token does not belong to client")
)

// TokenService handles JWT generation, validation, and opaque refresh rotation.
type TokenService struct {
	jwkManager *JWKManager
	session    *session.Store
	users      *user.Service
	issuer     string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewTokenService(jwkManager *JWKManager, sessionStore *session.Store, issuer string, accessTTL, refreshTTL time.Duration) *TokenService {
	return &TokenService{jwkManager: jwkManager, session: sessionStore, issuer: strings.TrimRight(issuer, "/"), accessTTL: accessTTL, refreshTTL: refreshTTL}
}

// SetUserService enables active-state and auth_version checks for user tokens.
func (ts *TokenService) SetUserService(users *user.Service) { ts.users = users }

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

type Claims struct {
	jwt.RegisteredClaims
	Scope       string `json:"scope,omitempty"`
	TokenUse    string `json:"token_use"`
	AuthVersion int64  `json:"auth_version,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
}

// GenerateTokenPair is retained for internal callers and never implicitly issues refresh tokens.
func (ts *TokenService) GenerateTokenPair(ctx context.Context, clientID, subject string, scopes []string) (*TokenPair, error) {
	authVersion := int64(0)
	if id, err := uuid.Parse(subject); err == nil && ts.users != nil {
		u, err := ts.users.GetByID(ctx, id)
		if err != nil || u.Status != models.UserStatusActive {
			return nil, ErrInvalidToken
		}
		authVersion = u.AuthVersion
	}
	return ts.generateTokenPair(ctx, clientID, subject, scopes, authVersion, false, "")
}

func (ts *TokenService) GenerateAuthorizationCodeTokenPair(ctx context.Context, clientID, userID string, scopes []string, authVersion int64, issueRefresh bool) (*TokenPair, error) {
	if authVersion <= 0 {
		return nil, fmt.Errorf("invalid user auth version")
	}
	return ts.generateTokenPair(ctx, clientID, userID, scopes, authVersion, issueRefresh, "")
}

func (ts *TokenService) GenerateClientTokenPair(ctx context.Context, clientID string, scopes []string) (*TokenPair, error) {
	return ts.generateTokenPair(ctx, clientID, clientID, scopes, 0, false, "")
}

func (ts *TokenService) generateTokenPair(ctx context.Context, clientID, subject string, scopes []string, authVersion int64, issueRefresh bool, familyKey string) (*TokenPair, error) {
	access, jti, err := ts.signAccessToken(ctx, clientID, subject, scopes, authVersion)
	if err != nil {
		return nil, err
	}
	refresh := ""
	if issueRefresh {
		refresh, err = internalcrypto.GenerateRandomString(32)
		if err != nil {
			return nil, fmt.Errorf("generating refresh token: %w", err)
		}
		refreshData := &session.TokenData{ClientID: clientID, UserID: subject, Scopes: scopes, TokenUse: "refresh", AuthVersion: authVersion}
		if err := ts.session.SaveRefreshToken(ctx, refresh, refreshData, ts.refreshTTL); err != nil {
			return nil, fmt.Errorf("storing refresh token: %w", err)
		}
		familyKey = refreshData.FamilyKey
	}
	data := &session.TokenData{ClientID: clientID, UserID: subject, Scopes: scopes, TokenUse: "access", AuthVersion: authVersion, FamilyKey: familyKey}
	var saveErr error
	if familyKey == "" {
		saveErr = ts.session.SaveToken(ctx, jti, data, ts.accessTTL)
	} else {
		saveErr = ts.session.SaveTokenForRefreshFamily(ctx, jti, data, familyKey, ts.accessTTL)
	}
	if saveErr != nil {
		if refresh != "" {
			_ = ts.session.RevokeRefreshTokenForClient(ctx, refresh, clientID, ts.refreshTTL)
		}
		return nil, fmt.Errorf("storing access token metadata: %w", saveErr)
	}
	result := &TokenPair{AccessToken: access, TokenType: "Bearer", ExpiresIn: int(ts.accessTTL.Seconds()), Scope: joinScopes(scopes)}
	if !issueRefresh {
		return result, nil
	}
	result.RefreshToken = refresh
	return result, nil
}

func (ts *TokenService) signAccessToken(ctx context.Context, clientID, subject string, scopes []string, authVersion int64) (string, string, error) {
	privateKey, kid, err := ts.jwkManager.GetPrivateKey(ctx)
	if err != nil {
		return "", "", fmt.Errorf("getting signing key: %w", err)
	}
	now := time.Now().UTC()
	jti := uuid.NewString()
	claims := &Claims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: ts.issuer, Subject: subject, Audience: jwt.ClaimStrings{clientID},
		ExpiresAt: jwt.NewNumericDate(now.Add(ts.accessTTL)), IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ID: jti,
	}, Scope: joinScopes(scopes), TokenUse: "access", AuthVersion: authVersion}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("signing access token: %w", err)
	}
	return signed, jti, nil
}

func (ts *TokenService) GenerateIDToken(ctx context.Context, clientID, userID string, scopes []string, nonce string, userInfo map[string]interface{}) (string, error) {
	authVersion := int64(0)
	if id, err := uuid.Parse(userID); err == nil && ts.users != nil {
		u, err := ts.users.GetByID(ctx, id)
		if err != nil || u.Status != models.UserStatusActive {
			return "", ErrInvalidToken
		}
		authVersion = u.AuthVersion
	}
	privateKey, kid, err := ts.jwkManager.GetPrivateKey(ctx)
	if err != nil {
		return "", fmt.Errorf("getting signing key: %w", err)
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": ts.issuer, "sub": userID, "aud": clientID, "exp": now.Add(ts.accessTTL).Unix(),
		"iat": now.Unix(), "nbf": now.Unix(), "jti": uuid.NewString(), "token_use": "id", "auth_version": authVersion,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	for key, value := range scopedIDTokenUserInfo(scopes, userInfo) {
		claims[key] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	return token.SignedString(privateKey)
}

func (ts *TokenService) ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims, err := ts.parseSignedToken(ctx, tokenString)
	if err != nil || claims.TokenUse != "access" || claims.ID == "" || len(claims.Audience) != 1 {
		return nil, ErrInvalidToken
	}
	metadata, err := ts.session.GetToken(ctx, claims.ID)
	if err != nil || metadata.TokenUse != "access" || metadata.ClientID != claims.Audience[0] || metadata.UserID != claims.Subject ||
		metadata.AuthVersion != claims.AuthVersion || joinScopes(metadata.Scopes) != claims.Scope {
		return nil, ErrInvalidToken
	}
	if err := ts.validateUser(ctx, claims.Subject, claims.AuthVersion); err != nil {
		return nil, err
	}
	return claims, nil
}

// ValidateIDToken validates a locally issued ID token without requiring access-token metadata.
func (ts *TokenService) ValidateIDToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims, err := ts.parseSignedToken(ctx, tokenString)
	if err != nil || claims.TokenUse != "id" || claims.Subject == "" || len(claims.Audience) != 1 {
		return nil, ErrInvalidToken
	}
	if err := ts.validateUser(ctx, claims.Subject, claims.AuthVersion); err != nil {
		return nil, err
	}
	return claims, nil
}

func (ts *TokenService) parseSignedToken(ctx context.Context, tokenString string) (*Claims, error) {
	unverified := &Claims{}
	token, _, err := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"})).ParseUnverified(tokenString, unverified)
	if err != nil || token.Method.Alg() != "RS256" {
		return nil, ErrInvalidToken
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, ErrInvalidToken
	}
	publicKey, err := ts.getPublicKey(ctx, kid)
	if err != nil {
		return nil, ErrInvalidToken
	}
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 || token.Header["alg"] != "RS256" {
			return nil, ErrInvalidToken
		}
		return publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(ts.issuer), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(jwtClockSkew))
	if err != nil || !parsed.Valid || claims.Issuer != ts.issuer || claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.NotBefore == nil {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

func (ts *TokenService) RefreshToken(ctx context.Context, refreshToken, clientID string, allowedScopes []string) (*TokenPair, error) {
	data, _, err := ts.session.GetRefreshTokenState(ctx, refreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if data.ClientID != clientID || data.TokenUse != "refresh" {
		return nil, ErrClientMismatch
	}
	if !scopesAreSubset(data.Scopes, allowedScopes) {
		_ = ts.session.RevokeRefreshTokenForClient(ctx, refreshToken, clientID, ts.refreshTTL)
		return nil, ErrInvalidToken
	}
	if err := ts.validateUser(ctx, data.UserID, data.AuthVersion); err != nil {
		_ = ts.session.RevokeRefreshTokenForClient(ctx, refreshToken, clientID, ts.refreshTTL)
		return nil, err
	}
	newRefresh, err := internalcrypto.GenerateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("generating refresh token: %w", err)
	}
	data, err = ts.session.RotateRefreshToken(ctx, refreshToken, newRefresh, data, ts.refreshTTL)
	if err != nil {
		return nil, ErrInvalidToken
	}
	result, err := ts.generateTokenPair(ctx, data.ClientID, data.UserID, data.Scopes, data.AuthVersion, false, data.FamilyKey)
	if err != nil {
		_ = ts.session.RevokeRefreshTokenForClient(ctx, newRefresh, clientID, ts.refreshTTL)
		return nil, err
	}
	result.RefreshToken = newRefresh
	return result, nil
}

// RevokeTokenForClient revokes only tokens owned by the authenticated client.
func (ts *TokenService) RevokeTokenForClient(ctx context.Context, token, clientID string) error {
	if err := ts.session.RevokeRefreshTokenForClient(ctx, token, clientID, ts.refreshTTL); err == nil {
		return nil
	} else if errors.Is(err, session.ErrTokenBindingMismatch) {
		return ErrClientMismatch
	} else if !errors.Is(err, session.ErrNotFound) {
		return err
	}
	claims, err := ts.ValidateAccessToken(ctx, token)
	if err != nil {
		return nil
	} // RFC 7009 does not reveal invalid tokens.
	if len(claims.Audience) != 1 || claims.Audience[0] != clientID {
		return ErrClientMismatch
	}
	return ts.session.RevokeToken(ctx, claims.ID)
}

// RevokeToken is retained for internal trusted callers. HTTP handlers use RevokeTokenForClient.
func (ts *TokenService) RevokeToken(ctx context.Context, token string) error {
	if data, _, err := ts.session.GetRefreshTokenState(ctx, token); err == nil {
		return ts.session.RevokeRefreshTokenForClient(ctx, token, data.ClientID, ts.refreshTTL)
	}
	claims, err := ts.ValidateAccessToken(ctx, token)
	if err != nil {
		return err
	}
	return ts.session.RevokeToken(ctx, claims.ID)
}

func (ts *TokenService) IntrospectTokenForClient(ctx context.Context, tokenString, clientID string, allowedScopes []string) (map[string]interface{}, error) {
	claims, err := ts.ValidateAccessToken(ctx, tokenString)
	if err == nil && len(claims.Audience) == 1 && claims.Audience[0] == clientID {
		return introspectionClaims(claims), nil
	}
	data, err := ts.session.GetRefreshToken(ctx, tokenString)
	if err != nil || data.ClientID != clientID || data.TokenUse != "refresh" || !scopesAreSubset(data.Scopes, allowedScopes) {
		return map[string]interface{}{"active": false}, nil
	}
	if err := ts.validateUser(ctx, data.UserID, data.AuthVersion); err != nil {
		return map[string]interface{}{"active": false}, nil
	}
	return map[string]interface{}{
		"active": true, "sub": data.UserID, "client_id": data.ClientID,
		"scope": joinScopes(data.Scopes), "token_type": "refresh_token",
	}, nil
}

func (ts *TokenService) IntrospectToken(ctx context.Context, tokenString string) (map[string]interface{}, error) {
	claims, err := ts.ValidateAccessToken(ctx, tokenString)
	if err != nil {
		return map[string]interface{}{"active": false}, nil
	}
	return introspectionClaims(claims), nil
}

func introspectionClaims(claims *Claims) map[string]interface{} {
	return map[string]interface{}{
		"active": true, "sub": claims.Subject, "client_id": claims.Audience[0], "aud": claims.Audience,
		"scope": claims.Scope, "exp": claims.ExpiresAt.Unix(), "iat": claims.IssuedAt.Unix(),
		"jti": claims.ID, "iss": claims.Issuer, "token_type": "Bearer",
	}
}

func (ts *TokenService) validateUser(ctx context.Context, subject string, authVersion int64) error {
	if authVersion == 0 {
		return nil
	}
	if ts.users == nil {
		return ErrInvalidToken
	}
	id, err := uuid.Parse(subject)
	if err != nil {
		return ErrInvalidToken
	}
	u, err := ts.users.GetByID(ctx, id)
	if err != nil || u.Status != models.UserStatusActive || u.AuthVersion != authVersion {
		return ErrInvalidToken
	}
	return nil
}

func (ts *TokenService) getPublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	keys, err := ts.jwkManager.ListActivePublicKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if key.Kid != kid || key.Algorithm != "RS256" || key.KeyType != "RSA" || key.Usage != "sig" {
			continue
		}
		block, _ := pem.Decode([]byte(key.PublicKey))
		if block == nil {
			return nil, errors.New("invalid public key PEM")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		publicKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("not an RSA public key")
		}
		return publicKey, nil
	}
	return nil, fmt.Errorf("verification key %q not found", kid)
}

func joinScopes(scopes []string) string { return strings.Join(scopes, " ") }
func containsScope(scopes []string, target string) bool {
	for _, scope := range scopes {
		if scope == target {
			return true
		}
	}
	return false
}

func scopesAreSubset(requested, allowed []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, scope := range allowed {
		allowedSet[scope] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := allowedSet[scope]; !ok {
			return false
		}
	}
	return true
}

func scopedIDTokenUserInfo(scopes []string, userInfo map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	if containsScope(scopes, "profile") {
		for _, key := range []string{"name", "preferred_username", "picture"} {
			if value, ok := userInfo[key]; ok {
				result[key] = value
			}
		}
	}
	if containsScope(scopes, "email") {
		if value, ok := userInfo["email"]; ok {
			result["email"] = value
		}
	}
	return result
}
