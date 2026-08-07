package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	internalcrypto "github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/oauthstepup"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

const jwtClockSkew = 2 * time.Minute

var (
	ErrInvalidToken               = errors.New("invalid token")
	ErrClientMismatch             = errors.New("token does not belong to client")
	ErrRefreshTokenReuse          = errors.New("refresh token reuse detected")
	ErrTokenValidationUnavailable = errors.New("token validation unavailable")
)

// TokenService handles JWT generation, validation, and opaque refresh rotation.
type TokenService struct {
	jwkManager         *JWKManager
	session            *session.Store
	users              *user.Service
	accessPolicy       AccessPolicyChecker
	issuer             string
	fallback           TokenLifetimes
	lifetimeSource     func() TokenLifetimes
	revocationTTL      time.Duration
	codeRetention      time.Duration
	publicKeyLoader    func(context.Context, string) (*rsa.PublicKey, error)
	authorizationUsage func(context.Context, string, string, time.Time) error
}

// TokenLifetimes is an immutable snapshot used for one issuance operation.
// Existing credentials keep the expiration encoded or stored when issued.
type TokenLifetimes struct {
	AccessToken       time.Duration
	RefreshToken      time.Duration
	AuthorizationCode time.Duration
}

// AccessPolicyChecker evaluates whether a user may use a client under its
// access policy. Implemented by the client store.
type AccessPolicyChecker interface {
	UserMayAccess(ctx context.Context, clientID string, userID string) (bool, error)
	ClientAuthorizationRevision(ctx context.Context, clientID string) (int64, error)
}

func NewTokenService(jwkManager *JWKManager, sessionStore *session.Store, issuer string, accessTTL, refreshTTL time.Duration) *TokenService {
	return &TokenService{
		jwkManager: jwkManager, session: sessionStore, issuer: strings.TrimRight(issuer, "/"),
		fallback:      TokenLifetimes{AccessToken: accessTTL, RefreshToken: refreshTTL},
		revocationTTL: maxDuration(accessTTL, refreshTTL),
	}
}

// SetLifetimeSource installs the runtime policy source and the hard maxima
// used for security-state and consumed-code retention. It must be called
// during server construction, before request handling starts.
func (ts *TokenService) SetLifetimeSource(source func() TokenLifetimes, maximumAccessTTL, maximumRefreshTTL, maximumCodeTTL time.Duration) {
	ts.lifetimeSource = source
	ts.revocationTTL = maxDuration(ts.revocationTTL, maximumAccessTTL, maximumRefreshTTL)
	ts.codeRetention = maxDuration(ts.fallback.AuthorizationCode, maximumCodeTTL)
}

func (ts *TokenService) SetAuthorizationCodeFallback(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	ts.fallback.AuthorizationCode = ttl
	ts.codeRetention = maxDuration(ts.codeRetention, ttl)
}

func (ts *TokenService) Lifetimes() TokenLifetimes {
	value := ts.fallback
	if ts.lifetimeSource != nil {
		candidate := ts.lifetimeSource()
		if candidate.AccessToken > 0 {
			value.AccessToken = candidate.AccessToken
		}
		if candidate.RefreshToken > 0 {
			value.RefreshToken = candidate.RefreshToken
		}
		if candidate.AuthorizationCode > 0 {
			value.AuthorizationCode = candidate.AuthorizationCode
		}
	}
	return value
}

func (ts *TokenService) RevocationTTL() time.Duration { return ts.revocationTTL }

func (ts *TokenService) AuthorizationCodeRetention() time.Duration {
	if ts.codeRetention > 0 {
		return ts.codeRetention
	}
	return ts.Lifetimes().AuthorizationCode
}

func maxDuration(values ...time.Duration) time.Duration {
	var maximum time.Duration
	for _, value := range values {
		if value > maximum {
			maximum = value
		}
	}
	return maximum
}

// SetUserService enables active-state and auth_version checks for user tokens.
func (ts *TokenService) SetUserService(users *user.Service) { ts.users = users }

// SetAccessPolicyChecker enables per-client access policy enforcement on
// refresh and access-token validation.
func (ts *TokenService) SetAccessPolicyChecker(checker AccessPolicyChecker) {
	ts.accessPolicy = checker
}

// SetAuthorizationUsageSink records actual user-grant use after token state is
// durably stored. Failure is observational and must not turn an already issued
// token into an ambiguous client error.
func (ts *TokenService) SetAuthorizationUsageSink(sink func(context.Context, string, string, time.Time) error) {
	ts.authorizationUsage = sink
}

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
	Scope                 string   `json:"scope,omitempty"`
	AllowedClaims         []string `json:"claim_names,omitempty"`
	ClaimNamesSet         bool     `json:"claim_names_set,omitempty"`
	TokenUse              string   `json:"token_use"`
	AuthVersion           int64    `json:"auth_version,omitempty"`
	Nonce                 string   `json:"nonce,omitempty"`
	AuthenticationContext string   `json:"acr,omitempty"`
	AuthenticationMethods []string `json:"amr,omitempty"`
	AuthenticationTime    int64    `json:"auth_time,omitempty"`
}

// IssuanceAuthentication is the verified browser authentication context that
// is copied into user-bound OAuth credentials. Empty means a legacy or
// machine-token issuance and intentionally emits no user assurance claims.
type IssuanceAuthentication struct {
	Context  string
	Methods  []string
	AuthTime int64
}

func (ts *TokenService) GenerateAuthorizationCodeTokenPair(ctx context.Context, clientID, userID string, scopes []string, authVersion, authorizationIssuedAt int64, issueRefresh bool) (*TokenPair, error) {
	return ts.GenerateAuthorizationCodeTokenPairWithClaims(ctx, clientID, userID, scopes, legacyClaimNamesForScopes(scopes), authVersion, authorizationIssuedAt, issueRefresh)
}

func (ts *TokenService) GenerateAuthorizationCodeTokenPairWithClaims(ctx context.Context, clientID, userID string, scopes, allowedClaims []string, authVersion, authorizationIssuedAt int64, issueRefresh bool) (*TokenPair, error) {
	return ts.GenerateAuthorizationCodeTokenPairAtRevisionWithClaims(ctx, clientID, userID, scopes, allowedClaims, authVersion, authorizationIssuedAt, 0, issueRefresh)
}

func (ts *TokenService) GenerateAuthorizationCodeTokenPairAtRevisionWithClaims(ctx context.Context, clientID, userID string, scopes, allowedClaims []string, authVersion, authorizationIssuedAt, expectedClientRevision int64, issueRefresh bool) (*TokenPair, error) {
	return ts.GenerateAuthorizationCodeTokenPairAtRevisionWithClaimsAndAuthentication(ctx, clientID, userID, scopes, allowedClaims, authVersion, authorizationIssuedAt, expectedClientRevision, IssuanceAuthentication{}, issueRefresh)
}

func (ts *TokenService) GenerateAuthorizationCodeTokenPairAtRevisionWithClaimsAndAuthentication(ctx context.Context, clientID, userID string, scopes, allowedClaims []string, authVersion, authorizationIssuedAt, expectedClientRevision int64, authentication IssuanceAuthentication, issueRefresh bool) (*TokenPair, error) {
	if authVersion <= 0 || authorizationIssuedAt <= 0 {
		return nil, fmt.Errorf("invalid user auth version")
	}
	clientRevision, err := ts.currentClientAuthorizationRevision(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if expectedClientRevision > 0 && clientRevision != normalizedClientRevision(expectedClientRevision) {
		return nil, ErrInvalidToken
	}
	if err := ts.validateAuthorization(ctx, &session.TokenData{
		ClientID: clientID, UserID: userID, AuthVersion: authVersion, AuthorizationIssuedAt: authorizationIssuedAt,
		ClientAuthorizationRevision: clientRevision,
	}); err != nil {
		return nil, err
	}
	return ts.generateTokenPair(ctx, clientID, userID, scopes, allowedClaims, authVersion, issueRefresh, "", authorizationIssuedAt, clientRevision, authentication)
}

func (ts *TokenService) GenerateClientTokenPair(ctx context.Context, clientID string, scopes []string) (*TokenPair, error) {
	return ts.generateTokenPair(ctx, clientID, clientID, scopes, nil, 0, false, "", 0, 0, IssuanceAuthentication{})
}

func (ts *TokenService) generateTokenPair(ctx context.Context, clientID, subject string, scopes, allowedClaims []string, authVersion int64, issueRefresh bool, familyKey string, authorizationIssuedAt, clientAuthorizationRevision int64, authentication IssuanceAuthentication) (*TokenPair, error) {
	lifetimes := ts.Lifetimes()
	access, jti, err := ts.signAccessToken(ctx, clientID, subject, scopes, allowedClaims, authVersion, lifetimes.AccessToken, authentication)
	if err != nil {
		return nil, err
	}
	refresh := ""
	if issueRefresh {
		refresh, err = internalcrypto.GenerateRandomString(32)
		if err != nil {
			return nil, fmt.Errorf("generating refresh token: %w", err)
		}
		refreshData := &session.TokenData{ClientID: clientID, UserID: subject, Scopes: scopes, AllowedClaims: allowedClaims, ClaimNamesSet: allowedClaims != nil, TokenUse: "refresh", AuthVersion: authVersion, AuthenticationContext: authentication.Context, AuthenticationMethods: slices.Clone(authentication.Methods), AuthenticationTime: authentication.AuthTime, AuthorizationIssuedAt: authorizationIssuedAt, ClientAuthorizationRevision: clientAuthorizationRevision}
		if err := ts.session.SaveRefreshToken(ctx, refresh, refreshData, lifetimes.RefreshToken); err != nil {
			return nil, fmt.Errorf("storing refresh token: %w", err)
		}
		familyKey = refreshData.FamilyKey
	}
	data := &session.TokenData{ClientID: clientID, UserID: subject, Scopes: scopes, AllowedClaims: allowedClaims, ClaimNamesSet: allowedClaims != nil, TokenUse: "access", AuthVersion: authVersion, AuthenticationContext: authentication.Context, AuthenticationMethods: slices.Clone(authentication.Methods), AuthenticationTime: authentication.AuthTime, FamilyKey: familyKey, AuthorizationIssuedAt: authorizationIssuedAt, ClientAuthorizationRevision: clientAuthorizationRevision}
	var saveErr error
	if familyKey == "" {
		saveErr = ts.session.SaveToken(ctx, jti, data, lifetimes.AccessToken)
	} else {
		saveErr = ts.session.SaveTokenForRefreshFamily(ctx, jti, data, familyKey, lifetimes.AccessToken)
	}
	if saveErr != nil {
		if refresh != "" {
			_ = ts.session.RevokeRefreshTokenForClient(ctx, refresh, clientID, ts.revocationTTL)
		}
		return nil, fmt.Errorf("storing access token metadata: %w", saveErr)
	}
	if authVersion > 0 && ts.authorizationUsage != nil {
		if err := ts.authorizationUsage(ctx, subject, clientID, time.Now().UTC()); err != nil {
			slog.WarnContext(ctx, "OAuth authorization usage update failed", "client_id", clientID, "error", err)
		}
	}
	result := &TokenPair{AccessToken: access, TokenType: "Bearer", ExpiresIn: int(lifetimes.AccessToken.Seconds()), Scope: joinScopes(scopes)}
	if !issueRefresh {
		return result, nil
	}
	result.RefreshToken = refresh
	return result, nil
}

func (ts *TokenService) signAccessToken(ctx context.Context, clientID, subject string, scopes, allowedClaims []string, authVersion int64, accessTTL time.Duration, authentication IssuanceAuthentication) (string, string, error) {
	privateKey, kid, err := ts.jwkManager.GetPrivateKey(ctx)
	if err != nil {
		return "", "", fmt.Errorf("getting signing key: %w", err)
	}
	now := time.Now().UTC()
	jti := uuid.NewString()
	claims := &Claims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: ts.issuer, Subject: subject, Audience: jwt.ClaimStrings{clientID},
		ExpiresAt: jwt.NewNumericDate(now.Add(accessTTL)), IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ID: jti,
	}, Scope: joinScopes(scopes), AllowedClaims: allowedClaims, ClaimNamesSet: allowedClaims != nil, TokenUse: "access", AuthVersion: authVersion}
	applyAuthenticationClaims(claims, authentication)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("signing access token: %w", err)
	}
	return signed, jti, nil
}

func (ts *TokenService) GenerateIDToken(ctx context.Context, clientID, userID string, scopes []string, nonce string, userInfo map[string]interface{}) (string, error) {
	return ts.GenerateIDTokenWithClaims(ctx, clientID, userID, scopes, legacyClaimNamesForScopes(scopes), nonce, userInfo)
}

func (ts *TokenService) GenerateIDTokenWithClaims(ctx context.Context, clientID, userID string, scopes, allowedClaims []string, nonce string, userInfo map[string]interface{}) (string, error) {
	return ts.GenerateIDTokenWithClaimsAndAuthentication(ctx, clientID, userID, scopes, allowedClaims, nonce, userInfo, IssuanceAuthentication{})
}

func (ts *TokenService) GenerateIDTokenWithClaimsAndAuthentication(ctx context.Context, clientID, userID string, scopes, allowedClaims []string, nonce string, userInfo map[string]interface{}, authentication IssuanceAuthentication) (string, error) {
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
	accessTTL := ts.Lifetimes().AccessToken
	claims := jwt.MapClaims{
		"iss": ts.issuer, "sub": userID, "aud": clientID, "exp": now.Add(accessTTL).Unix(),
		"iat": now.Unix(), "nbf": now.Unix(), "jti": uuid.NewString(), "token_use": "id", "auth_version": authVersion,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	applyAuthenticationMapClaims(claims, authentication)
	for key, value := range claimLimitedUserInfo(allowedClaims, userInfo) {
		claims[key] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	return token.SignedString(privateKey)
}

func (ts *TokenService) ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims, err := ts.parseSignedToken(ctx, tokenString)
	if err != nil {
		if errors.Is(err, ErrTokenValidationUnavailable) {
			return nil, err
		}
		return nil, ErrInvalidToken
	}
	if claims.TokenUse != "access" || claims.ID == "" || len(claims.Audience) != 1 {
		return nil, ErrInvalidToken
	}
	metadata, err := ts.session.GetToken(ctx, claims.ID)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("%w: loading access-token metadata: %v", ErrTokenValidationUnavailable, err)
	}
	if metadata.TokenUse != "access" || metadata.ClientID != claims.Audience[0] || metadata.UserID != claims.Subject ||
		metadata.AuthVersion != claims.AuthVersion || joinScopes(metadata.Scopes) != claims.Scope ||
		metadata.ClaimNamesSet != claims.ClaimNamesSet || !slices.Equal(metadata.AllowedClaims, claims.AllowedClaims) ||
		metadata.AuthenticationContext != claims.AuthenticationContext || metadata.AuthenticationTime != claims.AuthenticationTime ||
		!slices.Equal(metadata.AuthenticationMethods, claims.AuthenticationMethods) {
		return nil, ErrInvalidToken
	}
	if err := ts.validateUser(ctx, claims.Subject, claims.AuthVersion); err != nil {
		return nil, err
	}
	if err := ts.validateAuthorization(ctx, metadata); err != nil {
		return nil, err
	}
	if err := ts.validateAccessPolicy(ctx, metadata); err != nil {
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
	publicKey, err := ts.loadPublicKey(ctx, kid)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("%w: loading verification key: %v", ErrTokenValidationUnavailable, err)
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
	return ts.RefreshTokenWithClaimPolicy(ctx, refreshToken, clientID, allowedScopes, nil)
}

func (ts *TokenService) RefreshTokenWithClaimPolicy(ctx context.Context, refreshToken, clientID string, allowedScopes []string, scopeClaims map[string][]string) (*TokenPair, error) {
	lifetimes := ts.Lifetimes()
	data, used, err := ts.session.GetRefreshTokenState(ctx, refreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if data.ClientID != clientID || data.TokenUse != "refresh" {
		return nil, ErrClientMismatch
	}
	if !scopesAreSubset(data.Scopes, allowedScopes) {
		_ = ts.session.RevokeRefreshTokenForClient(ctx, refreshToken, clientID, ts.revocationTTL)
		return nil, ErrInvalidToken
	}
	effectiveClaims := effectiveClaimNames(data.Scopes, data.AllowedClaims, data.ClaimNamesSet)
	if scopeClaims != nil && !scopesAreSubset(effectiveClaims, claimsForGrantedScopes(data.Scopes, scopeClaims)) {
		_ = ts.session.RevokeRefreshTokenForClient(ctx, refreshToken, clientID, ts.revocationTTL)
		return nil, ErrInvalidToken
	}
	if used {
		if err := ts.session.RevokeRefreshTokenForClient(ctx, refreshToken, clientID, ts.revocationTTL); err != nil && !errors.Is(err, session.ErrNotFound) {
			return nil, fmt.Errorf("revoking reused refresh token family: %w", err)
		}
		return nil, ErrRefreshTokenReuse
	}
	if err := ts.validateUser(ctx, data.UserID, data.AuthVersion); err != nil {
		_ = ts.session.RevokeRefreshTokenForClient(ctx, refreshToken, clientID, ts.revocationTTL)
		return nil, err
	}
	if err := ts.validateAuthorization(ctx, data); err != nil {
		_ = ts.session.RevokeRefreshTokenForClient(ctx, refreshToken, clientID, ts.revocationTTL)
		return nil, err
	}
	if err := ts.validateAccessPolicy(ctx, data); err != nil {
		_ = ts.session.RevokeRefreshTokenForClient(ctx, refreshToken, clientID, ts.revocationTTL)
		return nil, err
	}
	newRefresh, err := internalcrypto.GenerateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("generating refresh token: %w", err)
	}
	access, jti, err := ts.signAccessToken(ctx, data.ClientID, data.UserID, data.Scopes, effectiveClaims, data.AuthVersion, lifetimes.AccessToken, IssuanceAuthentication{Context: data.AuthenticationContext, Methods: data.AuthenticationMethods, AuthTime: data.AuthenticationTime})
	if err != nil {
		return nil, err
	}
	accessData := &session.TokenData{
		ClientID: data.ClientID, UserID: data.UserID, Scopes: data.Scopes, AllowedClaims: effectiveClaims, ClaimNamesSet: true, TokenUse: "access",
		AuthVersion: data.AuthVersion, AuthenticationContext: data.AuthenticationContext, AuthenticationMethods: slices.Clone(data.AuthenticationMethods), AuthenticationTime: data.AuthenticationTime, FamilyKey: data.FamilyKey, AuthorizationIssuedAt: data.AuthorizationIssuedAt,
		ClientAuthorizationRevision: data.ClientAuthorizationRevision,
	}
	_, err = ts.session.RotateRefreshTokenAndStoreAccess(
		ctx, refreshToken, newRefresh, jti, data, accessData, lifetimes.RefreshToken, lifetimes.AccessToken,
	)
	if err != nil {
		if errors.Is(err, session.ErrRefreshTokenReuse) {
			return nil, ErrRefreshTokenReuse
		}
		return nil, ErrInvalidToken
	}
	return &TokenPair{
		AccessToken: access, TokenType: "Bearer", ExpiresIn: int(lifetimes.AccessToken.Seconds()),
		RefreshToken: newRefresh, Scope: joinScopes(data.Scopes),
	}, nil
}

// RevokeTokenForClient revokes only tokens owned by the authenticated client.
func (ts *TokenService) RevokeTokenForClient(ctx context.Context, token, clientID string) error {
	if err := ts.session.RevokeRefreshTokenForClient(ctx, token, clientID, ts.revocationTTL); err == nil {
		return nil
	} else if errors.Is(err, session.ErrTokenBindingMismatch) {
		return ErrClientMismatch
	} else if !errors.Is(err, session.ErrNotFound) {
		return err
	}
	claims, err := ts.ValidateAccessToken(ctx, token)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			return nil
		}
		return err
	} // RFC 7009 does not reveal invalid tokens.
	if len(claims.Audience) != 1 || claims.Audience[0] != clientID {
		return ErrClientMismatch
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
	if err := ts.validateAuthorization(ctx, data); err != nil {
		return map[string]interface{}{"active": false}, nil
	}
	if err := ts.validateAccessPolicy(ctx, data); err != nil {
		return map[string]interface{}{"active": false}, nil
	}
	result := map[string]interface{}{
		"active": true, "sub": data.UserID, "client_id": data.ClientID,
		"scope": joinScopes(data.Scopes), "token_type": "refresh_token",
	}
	applyAuthenticationMapClaims(result, IssuanceAuthentication{
		Context: data.AuthenticationContext, Methods: data.AuthenticationMethods, AuthTime: data.AuthenticationTime,
	})
	return result, nil
}

func (ts *TokenService) IntrospectToken(ctx context.Context, tokenString string) (map[string]interface{}, error) {
	claims, err := ts.ValidateAccessToken(ctx, tokenString)
	if err != nil {
		return map[string]interface{}{"active": false}, nil
	}
	return introspectionClaims(claims), nil
}

func introspectionClaims(claims *Claims) map[string]interface{} {
	result := map[string]interface{}{
		"active": true, "sub": claims.Subject, "client_id": claims.Audience[0], "aud": claims.Audience,
		"scope": claims.Scope, "exp": claims.ExpiresAt.Unix(), "iat": claims.IssuedAt.Unix(),
		"jti": claims.ID, "iss": claims.Issuer, "token_type": "Bearer",
	}
	if claims.AuthenticationContext != "" {
		result["acr"] = claims.AuthenticationContext
	}
	if claims.AuthenticationTime > 0 {
		result["auth_time"] = claims.AuthenticationTime
	}
	if len(claims.AuthenticationMethods) > 0 {
		result["amr"] = slices.Clone(claims.AuthenticationMethods)
	}
	return result
}

func applyAuthenticationClaims(claims *Claims, authentication IssuanceAuthentication) {
	if claims == nil || strings.TrimSpace(authentication.Context) == "" {
		return
	}
	claims.AuthenticationContext = oauthstepup.NormalizeContext(authentication.Context).String()
	claims.AuthenticationTime = authentication.AuthTime
	if claims.AuthenticationTime <= 0 {
		claims.AuthenticationTime = time.Now().UTC().Unix()
	}
	claims.AuthenticationMethods = slices.Clone(authentication.Methods)
}

func applyAuthenticationMapClaims(claims map[string]interface{}, authentication IssuanceAuthentication) {
	if claims == nil || strings.TrimSpace(authentication.Context) == "" {
		return
	}
	claims["acr"] = oauthstepup.NormalizeContext(authentication.Context).String()
	authTime := authentication.AuthTime
	if authTime <= 0 {
		authTime = time.Now().UTC().Unix()
	}
	claims["auth_time"] = authTime
	if len(authentication.Methods) > 0 {
		claims["amr"] = slices.Clone(authentication.Methods)
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
	if err != nil {
		if user.IsNotFound(err) {
			return ErrInvalidToken
		}
		return fmt.Errorf("%w: loading token subject: %v", ErrTokenValidationUnavailable, err)
	}
	if u.Status != models.UserStatusActive || u.AuthVersion != authVersion {
		return ErrInvalidToken
	}
	return nil
}

// validateAccessPolicy re-evaluates the client's access policy for user-bound
// tokens so allowlist removals take effect on the next token use. Machine
// tokens (AuthVersion 0) are not user-bound and are never restricted.
func (ts *TokenService) validateAccessPolicy(ctx context.Context, data *session.TokenData) error {
	if data.AuthVersion == 0 || ts.accessPolicy == nil {
		return nil
	}
	allowed, err := ts.accessPolicy.UserMayAccess(ctx, data.ClientID, data.UserID)
	if err != nil {
		return fmt.Errorf("%w: evaluating access policy: %v", ErrTokenValidationUnavailable, err)
	}
	if !allowed {
		return ErrInvalidToken
	}
	return nil
}

func (ts *TokenService) validateAuthorization(ctx context.Context, data *session.TokenData) error {
	if data.AuthVersion == 0 {
		return nil
	}
	if data.AuthorizationIssuedAt <= 0 || data.UserID == "" || data.ClientID == "" {
		return ErrInvalidToken
	}
	revoked, err := ts.session.IsUserClientAuthorizationRevoked(ctx, data.UserID, data.ClientID, data.AuthorizationIssuedAt)
	if err != nil {
		return fmt.Errorf("%w: loading authorization state: %v", ErrTokenValidationUnavailable, err)
	}
	if revoked {
		return ErrInvalidToken
	}
	currentRevision, err := ts.currentClientAuthorizationRevision(ctx, data.ClientID)
	if err != nil {
		return err
	}
	issuedRevision := data.ClientAuthorizationRevision
	if issuedRevision == 0 {
		issuedRevision = 1
	}
	if issuedRevision != currentRevision {
		return ErrInvalidToken
	}
	return nil
}

func (ts *TokenService) currentClientAuthorizationRevision(ctx context.Context, clientID string) (int64, error) {
	if ts.accessPolicy == nil {
		return 0, ErrInvalidToken
	}
	revision, err := ts.accessPolicy.ClientAuthorizationRevision(ctx, clientID)
	if err != nil {
		return 0, fmt.Errorf("%w: loading client authorization revision: %v", ErrTokenValidationUnavailable, err)
	}
	if revision < 1 {
		return 0, ErrInvalidToken
	}
	return revision, nil
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
	return nil, ErrInvalidToken
}

func (ts *TokenService) loadPublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if ts.publicKeyLoader != nil {
		return ts.publicKeyLoader(ctx, kid)
	}
	return ts.getPublicKey(ctx, kid)
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
	return claimLimitedUserInfo(legacyClaimNamesForScopes(scopes), userInfo)
}

func legacyClaimNamesForScopes(scopes []string) []string {
	result := make([]string, 0, 6)
	if containsScope(scopes, "openid") {
		result = append(result, "sub")
	}
	if containsScope(scopes, "profile") {
		result = append(result, "preferred_username", "name", "picture")
	}
	if containsScope(scopes, "email") {
		// Tokens issued before schema 12 exposed only email for this scope.
		// Keep legacy Redis/JWT records at their original disclosure level.
		result = append(result, "email")
	}
	return result
}

func effectiveClaimNames(scopes, allowedClaims []string, claimNamesSet bool) []string {
	if claimNamesSet {
		return append([]string{}, allowedClaims...)
	}
	if allowedClaims != nil {
		return allowedClaims
	}
	return legacyClaimNamesForScopes(scopes)
}

func claimLimitedUserInfo(allowedClaims []string, userInfo map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, key := range allowedClaims {
		if key == "sub" {
			continue
		}
		if value, ok := userInfo[key]; ok {
			result[key] = value
		}
	}
	return result
}
