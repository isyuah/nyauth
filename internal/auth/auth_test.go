package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/oauthstepup"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

type tokenMetadataFailureHook struct{}

func (tokenMetadataFailureHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (tokenMetadataFailureHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		args := cmd.Args()
		if cmd.Name() == "get" && len(args) > 1 {
			if key, ok := args[1].(string); ok && strings.HasPrefix(key, "nyauth:token:") {
				return errors.New("token metadata store unavailable")
			}
		}
		return next(ctx, cmd)
	}
}
func (tokenMetadataFailureHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestValidatePKCES256RFC7636(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !validatePKCE(verifier, challenge, "S256") {
		t.Fatal("RFC 7636 S256 vector was rejected")
	}
	for _, method := range []string{"", "plain", "s256"} {
		if validatePKCE(verifier, challenge, method) {
			t.Fatalf("method %q must be rejected", method)
		}
	}
	if validatePKCE(verifier+"x", challenge, "S256") {
		t.Fatal("incorrect verifier was accepted")
	}
}

func TestIDTokenUserInfoIsLimitedByGrantedScopes(t *testing.T) {
	all := map[string]interface{}{
		"preferred_username": "alice", "name": "Alice", "picture": "https://example/avatar",
		"email": "alice@example.com", "email_verified": true, "role": "admin",
	}
	openidOnly := scopedIDTokenUserInfo([]string{"openid"}, all)
	if len(openidOnly) != 0 {
		t.Fatalf("openid-only claims leaked user info: %#v", openidOnly)
	}
	profile := scopedIDTokenUserInfo([]string{"openid", "profile"}, all)
	if profile["preferred_username"] != "alice" || profile["name"] != "Alice" || profile["picture"] == nil {
		t.Fatalf("profile claims missing: %#v", profile)
	}
	if _, ok := profile["email"]; ok {
		t.Fatalf("profile scope leaked email: %#v", profile)
	}
	email := scopedIDTokenUserInfo([]string{"openid", "email"}, all)
	if email["email"] != "alice@example.com" || len(email) != 1 {
		t.Fatalf("legacy email claims were expanded: %#v", email)
	}
	currentEmail := claimLimitedUserInfo([]string{"email", "email_verified"}, all)
	if currentEmail["email"] != "alice@example.com" || currentEmail["email_verified"] != true || len(currentEmail) != 2 {
		t.Fatalf("current email claims were not emitted: %#v", currentEmail)
	}
}

func TestRefreshRejectsRemovedScopesBeforeRotation(t *testing.T) {
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := session.NewStore(client)
	ctx := context.Background()
	data := &session.TokenData{ClientID: "client", UserID: "client", Scopes: []string{"openid", "offline_access"}, TokenUse: "refresh"}
	if err := store.SaveRefreshToken(ctx, "refresh", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	service := NewTokenService(nil, store, "", time.Minute, time.Hour)
	if _, err := service.RefreshToken(ctx, "refresh", "client", []string{"openid"}); err == nil {
		t.Fatal("refresh token retained a removed scope")
	}
	if _, err := store.GetRefreshToken(ctx, "refresh"); err == nil {
		t.Fatal("scope-invalid refresh family was not revoked")
	}
}

func TestRefreshRejectsRemovedClaimsBeforeRotation(t *testing.T) {
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := session.NewStore(client)
	ctx := context.Background()
	data := &session.TokenData{
		ClientID: "client", UserID: "client", Scopes: []string{"openid", "tenant.read"},
		AllowedClaims: []string{"sub", "role"}, TokenUse: "refresh",
	}
	if err := store.SaveRefreshToken(ctx, "refresh", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	service := NewTokenService(nil, store, "", time.Minute, time.Hour)
	currentScopeClaims := map[string][]string{"openid": {"sub"}, "tenant.read": {}}
	if _, err := service.RefreshTokenWithClaimPolicy(
		ctx, "refresh", "client", []string{"openid", "tenant.read"}, currentScopeClaims,
	); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("refresh token retained a removed claim: %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, "refresh"); err == nil {
		t.Fatal("claim-invalid refresh family was not revoked")
	}
}

func TestTokenServicePublishesRuntimeLifetimeSnapshotsAndSafeRetention(t *testing.T) {
	service := NewTokenService(nil, nil, "https://auth.example.test", time.Hour, 30*24*time.Hour)
	service.SetAuthorizationCodeFallback(5 * time.Minute)
	current := TokenLifetimes{
		AccessToken: 15 * time.Minute, RefreshToken: 7 * 24 * time.Hour, AuthorizationCode: time.Minute,
	}
	service.SetLifetimeSource(func() TokenLifetimes { return current }, 24*time.Hour, 365*24*time.Hour, 10*time.Minute)
	if got := service.Lifetimes(); got != current {
		t.Fatalf("runtime lifetimes = %#v, want %#v", got, current)
	}
	current = TokenLifetimes{
		AccessToken: 30 * time.Minute, RefreshToken: 14 * 24 * time.Hour, AuthorizationCode: 2 * time.Minute,
	}
	if got := service.Lifetimes(); got != current {
		t.Fatalf("updated runtime lifetimes = %#v, want %#v", got, current)
	}
	if service.RevocationTTL() != 365*24*time.Hour {
		t.Fatalf("revocation retention = %s", service.RevocationTTL())
	}
	if service.AuthorizationCodeRetention() != 10*time.Minute {
		t.Fatalf("authorization code reuse retention = %s", service.AuthorizationCodeRetention())
	}
}

func TestBrowserOAuthEntryPointsUseConfiguredSessionResolver(t *testing.T) {
	resolverErr := errors.New("session expired by runtime policy")
	resolverCalls := 0
	resolver := func(http.ResponseWriter, *http.Request) (*session.SessionData, error) {
		resolverCalls++
		return nil, resolverErr
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/authorize", nil)

	handler := &Handler{}
	handler.SetBrowserSessionResolver(resolver)
	if authenticated, currentUser := handler.currentSessionUser(recorder, request); authenticated != nil || currentUser != nil {
		t.Fatal("authorize accepted a session rejected by the runtime policy resolver")
	}

	consentHandler := &ConsentHandler{}
	consentHandler.SetBrowserSessionResolver(resolver)
	if authenticated, ok := consentHandler.authenticatedSession(recorder, request); ok || authenticated != nil {
		t.Fatal("consent accepted a session rejected by the runtime policy resolver")
	}
	if resolverCalls != 2 {
		t.Fatalf("session resolver calls = %d, want 2", resolverCalls)
	}
}

func TestRefreshWrongClientDoesNotMutateToken(t *testing.T) {
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := session.NewStore(client)
	ctx := context.Background()
	data := &session.TokenData{ClientID: "owner", UserID: "owner", Scopes: []string{"offline_access"}, TokenUse: "refresh"}
	if err := store.SaveRefreshToken(ctx, "refresh", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	service := NewTokenService(nil, store, "", time.Minute, time.Hour)
	if _, err := service.RefreshToken(ctx, "refresh", "attacker", []string{"offline_access"}); !errors.Is(err, ErrClientMismatch) {
		t.Fatalf("wrong-client refresh error = %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, "refresh"); err != nil {
		t.Fatalf("wrong-client attempt mutated token: %v", err)
	}
}

func TestRevokeAccessTokenReportsMetadataStoreFailure(t *testing.T) {
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := session.NewStore(client)
	ctx := context.Background()
	const issuer = "https://issuer.test"
	const clientID = "client"
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	jti := uuid.NewString()
	claims := &Claims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: issuer, Subject: clientID, Audience: jwt.ClaimStrings{clientID}, ID: jti,
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)), IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now),
	}, Scope: "openid", TokenUse: "access"}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveToken(ctx, jti, &session.TokenData{
		ClientID: clientID, UserID: clientID, Scopes: []string{"openid"}, TokenUse: "access",
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	client.AddHook(tokenMetadataFailureHook{})
	service := NewTokenService(nil, store, issuer, time.Minute, time.Hour)
	service.publicKeyLoader = func(context.Context, string) (*rsa.PublicKey, error) { return &privateKey.PublicKey, nil }

	err = service.RevokeTokenForClient(ctx, signed, clientID)
	if !errors.Is(err, ErrTokenValidationUnavailable) {
		t.Fatalf("revocation error = %v, want ErrTokenValidationUnavailable", err)
	}
}

func TestRefreshReuseIsReportedDistinctly(t *testing.T) {
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := session.NewStore(client)
	ctx := context.Background()
	data := &session.TokenData{ClientID: "client", UserID: "client", Scopes: []string{"offline_access"}, TokenUse: "refresh"}
	if err := store.SaveRefreshToken(ctx, "old-refresh", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RotateRefreshToken(ctx, "old-refresh", "current-refresh", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	service := NewTokenService(nil, store, "", time.Minute, time.Hour)
	if _, err := service.RefreshToken(ctx, "old-refresh", "client", []string{"offline_access"}); !errors.Is(err, ErrRefreshTokenReuse) {
		t.Fatalf("refresh reuse error = %v", err)
	}
}

func TestConfidentialIntrospectionSupportsOwnedRefreshTokens(t *testing.T) {
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := session.NewStore(client)
	ctx := context.Background()
	data := &session.TokenData{ClientID: "owner", UserID: "owner", Scopes: []string{"offline_access"}, TokenUse: "refresh"}
	if err := store.SaveRefreshToken(ctx, "refresh", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	service := &TokenService{session: store, accessPolicy: fakeAccessPolicy{allowed: true}}
	owned, err := service.IntrospectTokenForClient(ctx, "refresh", "owner", []string{"offline_access"})
	if err != nil || owned["active"] != true || owned["token_type"] != "refresh_token" {
		t.Fatalf("owned refresh introspection = %#v, err=%v", owned, err)
	}
	crossClient, err := service.IntrospectTokenForClient(ctx, "refresh", "attacker", []string{"offline_access"})
	if err != nil || crossClient["active"] != false {
		t.Fatalf("cross-client refresh introspection = %#v, err=%v", crossClient, err)
	}
}

func TestPKCEVerifierBoundsAndAlphabet(t *testing.T) {
	valid := strings.Repeat("a", 43)
	digest := sha256.Sum256([]byte(valid))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if !validPKCEVerifier(valid) || !validPKCEChallenge(challenge) {
		t.Fatal("valid PKCE inputs rejected")
	}
	for _, verifier := range []string{strings.Repeat("a", 42), strings.Repeat("a", 129), strings.Repeat("a", 42) + "/"} {
		if validPKCEVerifier(verifier) {
			t.Fatalf("invalid verifier accepted: %q", verifier)
		}
	}
}

func TestParseAndValidateScopes(t *testing.T) {
	scopes, err := parseAndValidateScopes("email openid", []string{"openid", "profile", "email"})
	if err != nil || strings.Join(scopes, " ") != "email openid" {
		t.Fatalf("unexpected scopes %v, err=%v", scopes, err)
	}
	for _, raw := range []string{"openid admin", "openid openid"} {
		if _, err := parseAndValidateScopes(raw, []string{"openid"}); err == nil {
			t.Fatalf("invalid scope request %q accepted", raw)
		}
	}
}

func TestConsentScopeSelectionPreservesRequiredScopes(t *testing.T) {
	t.Parallel()
	requested := []string{"email", "offline_access", "openid", "profile"}
	optional := []string{"email", "offline_access", "profile"}
	granted, err := resolveGrantedScopes(requested, optional, []string{"profile"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(granted, " "); got != "openid profile" {
		t.Fatalf("granted scopes = %q, want openid profile", got)
	}
	all, err := resolveGrantedScopes(requested, optional, optional)
	if err != nil || strings.Join(all, " ") != strings.Join(requested, " ") {
		t.Fatalf("all optional scopes grant = %v, %v", all, err)
	}

	invalid := []struct {
		name     string
		optional []string
		selected []string
	}{
		{name: "optional scope not requested", optional: []string{"groups"}, selected: nil},
		{name: "openid optional", optional: []string{"openid"}, selected: nil},
		{name: "required scope selected as optional", optional: optional, selected: []string{"openid"}},
		{name: "duplicate selection", optional: optional, selected: []string{"profile", "profile"}},
	}
	for _, testCase := range invalid {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := resolveGrantedScopes(requested, testCase.optional, testCase.selected); !errors.Is(err, errInvalidConsentScopes) {
				t.Fatalf("selection error = %v", err)
			}
		})
	}
}

func TestConsentPermissionsDescribeStandardClaims(t *testing.T) {
	t.Parallel()
	permissions := consentPermissions(
		[]string{"openid", "profile", "email", "offline_access", "tenant.read"},
		[]string{"profile", "email"},
		nil,
		nil,
	)
	if len(permissions) != 5 {
		t.Fatalf("permissions = %#v", permissions)
	}
	if !permissions[0].Required || strings.Join(permissions[0].Claims, " ") != "sub" {
		t.Fatalf("openid permission = %#v", permissions[0])
	}
	if permissions[1].Required || strings.Join(permissions[1].Claims, " ") != "preferred_username name picture" {
		t.Fatalf("profile permission = %#v", permissions[1])
	}
	if permissions[2].Required || strings.Join(permissions[2].Claims, " ") != "email email_verified" {
		t.Fatalf("email permission = %#v", permissions[2])
	}
	if permissions[3].Claims == nil || permissions[4].Claims == nil || len(permissions[3].Claims) != 0 || len(permissions[4].Claims) != 0 {
		t.Fatalf("non-claim permissions leaked claims: %#v", permissions)
	}
	encodedPermissions, err := json.Marshal(permissions)
	if err != nil {
		t.Fatalf("marshal permissions: %v", err)
	}
	if bytes.Contains(encodedPermissions, []byte(`"claims":null`)) {
		t.Fatalf("consent API encoded an absent claim list as null: %s", encodedPermissions)
	}
}

func TestConsentPermissionsMarkOnlyChangesToExistingGrant(t *testing.T) {
	t.Parallel()
	permissions := consentPermissionsWithHistory(
		[]string{"openid", "profile", "email"}, []string{"email"}, nil, nil, []string{"openid", "profile"},
	)
	if len(permissions) != 3 || !permissions[0].PreviouslyGranted || permissions[0].NewlyRequested ||
		!permissions[1].PreviouslyGranted || permissions[1].NewlyRequested ||
		permissions[2].PreviouslyGranted || !permissions[2].NewlyRequested {
		t.Fatalf("permission history = %#v", permissions)
	}
	firstConsent := consentPermissionsWithHistory([]string{"openid"}, nil, nil, nil, nil)
	if len(firstConsent) != 1 || firstConsent[0].NewlyRequested {
		t.Fatalf("first consent must not be presented as a change: %#v", firstConsent)
	}
}

func TestUserClaimsFollowAllowedClaimNamesInsteadOfStandardScopes(t *testing.T) {
	t.Parallel()
	displayName := "Alice Example"
	email := "alice@example.test"
	avatar := "/media/avatars/avatar-id/128.webp"
	verifiedAt := time.Now().UTC()
	handler := &Handler{config: &config.Config{Auth: config.AuthConfig{Issuer: "https://issuer.example"}}}
	u := &models.User{
		Username: "alice", DisplayName: &displayName, Email: &email, EmailVerifiedAt: &verifiedAt,
		AvatarURL: &avatar, Role: "admin",
	}
	claims := handler.userClaimsForAllowed(u, []string{"role", "email_verified"})
	if len(claims) != 2 || claims["role"] != "admin" || claims["email_verified"] != true {
		t.Fatalf("custom-scope claims = %#v", claims)
	}
	for _, forbidden := range []string{"preferred_username", "name", "picture", "email"} {
		if _, ok := claims[forbidden]; ok {
			t.Fatalf("unapproved claim %q leaked: %#v", forbidden, claims)
		}
	}
}

func TestExplicitEmptyAllowedClaimsRemainDistinctFromLegacyJWTs(t *testing.T) {
	t.Parallel()
	encoded, err := json.Marshal(&Claims{AllowedClaims: []string{}, ClaimNamesSet: true, TokenUse: "access"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"claim_names_set":true`) {
		t.Fatalf("explicit claim policy marker was omitted: %s", encoded)
	}
	var current Claims
	if err := json.Unmarshal(encoded, &current); err != nil {
		t.Fatal(err)
	}
	if !current.ClaimNamesSet || len(current.AllowedClaims) != 0 {
		t.Fatalf("explicit empty claim names decoded as %#v", current)
	}
	effective := effectiveClaimNames([]string{"openid", "profile"}, current.AllowedClaims, current.ClaimNamesSet)
	if effective == nil || len(effective) != 0 {
		t.Fatalf("explicit empty claim policy became %#v", effective)
	}
	var legacy Claims
	if err := json.Unmarshal([]byte(`{"token_use":"access"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.ClaimNamesSet || legacy.AllowedClaims != nil {
		t.Fatalf("legacy missing claim policy decoded as %#v", legacy)
	}
}

func TestDecodeConsentDecisionDistinguishesMissingAndNullOptionalScopes(t *testing.T) {
	t.Parallel()
	missing := httptest.NewRequest(http.MethodPost, "/api/consent/accept", strings.NewReader(`{"challenge":"challenge"}`))
	decoded, ok := decodeConsentDecisionRequest(missing)
	if !ok || decoded.GrantedOptionalScopes != nil {
		t.Fatalf("missing optional scopes decoded as %#v, ok=%v", decoded, ok)
	}
	empty := httptest.NewRequest(http.MethodPost, "/api/consent/accept", strings.NewReader(`{"challenge":"challenge","granted_optional_scopes":[]}`))
	decoded, ok = decodeConsentDecisionRequest(empty)
	if !ok || decoded.GrantedOptionalScopes == nil || len(*decoded.GrantedOptionalScopes) != 0 {
		t.Fatalf("empty optional scopes decoded as %#v, ok=%v", decoded, ok)
	}
	for _, body := range []string{
		`{"challenge":"challenge","granted_optional_scopes":null}`,
		`{"challenge":"challenge","granted_optional_scopes":"profile"}`,
		`{"challenge":"challenge","granted_optional_scopes":[],"unexpected":true}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/api/consent/accept", strings.NewReader(body))
		if _, ok := decodeConsentDecisionRequest(request); ok {
			t.Fatalf("invalid consent decision accepted: %s", body)
		}
	}
}

func TestAddQueryPreservesExistingParameters(t *testing.T) {
	got, err := addQuery("https://client.example/cb?tenant=one", map[string]string{"code": "a+b&c", "state": "x y"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://client.example/cb?code=a%2Bb%26c&state=x+y&tenant=one" {
		t.Fatalf("unexpected redirect URL: %s", got)
	}
}

func TestOAuthOpaqueParameterBounds(t *testing.T) {
	t.Parallel()
	if !validOAuthOpaqueParameter("", maxOAuthStateBytes, true) {
		t.Fatal("optional empty state was rejected")
	}
	if validOAuthOpaqueParameter("", maxOIDCNonceBytes, false) {
		t.Fatal("required empty nonce was accepted")
	}
	if !validOAuthOpaqueParameter(strings.Repeat("s", maxOAuthStateBytes), maxOAuthStateBytes, true) {
		t.Fatal("maximum-length state was rejected")
	}
	if validOAuthOpaqueParameter(strings.Repeat("s", maxOAuthStateBytes+1), maxOAuthStateBytes, true) {
		t.Fatal("oversized state was accepted")
	}
	if validOAuthOpaqueParameter(string([]byte{0xff}), maxOIDCNonceBytes, false) {
		t.Fatal("invalid UTF-8 nonce was accepted")
	}
}

func TestDiscoveryAdvertisesOnlySupportedFlows(t *testing.T) {
	policy := settings.DefaultOAuthPolicy()
	policy.AllowedScopes = append(policy.AllowedScopes, "tenant.read")
	policy.ScopeDefinitions["tenant.read"] = settings.OAuthScopeDefinition{
		DisplayName: "读取租户", Description: "读取当前用户可以访问的租户信息。",
		Claims: []string{"role"}, AssignmentPolicy: settings.OAuthAssignmentAdminOnly, RiskLevel: settings.OAuthRiskSensitive,
	}
	policy, err := settings.NormalizeOAuthPolicyUpdate(policy)
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{
		config: &config.Config{Auth: config.AuthConfig{Issuer: "https://issuer.example"}},
		oauthPolicySource: func() settings.Versioned[settings.OAuthPolicy] {
			return settings.Versioned[settings.OAuthPolicy]{Revision: 2, Value: policy}
		},
	}
	recorder := httptest.NewRecorder()
	handler.Discovery(recorder, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	var body map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	responses := body["response_types_supported"].([]interface{})
	if len(responses) != 1 || responses[0] != "code" {
		t.Fatalf("unexpected response types: %v", responses)
	}
	methods := body["code_challenge_methods_supported"].([]interface{})
	if len(methods) != 1 || methods[0] != "S256" {
		t.Fatalf("unexpected PKCE methods: %v", methods)
	}
	if body["device_authorization_endpoint"] != "https://issuer.example/device_authorization" {
		t.Fatalf("device authorization endpoint = %v", body["device_authorization_endpoint"])
	}
	acrValues := body["acr_values_supported"].([]interface{})
	if len(acrValues) != 2 || acrValues[0] != oauthstepup.ACRLevel1 || acrValues[1] != oauthstepup.ACRLevel2 {
		t.Fatalf("unexpected ACR values: %v", acrValues)
	}
	claims := body["claims_supported"].([]interface{})
	for _, expected := range []string{"acr", "amr", "auth_time"} {
		if !slices.Contains(claims, interface{}(expected)) {
			t.Fatalf("claims_supported is missing %q: %v", expected, claims)
		}
	}
	grants := body["grant_types_supported"].([]interface{})
	foundDeviceGrant := false
	for _, grant := range grants {
		if grant == models.GrantDeviceCode {
			foundDeviceGrant = true
		}
	}
	if !foundDeviceGrant {
		t.Fatalf("device authorization grant missing from discovery: %v", grants)
	}
	scopes := body["scopes_supported"].([]interface{})
	if scopes[len(scopes)-1] != "tenant.read" {
		t.Fatalf("discovery scopes = %v", scopes)
	}
}

func TestOAuthReauthenticationContinuationIsBoundAndSingleUse(t *testing.T) {
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := session.NewStore(client)
	handler := &Handler{sessionStore: store}
	request := httptest.NewRequest(http.MethodGet, "/authorize?client_id=client&max_age=0&state=state", nil)
	canonical := oauthAuthorizationRequestURI(request)
	token := "one-time-continuation"
	createdAt := time.Now().UTC().Add(-time.Second)
	if err := store.SaveOAuthReauthentication(request.Context(), token, &session.OAuthReauthenticationData{
		RequestURI: canonical,
		CreatedAt:  createdAt,
	}, time.Minute); err != nil {
		t.Fatal(err)
	}
	query := request.URL.Query()
	query.Set(oauthReauthenticationParameter, token)
	request.URL.RawQuery = query.Encode()
	zero := time.Duration(0)
	authenticated := &session.SessionData{AuthenticatedAt: createdAt.Add(500 * time.Millisecond)}
	satisfied, err := handler.oauthReauthenticationSatisfied(request, authenticated, &zero)
	if err != nil || !satisfied {
		t.Fatalf("first continuation satisfied=%v err=%v", satisfied, err)
	}
	satisfied, err = handler.oauthReauthenticationSatisfied(request, authenticated, &zero)
	if err != nil || satisfied {
		t.Fatalf("reused continuation satisfied=%v err=%v", satisfied, err)
	}
}

func TestAuthenticationClaimsAndIntrospectionUseStandardContext(t *testing.T) {
	claims := &Claims{}
	applyAuthenticationClaims(claims, IssuanceAuthentication{
		Context: oauthstepup.ACRLevel2,
		Methods: []string{"pwd", "otp"},
		AuthTime: 1234,
	})
	if claims.AuthenticationContext != oauthstepup.ACRLevel2 || claims.AuthenticationTime != 1234 ||
		!slices.Equal(claims.AuthenticationMethods, []string{"pwd", "otp"}) {
		t.Fatalf("authentication claims = %#v", claims)
	}
	claims.Subject = "user"
	claims.Audience = jwt.ClaimStrings{"client"}
	claims.Scope = "openid"
	claims.ID = "token"
	claims.Issuer = "https://issuer.example"
	claims.ExpiresAt = jwt.NewNumericDate(time.Unix(2000, 0))
	claims.IssuedAt = jwt.NewNumericDate(time.Unix(1000, 0))
	result := introspectionClaims(claims)
	if result["acr"] != oauthstepup.ACRLevel2 || result["auth_time"] != int64(1234) ||
		!slices.Equal(result["amr"].([]string), []string{"pwd", "otp"}) {
		t.Fatalf("introspection authentication context = %#v", result)
	}
}

func TestJWKVerificationRetentionUsesSignedTokenTTL(t *testing.T) {
	manager := NewJWKManager(nil, 2048, 24*time.Hour)
	masterKey := make([]byte, 32)
	if err := manager.Configure(masterKey, time.Hour); err != nil {
		t.Fatal(err)
	}
	if manager.verificationRetention != time.Hour+defaultClockSkew {
		t.Fatalf("verification retention = %v, want %v", manager.verificationRetention, time.Hour+defaultClockSkew)
	}
}

func TestEndSessionWithoutHintDoesNotDeleteAmbientSession(t *testing.T) {
	handler := &Handler{config: &config.Config{}}
	request := httptest.NewRequest("GET", "/end_session", nil)
	request.AddCookie(&http.Cookie{Name: oauthSessionCookie, Value: "ambient-session"})
	recorder := httptest.NewRecorder()
	handler.EndSession(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("hint-less GET cleared session cookie: %q", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := recorder.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q", got)
	}

	redirectRequest := httptest.NewRequest("GET", "/end_session?post_logout_redirect_uri=https%3A%2F%2Fclient.example%2Flogout", nil)
	redirectRequest.AddCookie(&http.Cookie{Name: oauthSessionCookie, Value: "ambient-session"})
	redirectRecorder := httptest.NewRecorder()
	handler.EndSession(redirectRecorder, redirectRequest)
	if redirectRecorder.Code != http.StatusBadRequest || redirectRecorder.Header().Get("Set-Cookie") != "" {
		t.Fatalf("hint-less redirect status=%d set-cookie=%q", redirectRecorder.Code, redirectRecorder.Header().Get("Set-Cookie"))
	}
}

func TestUserInfoResponsesDisableCaching(t *testing.T) {
	t.Parallel()
	handler := &Handler{tokenService: &TokenService{}}
	request := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	recorder := httptest.NewRecorder()
	handler.UserInfo(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := recorder.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q", got)
	}
}

func TestValidateEndSessionSessionFailsClosedOnStoreErrors(t *testing.T) {
	t.Parallel()
	subject := "user-id"
	if err := validateEndSessionSession(nil, session.ErrNotFound, subject); err != nil {
		t.Fatalf("stale session cookie was rejected: %v", err)
	}
	if err := validateEndSessionSession(&session.SessionData{UserID: subject}, nil, subject); err != nil {
		t.Fatalf("matching session was rejected: %v", err)
	}
	if err := validateEndSessionSession(&session.SessionData{UserID: "other-user"}, nil, subject); !errors.Is(err, errEndSessionSubjectMismatch) {
		t.Fatalf("subject mismatch error = %v", err)
	}
	storeErr := errors.New("redis unavailable")
	if err := validateEndSessionSession(nil, storeErr, subject); !errors.Is(err, storeErr) {
		t.Fatalf("store error = %v, want %v", err, storeErr)
	}
}

func TestOAuthFormBodyLimit(t *testing.T) {
	payload := "token=" + strings.Repeat("x", int(maxOAuthFormBodyBytes)+1)
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	err := parseOAuthForm(recorder, request)
	var tooLarge *http.MaxBytesError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("oversized OAuth form error = %v, want *http.MaxBytesError", err)
	}
	if tooLarge.Limit != maxOAuthFormBodyBytes {
		t.Fatalf("body limit = %d, want %d", tooLarge.Limit, maxOAuthFormBodyBytes)
	}
}

func TestOAuthFormEndpointsRejectOversizedBodies(t *testing.T) {
	handler := &Handler{}
	payload := "token=" + strings.Repeat("x", int(maxOAuthFormBodyBytes)+1)
	tests := []struct {
		name       string
		handle     func(http.ResponseWriter, *http.Request)
		wantStatus int
	}{
		{name: "token", handle: handler.Token, wantStatus: http.StatusBadRequest},
		{name: "revoke", handle: handler.Revoke, wantStatus: http.StatusBadRequest},
		{name: "introspect", handle: handler.Introspect, wantStatus: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/"+test.name, strings.NewReader(payload))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			recorder := httptest.NewRecorder()
			test.handle(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
		})
	}
}

func TestUnsupportedGrantAuditDoesNotPersistRequestSecrets(t *testing.T) {
	handler := &Handler{}
	var captured SecurityAuditEvent
	var metricGrant, metricResult, metricReason string
	handler.SetSecurityAuditSink(func(_ context.Context, event SecurityAuditEvent) error {
		captured = event
		return nil
	})
	handler.SetGrantMetricSink(func(_ context.Context, grantType, result, reason string) {
		metricGrant, metricResult, metricReason = grantType, result, reason
	})
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("grant_type=private_extension&code=must-not-be-audited&refresh_token=must-not-be-audited"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.Token(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", response.Code)
	}
	if captured.Event != models.AuditTokenGrantFailed || captured.AggregateID != "unsupported" || captured.Result != "failure" {
		t.Fatalf("unexpected audit event: %#v", captured)
	}
	if captured.Details["grant_type"] != "unsupported" || captured.Details["failure_reason"] != "unsupported_grant_type" {
		t.Fatalf("unexpected audit details: %#v", captured.Details)
	}
	if metricGrant != "unsupported" || metricResult != "failure" || metricReason != "unsupported_grant_type" {
		t.Fatalf("unexpected grant metric: grant=%q result=%q reason=%q", metricGrant, metricResult, metricReason)
	}
	for _, key := range []string{"code", "refresh_token", "token", "nonce"} {
		if _, exists := captured.Details[key]; exists {
			t.Fatalf("sensitive field %q was included in audit details", key)
		}
	}
}

func TestOAuthRevocationAndEndSessionAuditsUseRealActorsWithoutCredentials(t *testing.T) {
	handler := &Handler{}
	events := make([]SecurityAuditEvent, 0, 2)
	handler.SetSecurityAuditSink(func(_ context.Context, event SecurityAuditEvent) error {
		events = append(events, event)
		return nil
	})

	handler.recordTokenRevocationAudit(context.Background(), "client_123", true, "failure", "high", "client_binding_mismatch")
	userID := uuid.New()
	handler.recordEndSessionAudit(context.Background(), &userID, "alice", "client_123", "success", "medium", "")

	if len(events) != 2 {
		t.Fatalf("audit event count = %d, want 2", len(events))
	}
	revocation := events[0]
	if revocation.Event != models.AuditTokenRevoked || revocation.ActorID != nil || revocation.ActorName != "client_123" ||
		revocation.AggregateType != "client" || revocation.AggregateID != "client_123" || revocation.Result != "failure" {
		t.Fatalf("unexpected token revocation audit: %#v", revocation)
	}
	if revocation.Details["operation"] != "token_revocation" || revocation.Details["failure_reason"] != "client_binding_mismatch" {
		t.Fatalf("unexpected token revocation details: %#v", revocation.Details)
	}

	logout := events[1]
	if logout.Event != models.AuditUserLogout || logout.ActorID == nil || *logout.ActorID != userID || logout.ActorName != "alice" ||
		logout.AggregateType != "client" || logout.AggregateID != "client_123" || logout.Result != "success" {
		t.Fatalf("unexpected end-session audit: %#v", logout)
	}
	if logout.Details["operation"] != "oidc_end_session" {
		t.Fatalf("unexpected end-session details: %#v", logout.Details)
	}

	for _, event := range events {
		for _, key := range []string{"token", "code", "cookie", "nonce", "csrf", "secret"} {
			if _, exists := event.Details[key]; exists {
				t.Fatalf("sensitive detail %q was included in %#v", key, event)
			}
		}
	}
	if targetType, targetID := oauthAuditTarget("client?token=must-not-be-audited", "revoke"); targetType != "oauth_endpoint" || targetID != "revoke" {
		t.Fatalf("unsafe client identifier became an audit target: type=%q id=%q", targetType, targetID)
	}
}

func TestOAuthAuditSinkFailureDoesNotLeakInternalError(t *testing.T) {
	handler := &Handler{config: &config.Config{}}
	handler.SetSecurityAuditSink(func(context.Context, SecurityAuditEvent) error {
		return errors.New("postgres connection details must stay internal")
	})

	tests := []struct {
		name       string
		request    *http.Request
		handle     func(http.ResponseWriter, *http.Request)
		wantStatus int
	}{
		{
			name: "revoke", request: httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader("client_id=client_123")),
			handle: handler.Revoke, wantStatus: http.StatusBadRequest,
		},
		{
			name: "end session", request: httptest.NewRequest(http.MethodGet, "/end_session?post_logout_redirect_uri=https%3A%2F%2Fclient.example%2Flogout", nil),
			handle: handler.EndSession, wantStatus: http.StatusBadRequest,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.request.Body != nil {
				test.request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			response := httptest.NewRecorder()
			test.handle(response, test.request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "postgres connection") {
				t.Fatalf("internal audit error leaked in response: %s", response.Body.String())
			}
		})
	}
}

func TestTokenAndIntrospectionResponsesDisableCaching(t *testing.T) {
	handler := &Handler{}
	tests := []struct {
		name   string
		handle func(http.ResponseWriter, *http.Request)
		body   string
	}{
		{name: "token", handle: handler.Token, body: "grant_type=unsupported"},
		{name: "introspect", handle: handler.Introspect, body: "token=" + strings.Repeat("x", int(maxOAuthFormBodyBytes)+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/"+test.name, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			recorder := httptest.NewRecorder()
			test.handle(recorder, request)
			if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q", got)
			}
			if got := recorder.Header().Get("Pragma"); got != "no-cache" {
				t.Fatalf("Pragma = %q", got)
			}
		})
	}
}

func TestAuthorizationRevocationInvalidatesOnlyEarlierUserTokens(t *testing.T) {
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := session.NewStore(client)
	service := &TokenService{session: store, accessPolicy: fakeAccessPolicy{allowed: true}}
	ctx := context.Background()
	mini.SetTime(time.Date(2026, 7, 26, 9, 30, 0, 0, time.UTC))

	revokedAt, err := store.RevokeUserClientAuthorization(ctx, "user-1", "client-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldToken := &session.TokenData{ClientID: "client-1", UserID: "user-1", AuthVersion: 1, AuthorizationIssuedAt: revokedAt - 1}
	if err := service.validateAuthorization(ctx, oldToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("old authorization validation error = %v", err)
	}
	newToken := &session.TokenData{ClientID: "client-1", UserID: "user-1", AuthVersion: 1, AuthorizationIssuedAt: revokedAt + 1}
	if err := service.validateAuthorization(ctx, newToken); err != nil {
		t.Fatalf("new authorization was rejected: %v", err)
	}
	clientCredentials := &session.TokenData{ClientID: "client-1", UserID: "client-1", AuthVersion: 0}
	if err := service.validateAuthorization(ctx, clientCredentials); err != nil {
		t.Fatalf("client credentials token was affected by user revocation: %v", err)
	}
	missingIssuedAt := &session.TokenData{ClientID: "client-1", UserID: "user-1", AuthVersion: 1}
	if err := service.validateAuthorization(ctx, missingIssuedAt); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("user token without authorization time error = %v", err)
	}
}

func TestRevokedAuthorizationCodeCannotIssueTokens(t *testing.T) {
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := session.NewStore(client)
	service := &TokenService{session: store, accessPolicy: fakeAccessPolicy{allowed: true}}
	ctx := context.Background()
	mini.SetTime(time.Date(2026, 7, 26, 9, 45, 0, 0, time.UTC))
	revokedAt, err := store.RevokeUserClientAuthorization(ctx, "user-1", "client-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.GenerateAuthorizationCodeTokenPair(ctx, "client-1", "user-1", []string{"openid"}, 1, revokedAt-1, false)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("revoked authorization code issuance error = %v", err)
	}
}

type fakeAccessPolicy struct {
	allowed  bool
	err      error
	revision int64
}

func (f fakeAccessPolicy) UserMayAccess(context.Context, string, string) (bool, error) {
	return f.allowed, f.err
}

func (f fakeAccessPolicy) ClientAuthorizationRevision(context.Context, string) (int64, error) {
	if f.revision == 0 {
		return 1, f.err
	}
	return f.revision, f.err
}

func TestValidateAuthorizationRejectsStaleClientRevision(t *testing.T) {
	mini := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })
	store := session.NewStore(redisClient)
	service := &TokenService{session: store, accessPolicy: fakeAccessPolicy{allowed: true, revision: 2}}
	issuedAt, err := store.AuthorizationIssueTime(context.Background(), "user-1", "client-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	stale := &session.TokenData{ClientID: "client-1", UserID: "user-1", AuthVersion: 1, AuthorizationIssuedAt: issuedAt, ClientAuthorizationRevision: 1}
	if err := service.validateAuthorization(context.Background(), stale); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("stale client revision error = %v", err)
	}
	current := *stale
	current.ClientAuthorizationRevision = 2
	if err := service.validateAuthorization(context.Background(), &current); err != nil {
		t.Fatalf("current client revision rejected: %v", err)
	}
	if _, err := service.GenerateAuthorizationCodeTokenPairAtRevisionWithClaims(
		context.Background(), "client-1", "user-1", []string{"openid"}, []string{"sub"}, 1, issuedAt, 1, false,
	); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("stale authorization code revision error = %v", err)
	}
}

func TestValidateAccessPolicyEnforcesClientPolicy(t *testing.T) {
	ctx := context.Background()
	service := &TokenService{}
	data := &session.TokenData{ClientID: "client", UserID: "11111111-1111-1111-1111-111111111111", AuthVersion: 1}

	if err := service.validateAccessPolicy(ctx, data); err != nil {
		t.Fatalf("nil checker must allow: %v", err)
	}
	service.accessPolicy = fakeAccessPolicy{allowed: true}
	if err := service.validateAccessPolicy(ctx, data); err != nil {
		t.Fatalf("allowed user was rejected: %v", err)
	}
	service.accessPolicy = fakeAccessPolicy{allowed: false}
	if err := service.validateAccessPolicy(ctx, data); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("denied user error = %v", err)
	}
	service.accessPolicy = fakeAccessPolicy{err: errors.New("db down")}
	if err := service.validateAccessPolicy(ctx, data); !errors.Is(err, ErrTokenValidationUnavailable) {
		t.Fatalf("checker failure must be unavailable, got %v", err)
	}
	machine := &session.TokenData{ClientID: "client", UserID: "", AuthVersion: 0}
	service.accessPolicy = fakeAccessPolicy{allowed: false}
	if err := service.validateAccessPolicy(ctx, machine); err != nil {
		t.Fatalf("machine tokens must not be policy-restricted: %v", err)
	}
}
