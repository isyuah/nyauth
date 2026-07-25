package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGitHubAuthenticateUsesOnlyVerifiedEmail(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil || r.Form.Get("code") != "valid-code" {
				http.Error(w, "bad code", http.StatusBadRequest)
				return
			}
			writeTestJSON(w, map[string]interface{}{"access_token": "upstream-secret", "token_type": "bearer"})
		case "/user":
			assertBearer(t, r, "upstream-secret")
			writeTestJSON(w, map[string]interface{}{"id": 123456789, "login": "octo", "avatar_url": "https://example.com/avatar"})
		case "/emails":
			assertBearer(t, r, "upstream-secret")
			writeTestJSON(w, []map[string]interface{}{
				{"email": "unverified@example.com", "primary": true, "verified": false},
				{"email": "verified@example.com", "primary": false, "verified": true},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	github := newGitHub("github", "client", "secret", nil,
		server.URL+"/authorize", server.URL+"/token", server.URL+"/user", server.URL+"/emails", server.Client())
	user, err := github.Authenticate(context.Background(), "valid-code", "https://app.example/callback", "ignored")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if user.ID != "123456789" || user.Username != "octo" {
		t.Fatalf("unexpected stable identity: %#v", user)
	}
	if user.Email != "verified@example.com" || !user.EmailVerified {
		t.Fatalf("unverified email was accepted or verified email was lost: %#v", user)
	}
}

func TestGitHubAuthenticateRejectsUpstreamErrors(t *testing.T) {
	t.Parallel()
	var userRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.WriteHeader(http.StatusBadRequest)
			writeTestJSON(w, map[string]string{"error": "bad_verification_code"})
		case "/user":
			userRequests.Add(1)
			writeTestJSON(w, map[string]interface{}{"id": 1, "login": "should-not-run"})
		}
	}))
	defer server.Close()

	github := newGitHub("github", "client", "secret", nil,
		server.URL+"/authorize", server.URL+"/token", server.URL+"/user", server.URL+"/emails", server.Client())
	if _, err := github.Authenticate(context.Background(), "invalid", "https://app.example/callback", ""); err == nil {
		t.Fatal("Authenticate() accepted an OAuth error response")
	}
	if got := userRequests.Load(); got != 0 {
		t.Fatalf("userinfo was fetched %d times after token failure", got)
	}
}

func TestOIDCAuthenticateVerifiesTokenAndUserinfo(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid form", http.StatusBadRequest)
				return
			}
			claims := jwt.MapClaims{
				"iss": issuer, "aud": "client-id", "sub": "stable-subject",
				"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
				"nonce": "expected-nonce", "email": "signed@example.com", "email_verified": true,
			}
			signed := signTestIDToken(t, privateKey, claims)
			writeTestJSON(w, map[string]interface{}{"access_token": "access", "token_type": "Bearer", "id_token": signed})
		case "/jwks":
			writeTestJSON(w, testJWKS(&privateKey.PublicKey))
		case "/userinfo":
			assertBearer(t, r, "access")
			writeTestJSON(w, map[string]interface{}{
				"sub": "stable-subject", "preferred_username": "verified-user",
				"email": "userinfo@example.com", "email_verified": true,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL

	configured := newConfiguredOIDC("oidc", "client-id", "client-secret", []string{"openid", "email"},
		issuer, server.URL+"/authorize", server.URL+"/token", server.URL+"/userinfo", server.URL+"/jwks",
		[]string{"none", "HS256", "RS256"}, server.Client())
	user, err := configured.Authenticate(context.Background(), "code", "https://app.example/callback", "expected-nonce")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if user.ID != "stable-subject" || user.Username != "verified-user" {
		t.Fatalf("unexpected OIDC identity: %#v", user)
	}
	if user.Email != "userinfo@example.com" || !user.EmailVerified {
		t.Fatalf("verified userinfo email missing: %#v", user)
	}
	if len(configured.supportedAlgs) != 1 || configured.supportedAlgs[0] != "RS256" {
		t.Fatalf("unsafe signing algorithms were retained: %v", configured.supportedAlgs)
	}
}

func TestOIDCAuthenticateRejectsNonceMismatch(t *testing.T) {
	t.Parallel()
	configured, closeServer := testOIDCProvider(t, func(issuer string) jwt.MapClaims {
		return jwt.MapClaims{
			"iss": issuer, "aud": "client-id", "sub": "stable-subject",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "nonce": "different",
		}
	})
	defer closeServer()
	if _, err := configured.Authenticate(context.Background(), "code", "https://app.example/callback", "expected"); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("Authenticate() nonce error = %v", err)
	}
}

func TestOIDCAuthenticateRejectsAudienceMismatch(t *testing.T) {
	t.Parallel()
	configured, closeServer := testOIDCProvider(t, func(issuer string) jwt.MapClaims {
		return jwt.MapClaims{
			"iss": issuer, "aud": "other-client", "sub": "stable-subject",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "nonce": "expected",
		}
	})
	defer closeServer()
	if _, err := configured.Authenticate(context.Background(), "code", "https://app.example/callback", "expected"); err == nil {
		t.Fatal("Authenticate() accepted an ID token for another audience")
	}
}

func TestProviderSecretEnvelopeBindsProviderName(t *testing.T) {
	t.Parallel()
	manager := NewManager(nil, make([]byte, 32))
	encrypted, err := manager.EncryptSecret("github", "client-secret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encrypted, "v1:primary:") {
		t.Fatalf("unexpected envelope format: %q", encrypted)
	}
	decrypted, err := manager.decryptSecret("github", encrypted)
	if err != nil || decrypted != "client-secret" {
		t.Fatalf("decryptSecret() = %q, %v", decrypted, err)
	}
	if _, err := manager.decryptSecret("google", encrypted); err == nil {
		t.Fatal("provider-name AAD substitution succeeded")
	}
}

func TestValidateProviderName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"github", "google-workspace", "oidc.eu_1"} {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) error = %v", name, err)
		}
	}
	for _, name := range []string{"", " leading", "trailing ", "nested/provider", strings.Repeat("a", 65)} {
		if err := ValidateName(name); err == nil {
			t.Errorf("ValidateName(%q) accepted an unsafe provider name", name)
		}
	}
}

func TestProductionNetworkPolicyRejectsNonPublicAddresses(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.1.1", "::1", "::ffff:127.0.0.1", "fe80::1", "0.0.0.0"} {
		ip := netip.MustParseAddr(raw)
		if !forbiddenProviderIP(ip) {
			t.Errorf("forbiddenProviderIP(%s) = false", raw)
		}
	}
	if forbiddenProviderIP(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public address was rejected")
	}
	_, err := NewGenericOIDCWithMode("private", "client", "secret", nil, "https://127.0.0.1/.well-known/openid-configuration", true)
	if err == nil || !strings.Contains(err.Error(), "forbidden address") {
		t.Fatalf("private discovery error = %v", err)
	}
}

func TestProductionModeAppliesNetworkPolicyToBuiltinProviders(t *testing.T) {
	t.Parallel()
	manager := NewManager(nil, make([]byte, 32), true)

	for _, providerType := range []string{"github", "google"} {
		configured, err := manager.providerFromConfig("test", providerType, "client", "secret", nil, "", "", "", "")
		if err != nil {
			t.Fatalf("providerFromConfig(%s) error = %v", providerType, err)
		}
		var client *http.Client
		switch value := configured.(type) {
		case *GitHub:
			client = value.client
		case *Google:
			client = value.client
		default:
			t.Fatalf("providerFromConfig(%s) type = %T", providerType, configured)
		}
		request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/internal", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.CheckRedirect(request, nil); err == nil {
			t.Errorf("%s production client accepted an HTTP redirect", providerType)
		}
	}
}

func TestDynamicSnapshotMutationDoesNotReloadUnrelatedProviders(t *testing.T) {
	t.Parallel()
	manager := NewManager(nil, make([]byte, 32))
	static := NewGitHub("shared", "static-client", "secret", nil)
	dynamic := NewGitHub("shared", "dynamic-client", "secret", nil)
	manager.staticProviders["shared"] = static
	manager.providers["shared"] = static

	manager.setDynamicProvider("shared", dynamic, true)
	if got, ok := manager.Get("shared"); !ok || got != dynamic {
		t.Fatalf("enabled dynamic provider was not installed: %T, %v", got, ok)
	}
	manager.setDynamicProvider("shared", nil, false)
	if _, ok := manager.Get("shared"); ok {
		t.Fatal("disabled dynamic provider did not shadow the static provider")
	}
	manager.restoreStaticProvider("shared")
	if got, ok := manager.Get("shared"); !ok || got != static {
		t.Fatalf("deleting dynamic override did not restore static provider: %T, %v", got, ok)
	}
}

func TestAuthorizationURLPreservesEndpointQueryAndIncludesNonce(t *testing.T) {
	t.Parallel()
	configured := newConfiguredOIDC("oidc", "client-id", "secret", []string{"openid"},
		"https://issuer.example", "https://issuer.example/authorize?tenant=one", "https://issuer.example/token", "", "https://issuer.example/jwks",
		[]string{"RS256"}, http.DefaultClient)
	authorizationURL := configured.AuthorizationURL("state-value", "nonce-value", "https://app.example/callback")
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	for key, expected := range map[string]string{
		"tenant": "one", "state": "state-value", "nonce": "nonce-value",
		"client_id": "client-id", "redirect_uri": "https://app.example/callback",
	} {
		if got := parsed.Query().Get(key); got != expected {
			t.Errorf("query %s = %q, want %q", key, got, expected)
		}
	}
}

func testOIDCProvider(t *testing.T, claims func(string) jwt.MapClaims) (*GenericOIDC, func()) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			writeTestJSON(w, map[string]interface{}{
				"access_token": "access", "token_type": "Bearer",
				"id_token": signTestIDToken(t, privateKey, claims(issuer)),
			})
		case "/jwks":
			writeTestJSON(w, testJWKS(&privateKey.PublicKey))
		default:
			http.NotFound(w, r)
		}
	}))
	issuer = server.URL
	configured := newConfiguredOIDC("oidc", "client-id", "client-secret", []string{"openid"},
		issuer, server.URL+"/authorize", server.URL+"/token", "", server.URL+"/jwks", []string{"RS256"}, server.Client())
	return configured, server.Close
}

func signTestIDToken(t *testing.T, privateKey *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func testJWKS(publicKey *rsa.PublicKey) map[string]interface{} {
	exponent := big.NewInt(int64(publicKey.E)).Bytes()
	return map[string]interface{}{"keys": []map[string]interface{}{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-key",
		"n": base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(exponent),
	}}}
}

func writeTestJSON(w http.ResponseWriter, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic(fmt.Sprintf("encoding test response: %v", err))
	}
}

func assertBearer(t *testing.T, r *http.Request, token string) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer "+token {
		t.Errorf("Authorization = %q", got)
	}
}
