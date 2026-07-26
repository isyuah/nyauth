package oidcbff_test

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	issuerEnv           = "NYAUTH_EXAMPLE_ISSUER"
	adminUsernameEnv    = "NYAUTH_EXAMPLE_ADMIN_USERNAME"
	adminPasswordEnv    = "NYAUTH_EXAMPLE_ADMIN_PASSWORD"
	adminNewPasswordEnv = "NYAUTH_EXAMPLE_ADMIN_NEW_PASSWORD"
	maxResponseBytes    = 1 << 20
)

type browserSession struct {
	CSRFToken          string `json:"csrf_token"`
	MustChangePassword bool   `json:"must_change_password"`
}

type createdClient struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

type consentDetails struct {
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

type redirectResponse struct {
	RedirectURL string `json:"redirect_url"`
}

type callbackFlow struct {
	state       string
	nonce       string
	verifier    string
	issuer      string
	clientID    string
	oauthConfig *oauth2.Config
	idVerifier  *oidc.IDTokenVerifier
	result      chan error
	once        sync.Once
}

// TestStandardOAuthOIDCBFFFlow is an integration example, not a Nyauth SDK.
// It deliberately uses the standard oauth2 and go-oidc packages in the same
// way a server-side application would. No credentials means a normal unit-test
// run skips it.
func TestStandardOAuthOIDCBFFFlow(t *testing.T) {
	issuer := strings.TrimRight(strings.TrimSpace(os.Getenv(issuerEnv)), "/")
	username := strings.TrimSpace(os.Getenv(adminUsernameEnv))
	initialPassword := os.Getenv(adminPasswordEnv)
	if issuer == "" || username == "" || initialPassword == "" {
		t.Skip("standard OAuth/OIDC integration environment is not configured")
	}
	parsedIssuer, err := url.Parse(issuer)
	if err != nil || parsedIssuer.Scheme == "" || parsedIssuer.Host == "" || parsedIssuer.User != nil {
		t.Fatal("integration issuer is invalid")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal("creating browser cookie jar failed")
	}
	browser := &http.Client{
		Jar:     jar,
		Timeout: 20 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	session, currentPassword, err := loginAdministrator(ctx, browser, issuer, username, initialPassword, os.Getenv(adminNewPasswordEnv))
	if err != nil {
		t.Fatal(err)
	}
	if session.MustChangePassword {
		newPassword := os.Getenv(adminNewPasswordEnv)
		if newPassword == "" {
			t.Fatal("bootstrap administrator requires a password change but no new password is configured")
		}
		status, err := requestJSON(ctx, browser, http.MethodPost, issuer+"/api/me/password", session.CSRFToken, map[string]string{
			"current_password": currentPassword,
			"new_password":     newPassword,
		}, &session)
		if err != nil || status != http.StatusOK {
			t.Fatal("bootstrap administrator password change failed")
		}
		if session.MustChangePassword || session.CSRFToken == "" {
			t.Fatal("password change did not establish a usable administrator session")
		}
	}

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatal("OIDC discovery failed")
	}

	state, err := randomURLSafe(32)
	if err != nil {
		t.Fatal("generating OAuth state failed")
	}
	nonce, err := randomURLSafe(32)
	if err != nil {
		t.Fatal("generating OIDC nonce failed")
	}
	pkceVerifier := oauth2.GenerateVerifier()

	flow := &callbackFlow{
		state: state, nonce: nonce, verifier: pkceVerifier, issuer: issuer,
		result: make(chan error, 1),
	}
	callbackServer := httptest.NewServer(flow)
	defer callbackServer.Close()
	callbackURL := callbackServer.URL + "/callback"

	var clientRegistration createdClient
	status, err := requestJSON(ctx, browser, http.MethodPost, issuer+"/api/my/clients", session.CSRFToken, map[string]any{
		"name":          "Standard Go OIDC BFF integration",
		"redirect_uris": []string{callbackURL},
		"grants":        []string{"authorization_code"},
		"scopes":        []string{"openid", "profile"},
		"is_public":     true,
	}, &clientRegistration)
	if err != nil || status != http.StatusCreated || clientRegistration.ID == "" {
		t.Fatal("creating temporary public OAuth client failed")
	}
	if clientRegistration.Secret != "" {
		t.Fatal("public OAuth client unexpectedly returned a secret")
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		cleanupStatus, cleanupErr := requestJSON(cleanupCtx, browser, http.MethodDelete, issuer+"/api/my/clients/"+url.PathEscape(clientRegistration.ID), session.CSRFToken, nil, nil)
		if cleanupErr != nil || (cleanupStatus != http.StatusNoContent && cleanupStatus != http.StatusNotFound) {
			t.Errorf("temporary OAuth client cleanup failed (status %d)", cleanupStatus)
		}
	})

	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	oauthConfig := &oauth2.Config{
		ClientID: clientRegistration.ID, RedirectURL: callbackURL,
		Endpoint: endpoint, Scopes: []string{"openid", "profile"},
	}
	flow.clientID = clientRegistration.ID
	flow.oauthConfig = oauthConfig
	flow.idVerifier = provider.Verifier(&oidc.Config{ClientID: clientRegistration.ID})

	authorizeURL := oauthConfig.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(pkceVerifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	)
	authorizeResponse, err := browser.Get(authorizeURL)
	if err != nil {
		t.Fatal("authorization request failed")
	}
	_ = authorizeResponse.Body.Close()
	if authorizeResponse.StatusCode != http.StatusFound {
		t.Fatalf("authorization request returned status %d", authorizeResponse.StatusCode)
	}
	consentURL, err := resolveSameIssuerLocation(issuer, authorizeResponse.Header.Get("Location"))
	if err != nil || consentURL.Path != "/consent" {
		t.Fatal("authorization endpoint did not return a valid consent redirect")
	}
	challenge := consentURL.Query().Get("challenge")
	if challenge == "" {
		t.Fatal("authorization endpoint returned no consent challenge")
	}

	var consent consentDetails
	status, err = requestJSON(ctx, browser, http.MethodGet, issuer+"/api/consent?challenge="+url.QueryEscape(challenge), "", nil, &consent)
	if err != nil || status != http.StatusOK || consent.ClientID != clientRegistration.ID || !contains(consent.Scopes, "openid") {
		t.Fatal("loading OAuth consent details failed")
	}
	var accepted redirectResponse
	status, err = requestJSON(ctx, browser, http.MethodPost, issuer+"/api/consent/accept", session.CSRFToken, map[string]string{"challenge": challenge}, &accepted)
	if err != nil || status != http.StatusOK || accepted.RedirectURL == "" {
		t.Fatal("accepting OAuth consent failed")
	}
	callbackLocation, err := url.Parse(accepted.RedirectURL)
	if err != nil || callbackLocation.Scheme != mustURL(t, callbackURL).Scheme || callbackLocation.Host != mustURL(t, callbackURL).Host || callbackLocation.Path != "/callback" {
		t.Fatal("consent returned an invalid callback location")
	}

	callbackClient := &http.Client{Timeout: 30 * time.Second}
	callbackResponse, err := callbackClient.Get(accepted.RedirectURL)
	if err != nil {
		t.Fatal("invoking BFF callback failed")
	}
	_ = callbackResponse.Body.Close()
	select {
	case callbackErr := <-flow.result:
		if callbackErr != nil {
			t.Fatal(callbackErr)
		}
	case <-ctx.Done():
		t.Fatal("BFF callback did not complete before the integration deadline")
	}
}

func (f *callbackFlow) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := f.complete(r)
	f.once.Do(func() { f.result <- err })
	if err != nil {
		http.Error(w, "OIDC callback validation failed", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *callbackFlow) complete(r *http.Request) error {
	if r.URL.Path != "/callback" || f.oauthConfig == nil || f.idVerifier == nil {
		return errors.New("BFF callback was not initialized")
	}
	returnedState := r.URL.Query().Get("state")
	if len(returnedState) != len(f.state) || subtle.ConstantTimeCompare([]byte(returnedState), []byte(f.state)) != 1 {
		return errors.New("BFF callback state validation failed")
	}
	if r.URL.Query().Get("error") != "" || r.URL.Query().Get("code") == "" {
		return errors.New("authorization server returned no usable authorization code")
	}
	token, err := f.oauthConfig.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(f.verifier))
	if err != nil {
		return errors.New("authorization code exchange failed")
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return errors.New("token response contained no ID token")
	}
	// Verify performs signature, issuer, audience, and expiration validation
	// against the discovery document and its JWKS.
	idToken, err := f.idVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return errors.New("ID token cryptographic validation failed")
	}
	now := time.Now()
	if idToken.Issuer != f.issuer || !contains(idToken.Audience, f.clientID) || idToken.Expiry.Before(now) || idToken.IssuedAt.IsZero() || idToken.IssuedAt.After(now.Add(2*time.Minute)) {
		return errors.New("ID token issuer, audience, or time validation failed")
	}
	if len(idToken.Nonce) != len(f.nonce) || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(f.nonce)) != 1 {
		return errors.New("ID token nonce validation failed")
	}
	return nil
}

func loginAdministrator(ctx context.Context, client *http.Client, issuer, username, initialPassword, nextPassword string) (browserSession, string, error) {
	passwords := []string{initialPassword}
	if nextPassword != "" && nextPassword != initialPassword {
		passwords = append(passwords, nextPassword)
	}
	for _, password := range passwords {
		var session browserSession
		status, err := requestJSON(ctx, client, http.MethodPost, issuer+"/api/login", "", map[string]string{
			"username": username, "password": password,
		}, &session)
		if err != nil {
			return browserSession{}, "", errors.New("administrator login request failed")
		}
		if status == http.StatusOK && session.CSRFToken != "" {
			return session, password, nil
		}
		if status != http.StatusUnauthorized {
			return browserSession{}, "", fmt.Errorf("administrator login returned status %d", status)
		}
	}
	return browserSession{}, "", errors.New("administrator login was rejected")
}

func requestJSON(ctx context.Context, client *http.Client, method, endpoint, csrf string, body, output any) (int, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, errors.New("encoding JSON request failed")
		}
		reader = strings.NewReader(string(encoded))
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return 0, errors.New("creating HTTP request failed")
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, errors.New("HTTP request failed")
	}
	defer response.Body.Close()
	if output == nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return response.StatusCode, nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	if err := decoder.Decode(output); err != nil {
		return response.StatusCode, errors.New("decoding JSON response failed")
	}
	return response.StatusCode, nil
}

func resolveSameIssuerLocation(issuer, location string) (*url.URL, error) {
	base, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	target = base.ResolveReference(target)
	if target.Scheme != base.Scheme || target.Host != base.Host {
		return nil, errors.New("redirect changed origin")
	}
	return target, nil
}

func randomURLSafe(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal("internal callback URL is invalid")
	}
	return parsed
}
