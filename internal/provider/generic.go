package provider

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/nyasharp/nyauth/pkg/models"
	"golang.org/x/oauth2"
)

// GenericOIDC implements a discovery-backed OpenID Connect provider.
type GenericOIDC struct {
	name             string
	clientID         string
	clientSecret     string
	scopes           []string
	authorizationURL string
	tokenURL         string
	userinfoURL      string
	issuer           string
	jwksURL          string
	supportedAlgs    []string
	client           *http.Client
	verifier         *oidc.IDTokenVerifier
}

type oidcDiscovery struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

func NewGenericOIDC(name, clientID, clientSecret string, scopes []string, discoveryURL string) (*GenericOIDC, error) {
	return NewGenericOIDCWithMode(name, clientID, clientSecret, scopes, discoveryURL, false)
}

// NewGenericOIDCWithMode enables a network policy that prevents configured
// providers from reaching local or private services in production.
func NewGenericOIDCWithMode(name, clientID, clientSecret string, scopes []string, discoveryURL string, production bool) (*GenericOIDC, error) {
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	if !slices.Contains(scopes, "openid") {
		return nil, errors.New("OIDC provider scopes must include openid")
	}
	if err := validateHTTPSURL(discoveryURL); err != nil {
		return nil, fmt.Errorf("invalid discovery URL: %w", err)
	}

	client := newProviderHTTPClient(production)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating discovery request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching discovery: %w", err)
	}
	defer resp.Body.Close()
	var discovery oidcDiscovery
	if err := decodeProviderJSON(resp, &discovery); err != nil {
		return nil, fmt.Errorf("reading discovery document: %w", err)
	}
	if err := validateDiscovery(discovery, production); err != nil {
		return nil, err
	}
	if len(discovery.IDTokenSigningAlgValuesSupported) > 0 && len(filterAsymmetricSigningAlgorithms(discovery.IDTokenSigningAlgValuesSupported)) == 0 {
		return nil, errors.New("discovery document does not advertise a supported asymmetric ID-token signing algorithm")
	}

	return newConfiguredOIDC(
		name, clientID, clientSecret, scopes, discovery.Issuer,
		discovery.AuthorizationEndpoint, discovery.TokenEndpoint,
		discovery.UserinfoEndpoint, discovery.JWKSURI,
		discovery.IDTokenSigningAlgValuesSupported, client,
	), nil
}

func newConfiguredOIDC(name, clientID, clientSecret string, scopes []string, issuer, authURL, tokenURL, userinfoURL, jwksURL string, algs []string, client *http.Client) *GenericOIDC {
	safeAlgs := filterAsymmetricSigningAlgorithms(algs)
	if len(safeAlgs) == 0 {
		safeAlgs = []string{"RS256"}
	}
	remoteContext := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	verifier := oidc.NewVerifier(issuer, oidc.NewRemoteKeySet(remoteContext, jwksURL), &oidc.Config{
		ClientID: clientID, SupportedSigningAlgs: safeAlgs,
	})
	return &GenericOIDC{
		name: name, clientID: clientID, clientSecret: clientSecret,
		scopes: append([]string(nil), scopes...), authorizationURL: authURL,
		tokenURL: tokenURL, userinfoURL: userinfoURL, issuer: issuer,
		jwksURL: jwksURL, supportedAlgs: safeAlgs, client: client, verifier: verifier,
	}
}

func (g *GenericOIDC) Name() string { return g.name }
func (g *GenericOIDC) Type() string { return "generic" }

func (g *GenericOIDC) AuthorizationURL(state, nonce, redirectURI string) string {
	if g.authorizationURL == "" {
		return ""
	}
	return g.oauthConfig(redirectURI).AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce))
}

func (g *GenericOIDC) Authenticate(ctx context.Context, code, redirectURI, nonce string) (*models.ExternalUser, error) {
	if strings.TrimSpace(code) == "" {
		return nil, errors.New("authorization code is required")
	}
	if strings.TrimSpace(nonce) == "" {
		return nil, errors.New("OIDC nonce is required")
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, g.client)
	token, err := g.oauthConfig(redirectURI).Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchanging OIDC authorization code: %w", err)
	}
	if token == nil || strings.TrimSpace(token.AccessToken) == "" {
		return nil, errors.New("OIDC token response did not include an access token")
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("OIDC token response did not include an ID token")
	}
	idToken, err := g.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verifying OIDC ID token: %w", err)
	}
	if idToken.Subject == "" {
		return nil, errors.New("OIDC ID token is missing subject")
	}
	if idToken.Nonce == "" || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		return nil, errors.New("OIDC nonce mismatch")
	}

	claims := make(map[string]interface{})
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decoding OIDC ID token claims: %w", err)
	}
	if g.userinfoURL != "" {
		userinfo, err := g.fetchUserinfo(ctx, token.AccessToken)
		if err != nil {
			return nil, err
		}
		userinfoSubject, _ := userinfo["sub"].(string)
		if userinfoSubject == "" || subtle.ConstantTimeCompare([]byte(userinfoSubject), []byte(idToken.Subject)) != 1 {
			return nil, errors.New("OIDC userinfo subject does not match ID token")
		}
		for key, value := range userinfo {
			claims[key] = value
		}
	}

	user := &models.ExternalUser{Provider: g.name, ID: idToken.Subject, RawClaims: claims}
	user.Username = firstStringClaim(claims, "preferred_username", "name")
	if user.Username == "" {
		user.Username = idToken.Subject
	}
	if verified, ok := claims["email_verified"].(bool); ok && verified {
		if email, ok := claims["email"].(string); ok && strings.TrimSpace(email) != "" {
			user.Email = email
			user.EmailVerified = true
		}
	}
	if picture, ok := claims["picture"].(string); ok {
		user.AvatarURL = picture
	}
	return user, nil
}

func (g *GenericOIDC) oauthConfig(redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID: g.clientID, ClientSecret: g.clientSecret, RedirectURL: redirectURI,
		Scopes:   g.scopes,
		Endpoint: oauth2.Endpoint{AuthURL: g.authorizationURL, TokenURL: g.tokenURL},
	}
}

func (g *GenericOIDC) fetchUserinfo(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC userinfo: %w", err)
	}
	defer resp.Body.Close()
	claims := make(map[string]interface{})
	if err := decodeProviderJSON(resp, &claims); err != nil {
		return nil, fmt.Errorf("reading OIDC userinfo: %w", err)
	}
	return claims, nil
}

func validateDiscovery(discovery oidcDiscovery, production bool) error {
	if discovery.Issuer == "" || discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" || discovery.JWKSURI == "" {
		return errors.New("discovery document is missing issuer, authorization, token, or JWKS endpoint")
	}
	for label, endpoint := range map[string]string{
		"issuer": discovery.Issuer, "authorization endpoint": discovery.AuthorizationEndpoint,
		"token endpoint": discovery.TokenEndpoint, "JWKS endpoint": discovery.JWKSURI,
	} {
		if err := validateHTTPSURL(endpoint); err != nil {
			return fmt.Errorf("invalid %s: %w", label, err)
		}
	}
	if discovery.UserinfoEndpoint != "" {
		if err := validateHTTPSURL(discovery.UserinfoEndpoint); err != nil {
			return fmt.Errorf("invalid userinfo endpoint: %w", err)
		}
	}
	_ = production // HTTPS is mandatory in every environment; production additionally restricts dialing.
	return nil
}

func validateHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" {
		return errors.New("URL must be absolute and use HTTPS")
	}
	if u.User != nil || u.Fragment != "" {
		return errors.New("URL must not contain credentials or a fragment")
	}
	return nil
}

func filterAsymmetricSigningAlgorithms(values []string) []string {
	result := make([]string, 0, len(values))
	for _, algorithm := range values {
		if strings.HasPrefix(algorithm, "RS") || strings.HasPrefix(algorithm, "PS") || strings.HasPrefix(algorithm, "ES") || algorithm == "EdDSA" {
			result = append(result, algorithm)
		}
	}
	return result
}

func firstStringClaim(claims map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := claims[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func secureDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid provider address: %w", err)
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolving provider host: %w", err)
	}
	if len(addresses) == 0 {
		return nil, errors.New("provider host resolved to no addresses")
	}
	for _, address := range addresses {
		if forbiddenProviderIP(address) {
			return nil, fmt.Errorf("provider host resolves to forbidden address %s", address)
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, ip := range addresses {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("connecting to provider: %w", lastErr)
}

func forbiddenProviderIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is4() {
		octets := ip.As4()
		if octets[0] == 100 && octets[1]&0xc0 == 64 { // RFC 6598 shared address space.
			return true
		}
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// TestConnection tests an HTTPS discovery endpoint without exposing its body.
func TestConnection(ctx context.Context, discoveryURL string, production ...bool) (bool, time.Duration, string) {
	start := time.Now()
	if err := validateHTTPSURL(discoveryURL); err != nil {
		return false, 0, err.Error()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return false, time.Since(start), fmt.Sprintf("invalid URL: %v", err)
	}
	isProduction := len(production) > 0 && production[0]
	resp, err := newProviderHTTPClient(isProduction).Do(req)
	if err != nil {
		return false, time.Since(start), fmt.Sprintf("connection failed: %v", err)
	}
	defer resp.Body.Close()
	latency := time.Since(start)
	if resp.StatusCode != http.StatusOK {
		return false, latency, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return true, latency, ""
}
