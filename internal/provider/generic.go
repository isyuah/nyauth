package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nyasharp/nyauth/pkg/models"
)

// GenericOIDC implements the Provider interface for any standard OIDC provider.
type GenericOIDC struct {
	name              string
	clientID          string
	clientSecret      string
	scopes            []string
	authorizationURL  string
	tokenURL          string
	userinfoURL       string
	issuer            string
}

// OIDCDiscovery represents the OIDC discovery document.
type OIDCDiscovery struct {
	Issuer             string `json:"issuer"`
	AuthorizationEP    string `json:"authorization_endpoint"`
	TokenEP            string `json:"token_endpoint"`
	UserinfoEP         string `json:"userinfo_endpoint"`
	JWKSURI           string `json:"jwks_uri"`
}

// NewGenericOIDC creates a new generic OIDC provider by fetching the discovery document.
func NewGenericOIDC(name, clientID, clientSecret string, scopes []string, discoveryURL string) (*GenericOIDC, error) {
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating discovery request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching discovery: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var disc OIDCDiscovery
	if err := json.Unmarshal(body, &disc); err != nil {
		return nil, fmt.Errorf("parsing discovery document: %w", err)
	}

	if disc.AuthorizationEP == "" || disc.TokenEP == "" {
		return nil, fmt.Errorf("discovery document missing required endpoints")
	}

	return &GenericOIDC{
		name:             name,
		clientID:         clientID,
		clientSecret:     clientSecret,
		scopes:           scopes,
		authorizationURL: disc.AuthorizationEP,
		tokenURL:         disc.TokenEP,
		userinfoURL:      disc.UserinfoEP,
		issuer:           disc.Issuer,
	}, nil
}

// NewGenericOIDCFromURLs creates a provider with explicit URLs (no discovery).
func NewGenericOIDCFromURLs(name, clientID, clientSecret string, scopes []string, authURL, tokenURL, userinfoURL string) *GenericOIDC {
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	return &GenericOIDC{
		name:             name,
		clientID:         clientID,
		clientSecret:     clientSecret,
		scopes:           scopes,
		authorizationURL: authURL,
		tokenURL:         tokenURL,
		userinfoURL:      userinfoURL,
	}
}

func (g *GenericOIDC) Name() string { return g.name }
func (g *GenericOIDC) Type() string { return "generic" }

func (g *GenericOIDC) GetAuthorizationURL(state, redirectURI string) string {
	params := url.Values{
		"client_id":     {g.clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {strings.Join(g.scopes, " ")},
		"state":         {state},
		"response_type": {"code"},
	}
	return g.authorizationURL + "?" + params.Encode()
}

func (g *GenericOIDC) ExchangeCode(ctx context.Context, code, redirectURI string) (*TokenResponse, error) {
	data := url.Values{
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectURI},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", g.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var token TokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}
	return &token, nil
}

func (g *GenericOIDC) GetUserInfo(ctx context.Context, token *TokenResponse) (*models.ExternalUser, error) {
	if g.userinfoURL == "" {
		return nil, fmt.Errorf("userinfo endpoint not configured")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", g.userinfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var claims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, err
	}

	user := &models.ExternalUser{
		Provider:  g.name,
		RawClaims: claims,
	}

	if v, ok := claims["sub"].(string); ok {
		user.ID = v
	}
	if v, ok := claims["preferred_username"].(string); ok {
		user.Username = v
	} else if v, ok := claims["name"].(string); ok {
		user.Username = v
	}
	if v, ok := claims["email"].(string); ok {
		user.Email = v
	}
	if v, ok := claims["picture"].(string); ok {
		user.AvatarURL = v
	}

	return user, nil
}

// TestConnection tests if the discovery URL or provider endpoints are reachable.
func TestConnection(ctx context.Context, discoveryURL string) (bool, time.Duration, string) {
	start := time.Now()

	if discoveryURL == "" {
		return false, 0, "no discovery URL configured"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		return false, time.Since(start), fmt.Sprintf("invalid URL: %v", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
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
