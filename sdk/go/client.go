// Package nyauth provides a client SDK for authenticating with a nyauth server.
package nyauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config holds the nyauth client configuration.
type Config struct {
	// Issuer is the base URL of the nyauth server (e.g., "https://auth.example.com").
	Issuer string

	// ClientID is the OAuth 2.0 client ID.
	ClientID string

	// ClientSecret is the OAuth 2.0 client secret (optional for public clients).
	ClientSecret string

	// RedirectURI is the OAuth 2.0 redirect URI.
	RedirectURI string

	// HTTPClient is an optional custom HTTP client.
	HTTPClient *http.Client
}

// Client is the nyauth SDK client.
type Client struct {
	config Config
	http   *http.Client
}

// TokenResponse holds the response from the token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// UserInfo holds user information from the userinfo endpoint.
type UserInfo struct {
	Sub                string `json:"sub"`
	PreferredUsername  string `json:"preferred_username,omitempty"`
	Name               string `json:"name,omitempty"`
	Email              string `json:"email,omitempty"`
	Picture            string `json:"picture,omitempty"`
}

// DiscoveryDocument holds the OIDC discovery metadata.
type DiscoveryDocument struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI              string   `json:"jwks_uri"`
	RevocationEndpoint    string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint string   `json:"introspection_endpoint,omitempty"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported   []string `json:"grant_types_supported,omitempty"`
}

// NewClient creates a new nyauth client.
func NewClient(config Config) *Client {
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{config: config, http: httpClient}
}

// Discover fetches the OIDC discovery document from the issuer.
func (c *Client) Discover(ctx context.Context) (*DiscoveryDocument, error) {
	discoveryURL := strings.TrimSuffix(c.config.Issuer, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating discovery request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}

	var doc DiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding discovery: %w", err)
	}

	return &doc, nil
}

// GetAuthorizationURL returns the authorization URL and a random state parameter.
func (c *Client) GetAuthorizationURL(scopes []string, state string) (authURL string, stateOut string) {
	if state == "" {
		state = generateRandomState()
	}

	params := url.Values{
		"response_type": {"code"},
		"client_id":     {c.config.ClientID},
		"redirect_uri":  {c.config.RedirectURI},
		"scope":         {strings.Join(scopes, " ")},
		"state":         {state},
	}

	authEndpoint := strings.TrimSuffix(c.config.Issuer, "/") + "/authorize"
	return authEndpoint + "?" + params.Encode(), state
}

// GetAuthorizationURLPKCE returns the authorization URL with PKCE parameters.
func (c *Client) GetAuthorizationURLPKCE(scopes []string, state string) (authURL, stateOut, codeVerifier, codeChallenge string) {
	if state == "" {
		state = generateRandomState()
	}

	codeVerifier = generateCodeVerifier()
	codeChallenge = computeS256Challenge(codeVerifier)

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.config.ClientID},
		"redirect_uri":          {c.config.RedirectURI},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	authEndpoint := strings.TrimSuffix(c.config.Issuer, "/") + "/authorize"
	return authEndpoint + "?" + params.Encode(), state, codeVerifier, codeChallenge
}

// ExchangeCode exchanges an authorization code for tokens.
func (c *Client) ExchangeCode(ctx context.Context, code string) (*TokenResponse, error) {
	return c.ExchangeCodePKCE(ctx, code, "")
}

// ExchangeCodePKCE exchanges an authorization code for tokens with PKCE.
func (c *Client) ExchangeCodePKCE(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	tokenEndpoint := strings.TrimSuffix(c.config.Issuer, "/") + "/token"

	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {c.config.RedirectURI},
	}

	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	return c.doTokenRequest(ctx, tokenEndpoint, data)
}

// ClientCredentialsGrant performs the client credentials grant.
func (c *Client) ClientCredentialsGrant(ctx context.Context, scopes []string) (*TokenResponse, error) {
	tokenEndpoint := strings.TrimSuffix(c.config.Issuer, "/") + "/token"

	data := url.Values{
		"grant_type": {"client_credentials"},
	}

	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	return c.doTokenRequest(ctx, tokenEndpoint, data)
}

// RefreshToken refreshes an access token using a refresh token.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	tokenEndpoint := strings.TrimSuffix(c.config.Issuer, "/") + "/token"

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	return c.doTokenRequest(ctx, tokenEndpoint, data)
}

// GetUserInfo retrieves user information using an access token.
func (c *Client) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	userinfoEndpoint := strings.TrimSuffix(c.config.Issuer, "/") + "/userinfo"

	req, err := http.NewRequestWithContext(ctx, "GET", userinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo returned status %d", resp.StatusCode)
	}

	var info UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding userinfo: %w", err)
	}

	return &info, nil
}

// IntrospectToken performs token introspection (RFC 7662).
func (c *Client) IntrospectToken(ctx context.Context, token string) (map[string]interface{}, error) {
	introspectEndpoint := strings.TrimSuffix(c.config.Issuer, "/") + "/introspect"

	data := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, "POST", introspectEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if c.config.ClientSecret != "" {
		req.SetBasicAuth(c.config.ClientID, c.config.ClientSecret)
	} else {
		data.Set("client_id", c.config.ClientID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// RevokeToken revokes a token (RFC 7009).
func (c *Client) RevokeToken(ctx context.Context, token string) error {
	revokeEndpoint := strings.TrimSuffix(c.config.Issuer, "/") + "/revoke"

	data := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, "POST", revokeEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if c.config.ClientSecret != "" {
		req.SetBasicAuth(c.config.ClientID, c.config.ClientSecret)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (c *Client) doTokenRequest(ctx context.Context, endpoint string, data url.Values) (*TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if c.config.ClientSecret != "" {
		req.SetBasicAuth(c.config.ClientID, c.config.ClientSecret)
	} else {
		data.Set("client_id", c.config.ClientID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		json.Unmarshal(body, &errResp)
		if errResp.Error != "" {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}

	return &tokenResp, nil
}
