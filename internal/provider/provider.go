package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nyasharp/nyauth/pkg/models"
	"golang.org/x/oauth2"
)

const maxProviderResponseSize = 1 << 20

// Provider completes an upstream authentication flow and returns only verified
// identity data. Provider tokens never escape this boundary.
type Provider interface {
	Name() string
	Type() string
	AuthorizationURL(state, nonce, redirectURI string) string
	Authenticate(ctx context.Context, code, redirectURI, nonce string) (*models.ExternalUser, error)
}

// GitHub implements the GitHub OAuth provider.
type GitHub struct {
	name         string
	clientID     string
	clientSecret string
	scopes       []string
	authURL      string
	tokenURL     string
	userURL      string
	emailsURL    string
	client       *http.Client
}

func NewGitHub(name, clientID, clientSecret string, scopes []string) *GitHub {
	return NewGitHubWithMode(name, clientID, clientSecret, scopes, false)
}

// NewGitHubWithMode applies the production provider network policy to every
// GitHub token and userinfo request.
func NewGitHubWithMode(name, clientID, clientSecret string, scopes []string, production bool) *GitHub {
	return newGitHub(name, clientID, clientSecret, scopes,
		"https://github.com/login/oauth/authorize",
		"https://github.com/login/oauth/access_token",
		"https://api.github.com/user",
		"https://api.github.com/user/emails",
		newProviderHTTPClient(production),
	)
}

func newGitHub(name, clientID, clientSecret string, scopes []string, authURL, tokenURL, userURL, emailsURL string, client *http.Client) *GitHub {
	if len(scopes) == 0 {
		scopes = []string{"user:email"}
	}
	return &GitHub{
		name: name, clientID: clientID, clientSecret: clientSecret,
		scopes: append([]string(nil), scopes...), authURL: authURL,
		tokenURL: tokenURL, userURL: userURL, emailsURL: emailsURL, client: client,
	}
}

func (g *GitHub) Name() string { return g.name }
func (g *GitHub) Type() string { return "github" }

func (g *GitHub) AuthorizationURL(state, _ string, redirectURI string) string {
	return g.oauthConfig(redirectURI).AuthCodeURL(state)
}

func (g *GitHub) Authenticate(ctx context.Context, code, redirectURI, _ string) (*models.ExternalUser, error) {
	if strings.TrimSpace(code) == "" {
		return nil, errors.New("authorization code is required")
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, g.client)
	token, err := g.oauthConfig(redirectURI).Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchanging GitHub authorization code: %w", err)
	}
	if token == nil || strings.TrimSpace(token.AccessToken) == "" {
		return nil, errors.New("GitHub token response did not include an access token")
	}

	var profile struct {
		ID        json.Number `json:"id"`
		Login     string      `json:"login"`
		AvatarURL string      `json:"avatar_url"`
		Name      string      `json:"name"`
	}
	if err := g.getJSON(ctx, g.userURL, token.AccessToken, &profile); err != nil {
		return nil, fmt.Errorf("fetching GitHub user: %w", err)
	}
	externalID := profile.ID.String()
	if externalID == "" || externalID == "0" || strings.TrimSpace(profile.Login) == "" {
		return nil, errors.New("GitHub user response is missing a stable user ID or login")
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := g.getJSON(ctx, g.emailsURL, token.AccessToken, &emails); err != nil {
		return nil, fmt.Errorf("fetching GitHub verified emails: %w", err)
	}
	verifiedEmail := ""
	for _, email := range emails {
		if email.Verified && strings.TrimSpace(email.Email) != "" {
			if verifiedEmail == "" || email.Primary {
				verifiedEmail = email.Email
			}
			if email.Primary {
				break
			}
		}
	}

	return &models.ExternalUser{
		Provider: g.name, ID: externalID, Username: profile.Login,
		Email: verifiedEmail, EmailVerified: verifiedEmail != "", AvatarURL: profile.AvatarURL,
	}, nil
}

func (g *GitHub) oauthConfig(redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID: g.clientID, ClientSecret: g.clientSecret, RedirectURL: redirectURI,
		Scopes:   g.scopes,
		Endpoint: oauth2.Endpoint{AuthURL: g.authURL, TokenURL: g.tokenURL, AuthStyle: oauth2.AuthStyleInParams},
	}
}

func (g *GitHub) getJSON(ctx context.Context, endpoint, accessToken string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeProviderJSON(resp, target)
}

// Google is Google's OIDC profile backed by the same strict ID-token verifier
// used for generic OIDC providers.
type Google struct {
	*GenericOIDC
}

func NewGoogle(name, clientID, clientSecret string, scopes []string) *Google {
	return NewGoogleWithMode(name, clientID, clientSecret, scopes, false)
}

// NewGoogleWithMode applies the production provider network policy to token,
// userinfo, and remote JWK requests.
func NewGoogleWithMode(name, clientID, clientSecret string, scopes []string, production bool) *Google {
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	return &Google{GenericOIDC: newConfiguredOIDC(
		name, clientID, clientSecret, scopes,
		"https://accounts.google.com",
		"https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token",
		"https://openidconnect.googleapis.com/v1/userinfo",
		"https://www.googleapis.com/oauth2/v3/certs",
		[]string{"RS256"}, newProviderHTTPClient(production),
	)}
}

func (g *Google) Type() string { return "google" }

func decodeProviderJSON(resp *http.Response, target any) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponseSize+1))
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	if len(body) > maxProviderResponseSize {
		return errors.New("provider response exceeds size limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("provider returned HTTP %d", resp.StatusCode)
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decoding provider response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("provider response contains trailing JSON data")
	}
	return nil
}

func newProviderHTTPClient(production bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if production {
		transport.Proxy = nil
		transport.DialContext = secureDialContext
	}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many provider redirects")
			}
			if production && req.URL.Scheme != "https" {
				return errors.New("provider redirect must use HTTPS")
			}
			return nil
		},
	}
}
