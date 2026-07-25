package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/nyasharp/nyauth/pkg/models"
)

// Provider is the interface that all external OAuth providers implement.
type Provider interface {
	Name() string
	Type() string
	GetAuthorizationURL(state string, redirectURI string) string
	ExchangeCode(ctx context.Context, code string, redirectURI string) (*TokenResponse, error)
	GetUserInfo(ctx context.Context, token *TokenResponse) (*models.ExternalUser, error)
}

// TokenResponse holds the token data from a provider.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
}

// GitHub implements the GitHub OAuth provider.
type GitHub struct {
	name         string
	clientID     string
	clientSecret string
	scopes       []string
}

func NewGitHub(name, clientID, clientSecret string, scopes []string) *GitHub {
	if len(scopes) == 0 {
		scopes = []string{"user:email"}
	}
	return &GitHub{name: name, clientID: clientID, clientSecret: clientSecret, scopes: scopes}
}

func (g *GitHub) Name() string { return g.name }
func (g *GitHub) Type() string { return "github" }

func (g *GitHub) GetAuthorizationURL(state, redirectURI string) string {
	params := url.Values{
		"client_id":     {g.clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {strings.Join(g.scopes, " ")},
		"state":         {state},
		"response_type": {"code"},
	}
	return "https://github.com/login/oauth/authorize?" + params.Encode()
}

func (g *GitHub) ExchangeCode(ctx context.Context, code, redirectURI string) (*TokenResponse, error) {
	data := url.Values{
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://github.com/login/oauth/access_token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

func (g *GitHub) GetUserInfo(ctx context.Context, token *TokenResponse) (*models.ExternalUser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var user struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
		Name      string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &models.ExternalUser{
		Provider:  g.name,
		ID:        fmt.Sprintf("%d", user.ID),
		Username:  user.Login,
		Email:     user.Email,
		AvatarURL: user.AvatarURL,
	}, nil
}

// Google implements the Google OIDC provider.
type Google struct {
	name         string
	clientID     string
	clientSecret string
	scopes       []string
}

func NewGoogle(name, clientID, clientSecret string, scopes []string) *Google {
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	return &Google{name: name, clientID: clientID, clientSecret: clientSecret, scopes: scopes}
}

func (g *Google) Name() string { return g.name }
func (g *Google) Type() string { return "google" }

func (g *Google) GetAuthorizationURL(state, redirectURI string) string {
	params := url.Values{
		"client_id":     {g.clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {strings.Join(g.scopes, " ")},
		"state":         {state},
		"response_type": {"code"},
		"access_type":   {"offline"},
		"prompt":        {"consent"},
	}
	return "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
}

func (g *Google) ExchangeCode(ctx context.Context, code, redirectURI string) (*TokenResponse, error) {
	data := url.Values{
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectURI},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://oauth2.googleapis.com/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

func (g *Google) GetUserInfo(ctx context.Context, token *TokenResponse) (*models.ExternalUser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var user struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &models.ExternalUser{
		Provider:  g.name,
		ID:        user.ID,
		Username:  user.Email,
		Email:     user.Email,
		AvatarURL: user.Picture,
	}, nil
}
