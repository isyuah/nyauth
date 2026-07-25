package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

var ErrInvalidClient = errors.New("invalid OAuth client")

type Service struct{ store *Store }

func NewService(store *Store) *Service { return &Service{store: store} }

func validateRedirectURI(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%w: invalid redirect URI", ErrInvalidClient)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("%w: redirect URI must use HTTPS except for loopback development clients", ErrInvalidClient)
}
func validateRequest(req models.CreateClientRequest) error {
	if strings.TrimSpace(req.Name) == "" || len(req.Name) > 128 {
		return fmt.Errorf("%w: client name is required", ErrInvalidClient)
	}
	if len(req.RedirectURIs) == 0 {
		return fmt.Errorf("%w: at least one redirect URI is required", ErrInvalidClient)
	}
	for _, value := range append(append([]string{}, req.RedirectURIs...), req.PostLogoutRedirectURIs...) {
		if err := validateRedirectURI(value); err != nil {
			return err
		}
	}
	if len(req.Grants) == 0 {
		return fmt.Errorf("%w: at least one grant is required", ErrInvalidClient)
	}
	seen := map[string]bool{}
	for _, grant := range req.Grants {
		if seen[grant] {
			return fmt.Errorf("%w: duplicate grant", ErrInvalidClient)
		}
		seen[grant] = true
		switch grant {
		case models.GrantAuthorizationCode, models.GrantClientCredentials, models.GrantRefreshToken:
		default:
			return fmt.Errorf("%w: unsupported grant %q", ErrInvalidClient, grant)
		}
	}
	if req.IsPublic && seen[models.GrantClientCredentials] {
		return fmt.Errorf("%w: public clients cannot use client_credentials", ErrInvalidClient)
	}
	if seen[models.GrantRefreshToken] && !seen[models.GrantAuthorizationCode] {
		return fmt.Errorf("%w: refresh_token requires authorization_code", ErrInvalidClient)
	}
	return nil
}
func (s *Service) buildClient(req models.CreateClientRequest) (*models.OAuthClient, string, error) {
	if req.Grants == nil {
		req.Grants = []string{models.GrantAuthorizationCode}
	}
	if req.Scopes == nil {
		req.Scopes = []string{"openid", "profile", "email"}
	}
	if req.PostLogoutRedirectURIs == nil {
		req.PostLogoutRedirectURIs = []string{}
	}
	if err := validateRequest(req); err != nil {
		return nil, "", err
	}
	id, err := crypto.GenerateClientID()
	if err != nil {
		return nil, "", fmt.Errorf("generating client ID: %w", err)
	}
	secret := ""
	var secretHash *string
	if !req.IsPublic {
		secret, err = crypto.GenerateClientSecret()
		if err != nil {
			return nil, "", fmt.Errorf("generating client secret: %w", err)
		}
		hash := crypto.HashClientSecret(secret)
		secretHash = &hash
	}
	c := &models.OAuthClient{ID: id, SecretHash: secretHash, Name: strings.TrimSpace(req.Name), RedirectURIs: req.RedirectURIs, PostLogoutRedirectURIs: req.PostLogoutRedirectURIs, Grants: req.Grants, Scopes: req.Scopes, IsPublic: req.IsPublic, Metadata: req.Metadata}
	if c.Metadata == nil {
		c.Metadata = map[string]string{}
	}
	return c, secret, nil
}
func response(c *models.OAuthClient, secret string) *models.CreateClientResponse {
	return &models.CreateClientResponse{OAuthClient: *c, Secret: secret}
}
func (s *Service) Create(ctx context.Context, req models.CreateClientRequest) (*models.CreateClientResponse, error) {
	c, secret, err := s.buildClient(req)
	if err != nil {
		return nil, err
	}
	if err := s.store.Create(ctx, c); err != nil {
		return nil, err
	}
	return response(c, secret), nil
}
func (s *Service) CreateForOwner(ctx context.Context, ownerID string, limit int, req models.CreateClientRequest) (*models.CreateClientResponse, error) {
	c, secret, err := s.buildClient(req)
	if err != nil {
		return nil, err
	}
	if err := s.store.CreateForOwner(ctx, c, ownerID, limit); err != nil {
		return nil, err
	}
	return response(c, secret), nil
}
func (s *Service) GetByID(ctx context.Context, id string) (*models.OAuthClient, error) {
	return s.store.GetByID(ctx, id)
}
func (s *Service) Update(ctx context.Context, id string, req models.UpdateClientRequest) (*models.OAuthClient, error) {
	c, err := s.store.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if req.IsPublic != nil && *req.IsPublic != c.IsPublic {
		return nil, fmt.Errorf("%w: client type cannot be changed", ErrInvalidClient)
	}
	if req.Name != nil {
		c.Name = strings.TrimSpace(*req.Name)
	}
	if req.RedirectURIs != nil {
		c.RedirectURIs = req.RedirectURIs
	}
	if req.PostLogoutRedirectURIs != nil {
		c.PostLogoutRedirectURIs = req.PostLogoutRedirectURIs
	}
	if req.Grants != nil {
		c.Grants = req.Grants
	}
	if req.Scopes != nil {
		c.Scopes = req.Scopes
	}
	if req.Metadata != nil {
		c.Metadata = req.Metadata
	}
	check := models.CreateClientRequest{Name: c.Name, RedirectURIs: c.RedirectURIs, PostLogoutRedirectURIs: c.PostLogoutRedirectURIs, Grants: c.Grants, Scopes: c.Scopes, IsPublic: c.IsPublic, Metadata: c.Metadata}
	if err := validateRequest(check); err != nil {
		return nil, err
	}
	if err := s.store.Update(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}
func (s *Service) Delete(ctx context.Context, id string) error { return s.store.Delete(ctx, id) }
func (s *Service) List(ctx context.Context, page, pageSize int) (*models.PaginatedResponse[models.OAuthClient], error) {
	return s.store.List(ctx, models.NewPagination(page, pageSize))
}
func (s *Service) AuthenticateClient(ctx context.Context, id, secret string) (*models.OAuthClient, error) {
	return s.store.AuthenticateClient(ctx, id, secret)
}
func (s *Service) ListByOwner(ctx context.Context, ownerID string, page, pageSize int) (*models.PaginatedResponse[models.OAuthClient], error) {
	return s.store.ListByOwner(ctx, ownerID, models.NewPagination(page, pageSize))
}
func (s *Service) CountByOwner(ctx context.Context, ownerID string) (int64, error) {
	return s.store.CountByOwner(ctx, ownerID)
}
func (s *Service) GetStore() *Store  { return s.store }
func IsInvalidClient(err error) bool { return errors.Is(err, ErrInvalidClient) }
