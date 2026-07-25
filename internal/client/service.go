package client

import (
	"context"
	"fmt"

	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

// Service handles client business logic.
type Service struct {
	store *Store
}

// NewService creates a new client service.
func NewService(store *Store) *Service {
	return &Service{store: store}
}

// Create creates a new client and returns the plaintext secret.
func (s *Service) Create(ctx context.Context, req models.CreateClientRequest) (*models.CreateClientResponse, error) {
	clientID, err := crypto.GenerateClientID()
	if err != nil {
		return nil, fmt.Errorf("generating client ID: %w", err)
	}

	clientSecret, err := crypto.GenerateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("generating client secret: %w", err)
	}

	secretHash, err := crypto.HashPassword(clientSecret)
	if err != nil {
		return nil, fmt.Errorf("hashing client secret: %w", err)
	}

	if req.Grants == nil {
		req.Grants = []string{models.GrantAuthorizationCode}
	}
	if req.Scopes == nil {
		req.Scopes = []string{"openid", "profile", "email"}
	}

	client := &models.OAuthClient{
		ID:           clientID,
		SecretHash:   &secretHash,
		Name:         req.Name,
		RedirectURIs: req.RedirectURIs,
		Grants:       req.Grants,
		Scopes:       req.Scopes,
		IsPublic:     req.IsPublic,
		Metadata:     req.Metadata,
	}

	if req.IsPublic {
		client.SecretHash = nil // public clients don't have secrets
	}

	if err := s.store.Create(ctx, client); err != nil {
		return nil, err
	}

	resp := &models.CreateClientResponse{
		OAuthClient: *client,
	}
	if !req.IsPublic {
		resp.Secret = clientSecret
	}
	return resp, nil
}

// GetByID retrieves a client by ID.
func (s *Service) GetByID(ctx context.Context, id string) (*models.OAuthClient, error) {
	return s.store.GetByID(ctx, id)
}

// Update updates a client.
func (s *Service) Update(ctx context.Context, id string, req models.UpdateClientRequest) (*models.OAuthClient, error) {
	client, err := s.store.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if req.Name != nil {
		client.Name = *req.Name
	}
	if req.RedirectURIs != nil {
		client.RedirectURIs = req.RedirectURIs
	}
	if req.Grants != nil {
		client.Grants = req.Grants
	}
	if req.Scopes != nil {
		client.Scopes = req.Scopes
	}
	if req.IsPublic != nil {
		client.IsPublic = *req.IsPublic
	}
	if req.Metadata != nil {
		client.Metadata = req.Metadata
	}

	if err := s.store.Update(ctx, client); err != nil {
		return nil, err
	}
	return client, nil
}

// Delete deletes a client.
func (s *Service) Delete(ctx context.Context, id string) error {
	return s.store.Delete(ctx, id)
}

// List retrieves clients with pagination.
func (s *Service) List(ctx context.Context, page, pageSize int) (*models.PaginatedResponse[models.OAuthClient], error) {
	p := models.NewPagination(page, pageSize)
	return s.store.List(ctx, p)
}

// AuthenticateClient verifies client credentials.
func (s *Service) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (*models.OAuthClient, error) {
	return s.store.AuthenticateClient(ctx, clientID, clientSecret)
}

// ListByOwner retrieves clients owned by a specific user.
func (s *Service) ListByOwner(ctx context.Context, ownerID string, page, pageSize int) (*models.PaginatedResponse[models.OAuthClient], error) {
	p := models.NewPagination(page, pageSize)
	return s.store.ListByOwner(ctx, ownerID, p)
}

// CountByOwner counts how many clients a user owns.
func (s *Service) CountByOwner(ctx context.Context, ownerID string) (int64, error) {
	return s.store.CountByOwner(ctx, ownerID)
}

// GetStore returns the underlying store (for direct access when needed).
func (s *Service) GetStore() *Store {
	return s.store
}
