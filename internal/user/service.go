package user

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

// Service handles user business logic.
type Service struct {
	store *Store
}

// NewService creates a new user service.
func NewService(store *Store) *Service {
	return &Service{store: store}
}

// Create creates a new user with a hashed password.
func (s *Service) Create(ctx context.Context, req models.CreateUserRequest) (*models.User, error) {
	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	user := &models.User{
		ID:           uuid.New(),
		Username:     req.Username,
		Email:        nil,
		PasswordHash: hash,
		DisplayName:  nil,
		Status:       models.UserStatusActive,
		Role:         "user",
		Metadata:     req.Metadata,
	}

	if req.Email != "" {
		user.Email = &req.Email
	}
	if req.DisplayName != "" {
		user.DisplayName = &req.DisplayName
	}

	if err := s.store.Create(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

// GetByID retrieves a user by ID.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return s.store.GetByID(ctx, id)
}

// GetByUsername retrieves a user by username.
func (s *Service) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	return s.store.GetByUsername(ctx, username)
}

// Update updates a user.
func (s *Service) Update(ctx context.Context, id uuid.UUID, req models.UpdateUserRequest) (*models.User, error) {
	user, err := s.store.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if req.Email != nil {
		user.Email = req.Email
	}
	if req.DisplayName != nil {
		user.DisplayName = req.DisplayName
	}
	if req.AvatarURL != nil {
		user.AvatarURL = req.AvatarURL
	}
	if req.Status != nil {
		user.Status = *req.Status
	}
	if req.Metadata != nil {
		user.Metadata = req.Metadata
	}

	if err := s.store.Update(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

// ResetPassword resets a user's password.
func (s *Service) ResetPassword(ctx context.Context, id uuid.UUID, newPassword string) error {
	hash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}
	return s.store.UpdatePassword(ctx, id, hash)
}

// Delete deletes a user.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	return s.store.Delete(ctx, id)
}

// List retrieves users with pagination and optional search.
func (s *Service) List(ctx context.Context, page, pageSize int, search string) (*models.PaginatedResponse[models.User], error) {
	p := models.NewPagination(page, pageSize)
	return s.store.List(ctx, p, search)
}

// Authenticate verifies username/password and returns the user.
func (s *Service) Authenticate(ctx context.Context, username, password string) (*models.User, error) {
	user, err := s.store.GetByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if user.Status != models.UserStatusActive {
		return nil, fmt.Errorf("account is %s", user.Status)
	}

	ok, err := crypto.VerifyPassword(password, user.PasswordHash)
	if err != nil || !ok {
		return nil, fmt.Errorf("invalid credentials")
	}

	return user, nil
}

// RecordLogin updates the user's last login time and IP.
func (s *Service) RecordLogin(ctx context.Context, id uuid.UUID, ip string) error {
	return s.store.RecordLogin(ctx, id, ip)
}

// CreateInitialAdmin creates the initial admin user if it doesn't exist.
func (s *Service) CreateInitialAdmin(ctx context.Context, username, password, email string) error {
	_, err := s.store.GetByUsername(ctx, username)
	if err == nil {
		return nil // admin already exists
	}

	u, err := s.Create(ctx, models.CreateUserRequest{
		Username:    username,
		Email:       email,
		Password:    password,
		DisplayName: "Administrator",
	})
	if err != nil {
		return err
	}
	// Set role to admin
	u.Role = "admin"
	_ = s.store.Update(ctx, u)
	return nil
}
