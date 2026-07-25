package user

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrInvalidInput        = errors.New("invalid input")
	ErrPasswordUnavailable = errors.New("password login is not available for this account")
)

type serviceStore interface {
	Create(ctx context.Context, u *models.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	UpdateSelf(ctx context.Context, id uuid.UUID, req models.UpdateUserRequest) (*models.User, error)
	UpdateAdmin(ctx context.Context, id uuid.UUID, req models.AdminUpdateUserRequest) (*models.User, error)
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string, mustChange bool) (*models.User, error)
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, p models.Pagination, search string) (*models.PaginatedResponse[models.User], error)
	RecordLogin(ctx context.Context, id uuid.UUID, ip string) error
	Count(ctx context.Context) (int64, error)
	BootstrapAdmin(ctx context.Context, u *models.User) (bool, error)
}

type Service struct{ store serviceStore }

func NewService(store *Store) *Service { return &Service{store: store} }

func validateUsername(username string) error {
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 64 {
		return fmt.Errorf("%w: username must be 3 to 64 characters", ErrInvalidInput)
	}
	for _, r := range username {
		if !(r == '_' || r == '-' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return fmt.Errorf("%w: username contains unsupported characters", ErrInvalidInput)
		}
	}
	return nil
}

func validateEmail(email string) error {
	if email == "" {
		return nil
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || !strings.EqualFold(parsed.Address, email) {
		return fmt.Errorf("%w: invalid email address", ErrInvalidInput)
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 12 || len(password) > 1024 {
		return fmt.Errorf("%w: password must be 12 to 1024 characters", ErrInvalidInput)
	}
	return nil
}

func (s *Service) Create(ctx context.Context, req models.CreateUserRequest) (*models.User, error) {
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	if err := validateUsername(req.Username); err != nil {
		return nil, err
	}
	if err := validateEmail(req.Email); err != nil {
		return nil, err
	}
	if err := validatePassword(req.Password); err != nil {
		return nil, err
	}
	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}
	u := &models.User{
		ID: uuid.New(), Username: req.Username, PasswordHash: &hash,
		Status: models.UserStatusActive, Role: "user", AuthVersion: 1,
		Metadata: req.Metadata,
	}
	if req.Email != "" {
		u.Email = &req.Email
	}
	if req.DisplayName != "" {
		u.DisplayName = &req.DisplayName
	}
	if err := s.store.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return s.store.GetByID(ctx, id)
}

func (s *Service) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	return s.store.GetByUsername(ctx, username)
}

func (s *Service) Update(ctx context.Context, id uuid.UUID, req models.UpdateUserRequest) (*models.User, error) {
	if req.Email != nil {
		trimmed := strings.TrimSpace(*req.Email)
		if err := validateEmail(trimmed); err != nil {
			return nil, err
		}
		req.Email = &trimmed
	}
	return s.store.UpdateSelf(ctx, id, req)
}

func (s *Service) AdminUpdate(ctx context.Context, id uuid.UUID, req models.AdminUpdateUserRequest) (*models.User, error) {
	if req.Email != nil {
		trimmed := strings.TrimSpace(*req.Email)
		if err := validateEmail(trimmed); err != nil {
			return nil, err
		}
		req.Email = &trimmed
	}
	if req.Status != nil && *req.Status != models.UserStatusActive && *req.Status != models.UserStatusSuspended && *req.Status != models.UserStatusPending {
		return nil, fmt.Errorf("%w: invalid user status", ErrInvalidInput)
	}
	if req.Role != nil && *req.Role != "admin" && *req.Role != "user" {
		return nil, fmt.Errorf("%w: invalid user role", ErrInvalidInput)
	}
	return s.store.UpdateAdmin(ctx, id, req)
}

func (s *Service) ResetPassword(ctx context.Context, id uuid.UUID, newPassword string) (*models.User, error) {
	if err := validatePassword(newPassword); err != nil {
		return nil, err
	}
	hash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}
	return s.store.UpdatePassword(ctx, id, hash, true)
}

func (s *Service) ChangePassword(ctx context.Context, id uuid.UUID, currentPassword, newPassword string) (*models.User, error) {
	if err := validatePassword(newPassword); err != nil {
		return nil, err
	}
	u, err := s.store.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if u.PasswordHash == nil {
		return nil, ErrPasswordUnavailable
	}
	ok, err := crypto.VerifyPassword(currentPassword, *u.PasswordHash)
	if err != nil || !ok {
		return nil, ErrInvalidCredentials
	}
	hash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}
	return s.store.UpdatePassword(ctx, id, hash, false)
}

func (s *Service) Delete(ctx context.Context, id uuid.UUID) error { return s.store.Delete(ctx, id) }

func (s *Service) List(ctx context.Context, page, pageSize int, search string) (*models.PaginatedResponse[models.User], error) {
	return s.store.List(ctx, models.NewPagination(page, pageSize), search)
}

func (s *Service) Authenticate(ctx context.Context, username, password string) (*models.User, error) {
	u, lookupErr := s.store.GetByUsername(ctx, strings.TrimSpace(username))
	hash := crypto.DummyPasswordHash
	if lookupErr == nil && u.PasswordHash != nil {
		hash = *u.PasswordHash
	}
	ok, verifyErr := crypto.VerifyPassword(password, hash)
	if lookupErr != nil || verifyErr != nil || !ok || u == nil || u.PasswordHash == nil || u.Status != models.UserStatusActive {
		return nil, ErrInvalidCredentials
	}
	return u, nil
}

func (s *Service) RecordLogin(ctx context.Context, id uuid.UUID, ip string) error {
	return s.store.RecordLogin(ctx, id, ip)
}

type BootstrapResult struct {
	Created           bool
	GeneratedPassword string
}

// BootstrapInitialAdmin creates an administrator only when the users table is empty.
func (s *Service) BootstrapInitialAdmin(ctx context.Context, username, configuredPassword, email string) (*BootstrapResult, error) {
	// This check is intentionally non-authoritative: it avoids random-number
	// generation, validation, and Argon2 work on every normal restart. The
	// locked BootstrapAdmin transaction remains the final concurrency arbiter.
	count, err := s.store.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking for existing users: %w", err)
	}
	if count != 0 {
		return &BootstrapResult{}, nil
	}
	if username == "" {
		username = "admin"
	}
	username = strings.TrimSpace(username)
	email = strings.TrimSpace(email)
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	if err := validateEmail(email); err != nil {
		return nil, err
	}
	password := configuredPassword
	generated := ""
	if password == "" {
		var err error
		password, err = crypto.GenerateRandomString(32)
		if err != nil {
			return nil, fmt.Errorf("generating bootstrap password: %w", err)
		}
		generated = password
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hashing bootstrap password: %w", err)
	}
	displayName := "Administrator"
	u := &models.User{ID: uuid.New(), Username: username, Email: nil, PasswordHash: &hash, DisplayName: &displayName, Status: models.UserStatusActive, Role: "admin", AuthVersion: 1, MustChangePassword: true, Metadata: map[string]string{}}
	if email != "" {
		u.Email = &email
	}
	created, err := s.store.BootstrapAdmin(ctx, u)
	if err != nil {
		return nil, err
	}
	if !created {
		generated = ""
	}
	return &BootstrapResult{Created: created, GeneratedPassword: generated}, nil
}

func IsInvalidInput(err error) bool { return errors.Is(err, ErrInvalidInput) }
