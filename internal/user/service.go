package user

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/passwordpolicy"
	"github.com/nyasharp/nyauth/internal/registration"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrInvalidInput        = errors.New("invalid input")
	ErrPasswordUnavailable = errors.New("password login is not available for this account")
	ErrPasswordConfigured  = errors.New("a local password is already configured")
	ErrAuthStateChanged    = errors.New("authentication state changed")
	ErrInviteInvalid       = registration.ErrInviteInvalid
	// ErrEmailVerificationPending is returned only after the supplied
	// credentials verified correctly, so revealing it is safe and actionable.
	ErrEmailVerificationPending = errors.New("email verification is required before signing in")
)

type serviceStore interface {
	Create(ctx context.Context, u *models.User) error
	CreateRegistration(ctx context.Context, u *models.User, options RegistrationCommitOptions) (*uuid.UUID, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	UpdateSelf(ctx context.Context, id uuid.UUID, req models.UpdateUserRequest) (*models.User, error)
	UpdateAdmin(ctx context.Context, id uuid.UUID, req models.AdminUpdateUserRequest, mutation audit.MutationAudit) (*models.User, error)
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string, mustChange bool, mutation audit.MutationAudit) (*models.User, error)
	ResetPassword(ctx context.Context, id uuid.UUID, passwordHash string, mutation audit.MutationAudit) (*models.User, error)
	SetPasswordIfMissing(ctx context.Context, id uuid.UUID, passwordHash string, mutation audit.MutationAudit) (*models.User, error)
	RevokeSessions(ctx context.Context, id uuid.UUID, mutation audit.MutationAudit) (int64, error)
	Delete(ctx context.Context, id uuid.UUID, mutation audit.MutationAudit) error
	List(ctx context.Context, p models.Pagination, search string, status models.UserStatus) (*models.PaginatedResponse[models.User], error)
	RecordLogin(ctx context.Context, id uuid.UUID, ip string) error
	RecordAuthentication(ctx context.Context, id uuid.UUID, authVersion, sessionVersion int64) (*models.User, error)
	Count(ctx context.Context) (int64, error)
	BootstrapAdmin(ctx context.Context, u *models.User) (bool, error)
}

type Service struct{ store serviceStore }

type RegistrationCommitOptions struct {
	InviteCodeHash *string
	ExpiresAt      time.Time
	Now            time.Time
	Registration   settings.Registration
	MailGate       runtimecoord.MailDeliveryGate
	Audit          registration.AuditContext
	Verification   *account.PreparedActionEmail
}

type RegisterOptions struct {
	PendingVerification bool
	InviteCodeHash      *string
	ExpiresAt           time.Time
	Now                 time.Time
	Registration        settings.Registration
	MailGate            runtimecoord.MailDeliveryGate
	Audit               registration.AuditContext
	PrepareVerification func(*models.User) (*account.PreparedActionEmail, error)
}

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
	if err := passwordpolicy.Validate(password); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidInput, err)
	}
	return nil
}

func (s *Service) Create(ctx context.Context, req models.CreateUserRequest) (*models.User, error) {
	u, err := buildLocalUser(req)
	if err != nil {
		return nil, err
	}
	if err := s.store.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

type adminCreateStore interface {
	CreateAdmin(ctx context.Context, u *models.User, mutation audit.MutationAudit) error
}

func (s *Service) CreateAdmin(ctx context.Context, req models.CreateUserRequest, mutation audit.MutationAudit) (*models.User, error) {
	if err := mutation.ValidateEvent(models.AuditUserCreated); err != nil {
		return nil, fmt.Errorf("%w: invalid user creation audit context", ErrInvalidInput)
	}
	u, err := buildLocalUser(req)
	if err != nil {
		return nil, err
	}
	store, ok := s.store.(adminCreateStore)
	if !ok {
		return nil, fmt.Errorf("administrator user creation is unavailable")
	}
	if err := store.CreateAdmin(ctx, u, mutation); err != nil {
		return nil, err
	}
	return u, nil
}

func buildLocalUser(req models.CreateUserRequest) (*models.User, error) {
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
		Status: models.UserStatusActive, Role: "user", AuthVersion: 1, SessionVersion: 1,
		Metadata: req.Metadata,
	}
	if u.Metadata == nil {
		// users.metadata is NOT NULL; an omitted metadata field must not
		// become a SQL NULL.
		u.Metadata = map[string]string{}
	}
	if req.Email != "" {
		u.Email = &req.Email
	}
	if req.DisplayName != "" {
		u.DisplayName = &req.DisplayName
	}
	return u, nil
}

// ValidateRegistration runs the registration field validations without side
// effects so callers can fail fast before consuming an invite.
func (s *Service) ValidateRegistration(req models.RegisterRequest) error {
	username := strings.TrimSpace(req.Username)
	email := strings.TrimSpace(req.Email)
	if err := validateUsername(username); err != nil {
		return err
	}
	if email == "" {
		return fmt.Errorf("%w: email is required", ErrInvalidInput)
	}
	if err := validateEmail(email); err != nil {
		return err
	}
	return validatePassword(req.Password)
}

// Register creates a self-registered account. Email is mandatory because it
// is the recovery anchor; the account starts pending when verification is
// required and only becomes active after the emailed confirmation.
func (s *Service) Register(ctx context.Context, req models.RegisterRequest, options RegisterOptions) (*models.User, *uuid.UUID, error) {
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	if err := validateUsername(req.Username); err != nil {
		return nil, nil, err
	}
	if req.Email == "" {
		return nil, nil, fmt.Errorf("%w: email is required", ErrInvalidInput)
	}
	if err := validateEmail(req.Email); err != nil {
		return nil, nil, err
	}
	if err := validatePassword(req.Password); err != nil {
		return nil, nil, err
	}
	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("hashing password: %w", err)
	}
	status := models.UserStatusActive
	if options.PendingVerification {
		status = models.UserStatusPending
	}
	u := &models.User{
		ID: uuid.New(), Username: req.Username, Email: &req.Email, PasswordHash: &hash,
		Status: status, Role: "user", AuthVersion: 1, SessionVersion: 1,
		Metadata: map[string]string{},
	}
	var verification *account.PreparedActionEmail
	if options.PendingVerification {
		if options.PrepareVerification == nil {
			return nil, nil, fmt.Errorf("preparing registration verification: verification builder is required")
		}
		verification, err = options.PrepareVerification(u)
		if err != nil {
			return nil, nil, fmt.Errorf("preparing registration verification: %w", err)
		}
	}
	inviteID, err := s.store.CreateRegistration(ctx, u, RegistrationCommitOptions{
		InviteCodeHash: options.InviteCodeHash,
		ExpiresAt:      options.ExpiresAt,
		Now:            options.Now,
		Registration:   options.Registration,
		MailGate:       options.MailGate,
		Audit:          options.Audit,
		Verification:   verification,
	})
	if err != nil {
		return nil, nil, err
	}
	return u, inviteID, nil
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

func (s *Service) AdminUpdate(ctx context.Context, id uuid.UUID, req models.AdminUpdateUserRequest, mutation audit.MutationAudit) (*models.User, error) {
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
	if err := validateAdminUpdateAudit(req, mutation); err != nil {
		return nil, err
	}
	return s.store.UpdateAdmin(ctx, id, req, mutation)
}

func validateAdminUpdateAudit(req models.AdminUpdateUserRequest, mutation audit.MutationAudit) error {
	profileFieldsPresent := req.Email != nil || req.DisplayName != nil || req.Metadata != nil
	switch mutation.Event {
	case models.AuditUserUpdated:
		if req.Role != nil || req.Status != nil {
			return fmt.Errorf("%w: role and status require their dedicated endpoints", ErrInvalidInput)
		}
	case models.AuditUserRoleChanged:
		if req.Role == nil || req.Status != nil || profileFieldsPresent {
			return fmt.Errorf("%w: role endpoint accepts only role", ErrInvalidInput)
		}
	case models.AuditUserSuspended:
		if req.Status == nil || *req.Status != models.UserStatusSuspended || req.Role != nil || profileFieldsPresent {
			return fmt.Errorf("%w: suspend endpoint accepts only suspended status", ErrInvalidInput)
		}
	case models.AuditUserActivated:
		if req.Status == nil || *req.Status != models.UserStatusActive || req.Role != nil || profileFieldsPresent {
			return fmt.Errorf("%w: activate endpoint accepts only active status", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("%w: invalid management audit event", ErrInvalidInput)
	}
	return nil
}

func (s *Service) ResetPassword(ctx context.Context, id uuid.UUID, newPassword string, mutation audit.MutationAudit) (*models.User, error) {
	if err := mutation.ValidateEvent(models.AuditUserPasswordReset); err != nil {
		return nil, fmt.Errorf("%w: invalid management audit event", ErrInvalidInput)
	}
	if err := validatePassword(newPassword); err != nil {
		return nil, err
	}
	hash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}
	return s.store.ResetPassword(ctx, id, hash, mutation)
}

func (s *Service) ChangePassword(ctx context.Context, id uuid.UUID, currentPassword, newPassword string, mutation audit.MutationAudit) (*models.User, error) {
	if err := mutation.ValidateEvent(models.AuditUserPasswordChanged); err != nil {
		return nil, fmt.Errorf("%w: invalid password-change audit event", ErrInvalidInput)
	}
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
	return s.store.UpdatePassword(ctx, id, hash, false, mutation)
}

// SetPassword adds the local-password capability to an external-only account.
// The handler must require recent authentication before calling this method.
func (s *Service) SetPassword(ctx context.Context, id uuid.UUID, newPassword string, mutation audit.MutationAudit) (*models.User, error) {
	if err := mutation.ValidateEvent(models.AuditUserPasswordSet); err != nil {
		return nil, fmt.Errorf("%w: invalid password-configuration audit event", ErrInvalidInput)
	}
	if err := validatePassword(newPassword); err != nil {
		return nil, err
	}
	u, err := s.store.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if u.PasswordHash != nil {
		return nil, ErrPasswordConfigured
	}
	hash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}
	return s.store.SetPasswordIfMissing(ctx, id, hash, mutation)
}

// VerifyPasswordForReauthentication verifies the local primary factor without
// yet marking the session as recently authenticated. MFA-enabled accounts use
// this before completing their second-factor challenge.
func (s *Service) VerifyPasswordForReauthentication(ctx context.Context, id uuid.UUID, password string) (*models.User, error) {
	u, err := s.store.GetByID(ctx, id)
	if err != nil || u == nil || u.Status != models.UserStatusActive {
		return nil, ErrInvalidCredentials
	}
	if u.PasswordHash == nil {
		return nil, ErrPasswordUnavailable
	}
	ok, verifyErr := crypto.VerifyPassword(password, *u.PasswordHash)
	if verifyErr != nil || !ok {
		return nil, ErrInvalidCredentials
	}
	return u, nil
}

// Reauthenticate verifies the existing local factor and records a fresh
// authentication instant without changing the password or login history.
func (s *Service) Reauthenticate(ctx context.Context, id uuid.UUID, password string) (*models.User, error) {
	verified, err := s.VerifyPasswordForReauthentication(ctx, id, password)
	if err != nil {
		return nil, err
	}
	return s.store.RecordAuthentication(ctx, id, verified.AuthVersion, verified.SessionVersion)
}

func (s *Service) RecordAuthentication(ctx context.Context, id uuid.UUID, authVersion, sessionVersion int64) (*models.User, error) {
	return s.store.RecordAuthentication(ctx, id, authVersion, sessionVersion)
}

func (s *Service) Delete(ctx context.Context, id uuid.UUID, mutation audit.MutationAudit) error {
	if err := mutation.ValidateEvent(models.AuditUserDeleted); err != nil {
		return fmt.Errorf("%w: invalid management audit event", ErrInvalidInput)
	}
	return s.store.Delete(ctx, id, mutation)
}

// RevokeSessions advances only the browser-session generation. OAuth tokens
// remain bound to auth_version and are intentionally unaffected.
func (s *Service) RevokeSessions(ctx context.Context, id uuid.UUID, mutation audit.MutationAudit) (int64, error) {
	if err := mutation.ValidateEvent(models.AuditUserSessionsRevoked); err != nil {
		return 0, fmt.Errorf("%w: invalid session-revocation audit event", ErrInvalidInput)
	}
	return s.store.RevokeSessions(ctx, id, mutation)
}

func (s *Service) List(ctx context.Context, page, pageSize int, search string, status models.UserStatus) (*models.PaginatedResponse[models.User], error) {
	if status != "" && status != models.UserStatusActive && status != models.UserStatusSuspended && status != models.UserStatusPending {
		return nil, fmt.Errorf("%w: invalid user status", ErrInvalidInput)
	}
	return s.store.List(ctx, models.NewPagination(page, pageSize), search, status)
}

func (s *Service) Authenticate(ctx context.Context, username, password string) (*models.User, error) {
	username = strings.TrimSpace(username)
	validUsername := validateUsername(username) == nil
	validPassword := passwordpolicy.Validate(password) == nil

	var u *models.User
	lookupErr := ErrInvalidCredentials
	if validUsername {
		u, lookupErr = s.store.GetByUsername(ctx, username)
	}
	hash := crypto.DummyPasswordHash
	if lookupErr == nil && u != nil && u.PasswordHash != nil {
		hash = *u.PasswordHash
	}
	candidate := password
	if !validPassword {
		candidate = "invalid-login-password"
	}
	ok, verifyErr := crypto.VerifyPassword(candidate, hash)
	if !validUsername || !validPassword || lookupErr != nil || verifyErr != nil || !ok || u == nil || u.PasswordHash == nil {
		return nil, ErrInvalidCredentials
	}
	if u.Status == models.UserStatusPending {
		return nil, ErrEmailVerificationPending
	}
	if u.Status != models.UserStatusActive {
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
	u := &models.User{ID: uuid.New(), Username: username, Email: nil, PasswordHash: &hash, DisplayName: &displayName, Status: models.UserStatusActive, Role: "admin", AuthVersion: 1, SessionVersion: 1, MustChangePassword: true, Metadata: map[string]string{}}
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
