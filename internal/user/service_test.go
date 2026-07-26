package user

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

type bootstrapStore struct {
	count           int64
	bootstrapCalled bool
}

func (s *bootstrapStore) Create(context.Context, *models.User) error { return errors.New("unused") }
func (s *bootstrapStore) GetByID(context.Context, uuid.UUID) (*models.User, error) {
	return nil, errors.New("unused")
}
func (s *bootstrapStore) GetByUsername(context.Context, string) (*models.User, error) {
	return nil, errors.New("unused")
}
func (s *bootstrapStore) UpdateSelf(context.Context, uuid.UUID, models.UpdateUserRequest) (*models.User, error) {
	return nil, errors.New("unused")
}
func (s *bootstrapStore) UpdateAdmin(context.Context, uuid.UUID, models.AdminUpdateUserRequest, audit.MutationAudit) (*models.User, error) {
	return nil, errors.New("unused")
}
func (s *bootstrapStore) UpdatePassword(context.Context, uuid.UUID, string, bool, audit.MutationAudit) (*models.User, error) {
	return nil, errors.New("unused")
}
func (s *bootstrapStore) ResetPassword(context.Context, uuid.UUID, string, audit.MutationAudit) (*models.User, error) {
	return nil, errors.New("unused")
}
func (s *bootstrapStore) SetPasswordIfMissing(context.Context, uuid.UUID, string, audit.MutationAudit) (*models.User, error) {
	return nil, errors.New("unused")
}
func (s *bootstrapStore) RevokeSessions(context.Context, uuid.UUID, audit.MutationAudit) (int64, error) {
	return 0, errors.New("unused")
}
func (s *bootstrapStore) Delete(context.Context, uuid.UUID, audit.MutationAudit) error {
	return errors.New("unused")
}
func (s *bootstrapStore) List(context.Context, models.Pagination, string, models.UserStatus) (*models.PaginatedResponse[models.User], error) {
	return nil, errors.New("unused")
}
func (s *bootstrapStore) RecordLogin(context.Context, uuid.UUID, string) error {
	return errors.New("unused")
}
func (s *bootstrapStore) RecordAuthentication(context.Context, uuid.UUID) (*models.User, error) {
	return nil, errors.New("unused")
}
func (s *bootstrapStore) Count(context.Context) (int64, error) { return s.count, nil }
func (s *bootstrapStore) BootstrapAdmin(context.Context, *models.User) (bool, error) {
	s.bootstrapCalled = true
	return true, nil
}

func TestBootstrapSkipsValidationAndHashingWhenUsersExist(t *testing.T) {
	t.Parallel()
	store := &bootstrapStore{count: 1}
	service := &Service{store: store}
	result, err := service.BootstrapInitialAdmin(context.Background(), "invalid username", "short", "invalid email")
	if err != nil {
		t.Fatalf("non-empty database was blocked by unused bootstrap configuration: %v", err)
	}
	if result.Created || result.GeneratedPassword != "" {
		t.Fatalf("unexpected bootstrap result: %#v", result)
	}
	if store.bootstrapCalled {
		t.Fatal("locked bootstrap transaction ran for a non-empty database")
	}
}

func TestAdminUpdateAuditEventRestrictsSensitiveFields(t *testing.T) {
	t.Parallel()
	role := "admin"
	if err := validateAdminUpdateAudit(models.AdminUpdateUserRequest{Role: &role}, audit.MutationAudit{Event: models.AuditUserUpdated}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("generic update role error = %v", err)
	}
	status := models.UserStatusSuspended
	if err := validateAdminUpdateAudit(models.AdminUpdateUserRequest{Status: &status}, audit.MutationAudit{Event: models.AuditUserUpdated}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("generic update status error = %v", err)
	}
	if err := validateAdminUpdateAudit(models.AdminUpdateUserRequest{Role: &role}, audit.MutationAudit{Event: models.AuditUserRoleChanged}); err != nil {
		t.Fatalf("dedicated role update rejected: %v", err)
	}
}

type securityStore struct {
	bootstrapStore
	user                   *models.User
	authenticationRecorded bool
	setPasswordHash        string
	usernameLookups        int
}

func (s *securityStore) GetByID(context.Context, uuid.UUID) (*models.User, error) {
	return s.user, nil
}

func (s *securityStore) GetByUsername(context.Context, string) (*models.User, error) {
	s.usernameLookups++
	if s.user == nil {
		return nil, errors.New("not found")
	}
	return s.user, nil
}

func (s *securityStore) RecordAuthentication(context.Context, uuid.UUID) (*models.User, error) {
	s.authenticationRecorded = true
	return s.user, nil
}

func (s *securityStore) SetPasswordIfMissing(_ context.Context, _ uuid.UUID, hash string, _ audit.MutationAudit) (*models.User, error) {
	s.setPasswordHash = hash
	updated := *s.user
	updated.PasswordHash = &hash
	updated.AuthVersion++
	return &updated, nil
}

func TestReauthenticateVerifiesLocalPasswordBeforeRecording(t *testing.T) {
	t.Parallel()
	hash, err := crypto.HashPassword("correct-password-value")
	if err != nil {
		t.Fatal(err)
	}
	store := &securityStore{user: &models.User{ID: uuid.New(), PasswordHash: &hash, Status: models.UserStatusActive}}
	service := &Service{store: store}
	if _, err := service.Reauthenticate(context.Background(), store.user.ID, "wrong-password-value"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password error = %v", err)
	}
	if store.authenticationRecorded {
		t.Fatal("wrong password recorded a recent authentication")
	}
	if _, err := service.Reauthenticate(context.Background(), store.user.ID, "correct-password-value"); err != nil {
		t.Fatalf("correct password error = %v", err)
	}
	if !store.authenticationRecorded {
		t.Fatal("correct password did not record authentication")
	}
}

func TestAuthenticateRejectsOversizedUsernameBeforeLookup(t *testing.T) {
	t.Parallel()
	store := &securityStore{}
	service := &Service{store: store}

	_, err := service.Authenticate(context.Background(), strings.Repeat("a", 65), "valid-password-value")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if store.usernameLookups != 0 {
		t.Fatalf("username lookups = %d, want 0", store.usernameLookups)
	}
}

func TestAuthenticateRejectsOversizedPassword(t *testing.T) {
	t.Parallel()
	store := &securityStore{}
	service := &Service{store: store}

	_, err := service.Authenticate(context.Background(), "valid-user", strings.Repeat("p", 1025))
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Authenticate() error = %v", err)
	}
}

func TestSetPasswordOnlyAddsMissingCapability(t *testing.T) {
	t.Parallel()
	store := &securityStore{user: &models.User{ID: uuid.New(), Status: models.UserStatusActive, AuthVersion: 1}}
	service := &Service{store: store}
	mutation := audit.MutationAudit{Event: models.AuditUserPasswordSet}
	updated, err := service.SetPassword(context.Background(), store.user.ID, "new-password-value", mutation)
	if err != nil {
		t.Fatalf("SetPassword error = %v", err)
	}
	if store.setPasswordHash == "" || updated.PasswordHash == nil || updated.AuthVersion != 2 {
		t.Fatalf("password capability was not set: %#v", updated)
	}
	store.user.PasswordHash = &store.setPasswordHash
	if _, err := service.SetPassword(context.Background(), store.user.ID, "another-password", mutation); !errors.Is(err, ErrPasswordConfigured) {
		t.Fatalf("configured password error = %v", err)
	}
}
