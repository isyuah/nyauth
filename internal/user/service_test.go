package user

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

type bootstrapStore struct {
	count           int64
	bootstrapCalled bool
}

func (s *bootstrapStore) Create(context.Context, *models.User) error { return errors.New("unused") }
func (s *bootstrapStore) CreateRegistration(context.Context, *models.User, RegistrationCommitOptions) (*uuid.UUID, error) {
	return nil, errors.New("unused")
}
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
func (s *bootstrapStore) RecordAuthentication(context.Context, uuid.UUID, int64, int64) (*models.User, error) {
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

func (s *securityStore) RecordAuthentication(context.Context, uuid.UUID, int64, int64) (*models.User, error) {
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

type createRecordingStore struct {
	bootstrapStore
	created *models.User
}

func (s *createRecordingStore) Create(_ context.Context, u *models.User) error {
	s.created = u
	return nil
}

func TestCreateDefaultsOmittedMetadataToEmptyObject(t *testing.T) {
	store := &createRecordingStore{}
	service := &Service{store: store}
	created, err := service.Create(context.Background(), models.CreateUserRequest{
		Username: "newuser",
		Password: "a-valid-password-123",
	})
	if err != nil {
		t.Fatal(err)
	}
	// users.metadata is NOT NULL in the schema; a nil map would be inserted
	// as SQL NULL and fail the whole request with a 500.
	if store.created == nil || store.created.Metadata == nil {
		t.Fatalf("created user metadata must not be nil: %#v", store.created)
	}
	if created.DisplayName != nil || created.Email != nil {
		t.Fatalf("blank optional fields must stay null: %#v", created)
	}
}

type adminCreateRecordingStore struct {
	bootstrapStore
	created  *models.User
	mutation audit.MutationAudit
}

func (s *adminCreateRecordingStore) CreateAdmin(_ context.Context, u *models.User, mutation audit.MutationAudit) error {
	s.created = u
	s.mutation = mutation
	return nil
}

func TestCreateAdminForwardsTrustedActorAndDefaultsMetadata(t *testing.T) {
	store := &adminCreateRecordingStore{}
	service := &Service{store: store}
	actorID := uuid.New()
	mutation := audit.MutationAudit{
		Event: models.AuditUserCreated, ActorID: actorID, ActorName: "admin",
		Result: "success", RiskLevel: "low",
	}
	created, err := service.CreateAdmin(context.Background(), models.CreateUserRequest{
		Username: "managed-user", Password: "a-valid-password-123",
	}, mutation)
	if err != nil {
		t.Fatal(err)
	}
	if store.created == nil || created.ID != store.created.ID || store.created.Metadata == nil {
		t.Fatalf("administrator-created user = %#v stored=%#v", created, store.created)
	}
	if store.mutation.ActorID != actorID || store.mutation.Event != models.AuditUserCreated {
		t.Fatalf("administrator creation mutation = %#v", store.mutation)
	}
}

type registrationRecordingStore struct {
	bootstrapStore
	created  *models.User
	options  RegistrationCommitOptions
	inviteID uuid.UUID
}

func (s *registrationRecordingStore) CreateRegistration(_ context.Context, u *models.User, options RegistrationCommitOptions) (*uuid.UUID, error) {
	s.created = u
	s.options = options
	if options.InviteCodeHash == nil {
		return nil, nil
	}
	s.inviteID = uuid.New()
	return &s.inviteID, nil
}

func TestRegisterCreatesPendingUserAndForwardsInviteHash(t *testing.T) {
	store := &registrationRecordingStore{}
	service := &Service{store: store}
	hash := "invite-hash"
	now := time.Now().UTC()
	created, inviteID, err := service.Register(context.Background(), models.RegisterRequest{
		Username: "newbie", Email: "newbie@example.com", Password: "a-valid-password-123",
	}, RegisterOptions{
		PendingVerification: true, InviteCodeHash: &hash, Now: now, ExpiresAt: now.Add(72 * time.Hour),
		PrepareVerification: func(*models.User) (*account.PreparedActionEmail, error) {
			return &account.PreparedActionEmail{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Status != models.UserStatusPending {
		t.Fatalf("status = %q", created.Status)
	}
	if created.Email == nil || *created.Email != "newbie@example.com" || created.Metadata == nil {
		t.Fatalf("created = %#v", created)
	}
	if created.Role != "user" || created.MustChangePassword {
		t.Fatalf("unexpected privileges: %#v", created)
	}
	if store.options.InviteCodeHash == nil || *store.options.InviteCodeHash != hash {
		t.Fatalf("invite hash was not forwarded: %#v", store.options.InviteCodeHash)
	}
	if store.options.Verification == nil || !store.options.ExpiresAt.Equal(now.Add(72*time.Hour)) {
		t.Fatalf("registration commit options = %#v", store.options)
	}
	if inviteID == nil || *inviteID != store.inviteID {
		t.Fatalf("invite ID = %#v", inviteID)
	}

	active, activeInviteID, err := service.Register(context.Background(), models.RegisterRequest{
		Username: "walkin", Email: "walkin@example.com", Password: "a-valid-password-123",
	}, RegisterOptions{Now: now, ExpiresAt: now.Add(72 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if active.Status != models.UserStatusActive || activeInviteID != nil {
		t.Fatalf("open registration = %#v invite=%v", active, activeInviteID)
	}
}

func TestRegisterRejectsMissingEmail(t *testing.T) {
	service := &Service{store: &registrationRecordingStore{}}
	if _, _, err := service.Register(context.Background(), models.RegisterRequest{
		Username: "noemail", Password: "a-valid-password-123",
	}, RegisterOptions{PendingVerification: true, Now: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}); !IsInvalidInput(err) {
		t.Fatalf("missing email error = %v", err)
	}
	if err := service.ValidateRegistration(models.RegisterRequest{Username: "noemail", Password: "a-valid-password-123"}); !IsInvalidInput(err) {
		t.Fatalf("validate missing email error = %v", err)
	}
}

type pendingAuthStore struct {
	bootstrapStore
	user *models.User
}

func (s *pendingAuthStore) GetByUsername(context.Context, string) (*models.User, error) {
	return s.user, nil
}

func TestAuthenticatePendingUserGetsDistinctErrorOnlyWithValidPassword(t *testing.T) {
	hash, err := crypto.HashPassword("a-valid-password-123")
	if err != nil {
		t.Fatal(err)
	}
	store := &pendingAuthStore{user: &models.User{
		ID: uuid.New(), Username: "pending-user", PasswordHash: &hash,
		Status: models.UserStatusPending, AuthVersion: 1,
	}}
	service := &Service{store: store}

	if _, err := service.Authenticate(context.Background(), "pending-user", "a-valid-password-123"); !errors.Is(err, ErrEmailVerificationPending) {
		t.Fatalf("pending login error = %v", err)
	}
	// A wrong password must NOT reveal the pending state.
	if _, err := service.Authenticate(context.Background(), "pending-user", "wrong-password-123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong-password error = %v", err)
	}

	store.user.Status = models.UserStatusSuspended
	if _, err := service.Authenticate(context.Background(), "pending-user", "a-valid-password-123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("suspended login error = %v", err)
	}
}
