package user

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
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
func (s *bootstrapStore) UpdateAdmin(context.Context, uuid.UUID, models.AdminUpdateUserRequest) (*models.User, error) {
	return nil, errors.New("unused")
}
func (s *bootstrapStore) UpdatePassword(context.Context, uuid.UUID, string, bool) (*models.User, error) {
	return nil, errors.New("unused")
}
func (s *bootstrapStore) Delete(context.Context, uuid.UUID) error { return errors.New("unused") }
func (s *bootstrapStore) List(context.Context, models.Pagination, string) (*models.PaginatedResponse[models.User], error) {
	return nil, errors.New("unused")
}
func (s *bootstrapStore) RecordLogin(context.Context, uuid.UUID, string) error {
	return errors.New("unused")
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
