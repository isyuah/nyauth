package user

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/pkg/models"
)

type fakeUserHandlerService struct {
	createErr  error
	listStatus models.UserStatus
	listCalled bool
}

func (f *fakeUserHandlerService) List(_ context.Context, _, _ int, _ string, status models.UserStatus) (*models.PaginatedResponse[models.User], error) {
	f.listCalled = true
	f.listStatus = status
	return &models.PaginatedResponse[models.User]{}, nil
}
func (f *fakeUserHandlerService) Create(context.Context, models.CreateUserRequest) (*models.User, error) {
	return nil, f.createErr
}
func (f *fakeUserHandlerService) GetByID(context.Context, uuid.UUID) (*models.User, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeUserHandlerService) AdminUpdate(context.Context, uuid.UUID, models.AdminUpdateUserRequest, audit.MutationAudit) (*models.User, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeUserHandlerService) Delete(context.Context, uuid.UUID, audit.MutationAudit) error {
	return errors.New("not implemented")
}
func (f *fakeUserHandlerService) ResetPassword(context.Context, uuid.UUID, string, audit.MutationAudit) (*models.User, error) {
	return nil, errors.New("not implemented")
}

func TestCreateDoesNotExposeInternalErrors(t *testing.T) {
	t.Parallel()
	handler := &Handler{service: &fakeUserHandlerService{createErr: errors.New("INSERT INTO users: database password leaked")}}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username":"alice","password":"long-enough-password"}`))
	response := httptest.NewRecorder()
	handler.Create(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if body := response.Body.String(); strings.Contains(body, "INSERT") || strings.Contains(body, "password leaked") {
		t.Fatalf("internal error leaked in response: %s", body)
	}
}

func TestCreateRejectsUnknownJSONFields(t *testing.T) {
	t.Parallel()
	handler := &Handler{service: &fakeUserHandlerService{}}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username":"alice","password":"long-enough-password","role":"admin"}`))
	response := httptest.NewRecorder()
	handler.Create(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestListPassesValidatedStatusFilter(t *testing.T) {
	t.Parallel()
	service := &fakeUserHandlerService{}
	handler := &Handler{service: service}
	request := httptest.NewRequest(http.MethodGet, "/?status=active", nil)
	response := httptest.NewRecorder()

	handler.List(response, request)

	if response.Code != http.StatusOK || !service.listCalled || service.listStatus != models.UserStatusActive {
		t.Fatalf("status=%d called=%v filter=%q", response.Code, service.listCalled, service.listStatus)
	}
}

func TestListRejectsInvalidStatusFilter(t *testing.T) {
	t.Parallel()
	service := &fakeUserHandlerService{}
	handler := &Handler{service: service}
	request := httptest.NewRequest(http.MethodGet, "/?status=deleted", nil)
	response := httptest.NewRecorder()

	handler.List(response, request)

	if response.Code != http.StatusBadRequest || service.listCalled {
		t.Fatalf("status=%d called=%v body=%s", response.Code, service.listCalled, response.Body.String())
	}
}
