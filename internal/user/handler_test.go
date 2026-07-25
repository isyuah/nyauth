package user

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

type fakeUserHandlerService struct {
	createErr error
}

func (f *fakeUserHandlerService) List(context.Context, int, int, string) (*models.PaginatedResponse[models.User], error) {
	return &models.PaginatedResponse[models.User]{}, nil
}
func (f *fakeUserHandlerService) Create(context.Context, models.CreateUserRequest) (*models.User, error) {
	return nil, f.createErr
}
func (f *fakeUserHandlerService) GetByID(context.Context, uuid.UUID) (*models.User, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeUserHandlerService) AdminUpdate(context.Context, uuid.UUID, models.AdminUpdateUserRequest) (*models.User, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeUserHandlerService) Delete(context.Context, uuid.UUID) error {
	return errors.New("not implemented")
}
func (f *fakeUserHandlerService) ResetPassword(context.Context, uuid.UUID, string) (*models.User, error) {
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
