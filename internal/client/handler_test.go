package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/nyasharp/nyauth/pkg/models"
)

type fakeHandlerService struct {
	listErr   error
	createErr error
	getErr    error
	updateErr error
	deleteErr error
}

func (f *fakeHandlerService) List(context.Context, int, int) (*models.PaginatedResponse[models.OAuthClient], error) {
	return nil, f.listErr
}
func (f *fakeHandlerService) Create(context.Context, models.CreateClientRequest) (*models.CreateClientResponse, error) {
	return nil, f.createErr
}
func (f *fakeHandlerService) GetByID(context.Context, string) (*models.OAuthClient, error) {
	return nil, f.getErr
}
func (f *fakeHandlerService) Update(context.Context, string, models.UpdateClientRequest) (*models.OAuthClient, error) {
	return nil, f.updateErr
}
func (f *fakeHandlerService) Delete(context.Context, string) error { return f.deleteErr }

func TestHandlerDoesNotExposeInternalErrors(t *testing.T) {
	t.Parallel()
	handler := &Handler{service: &fakeHandlerService{listErr: errors.New("SELECT secret_hash FROM oauth_clients: database password leaked")}}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.List(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", response.Code)
	}
	if body := response.Body.String(); strings.Contains(body, "secret_hash") || strings.Contains(body, "password") {
		t.Fatalf("internal error leaked in response: %s", body)
	}
}

func TestHandlerMapsSafeClientErrors(t *testing.T) {
	t.Parallel()
	t.Run("invalid create", func(t *testing.T) {
		handler := &Handler{service: &fakeHandlerService{createErr: fmt.Errorf("%w: invalid redirect URI", ErrInvalidClient)}}
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test"}`))
		response := httptest.NewRecorder()
		handler.Create(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	})
	t.Run("missing client", func(t *testing.T) {
		handler := &Handler{service: &fakeHandlerService{getErr: fmt.Errorf("wrapped: %w", pgx.ErrNoRows)}}
		request := httptest.NewRequest(http.MethodGet, "/missing", nil)
		response := httptest.NewRecorder()
		handler.Get(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	})
}

func TestHandlerRejectsUnknownJSONFields(t *testing.T) {
	t.Parallel()
	handler := &Handler{service: &fakeHandlerService{}}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test","unexpected":true}`))
	response := httptest.NewRecorder()
	handler.Create(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}
