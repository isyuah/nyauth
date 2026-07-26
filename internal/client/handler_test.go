package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/pkg/models"
)

type fakeHandlerService struct {
	listErr           error
	createErr         error
	getErr            error
	updateErr         error
	updateOwnerErr    error
	updateOwnerResult *models.OAuthClient
	updateOwnerReq    models.UpdateClientOwnerRequest
	deleteErr         error
	rotateErr         error
	rotateResult      *models.RotateClientSecretResponse
	accessUsers       []models.ClientAccessUser
	accessUsersErr    error
	replaceAccessReq  models.ReplaceClientAccessUsersRequest
}

func (f *fakeHandlerService) List(context.Context, int, int) (*models.PaginatedResponse[models.OAuthClient], error) {
	return nil, f.listErr
}
func (f *fakeHandlerService) CreateAdmin(context.Context, models.CreateClientRequest, audit.MutationAudit) (*models.CreateClientResponse, error) {
	return nil, f.createErr
}
func (f *fakeHandlerService) GetByID(context.Context, string) (*models.OAuthClient, error) {
	return nil, f.getErr
}
func (f *fakeHandlerService) Update(context.Context, string, models.UpdateClientRequest, audit.MutationAudit) (*models.OAuthClient, error) {
	return nil, f.updateErr
}
func (f *fakeHandlerService) UpdateOwner(_ context.Context, _ string, req models.UpdateClientOwnerRequest, _ audit.MutationAudit) (*models.OAuthClient, error) {
	f.updateOwnerReq = req
	return f.updateOwnerResult, f.updateOwnerErr
}
func (f *fakeHandlerService) Delete(context.Context, string, audit.MutationAudit) error {
	return f.deleteErr
}
func (f *fakeHandlerService) RotateSecret(context.Context, string, audit.MutationAudit) (*models.RotateClientSecretResponse, error) {
	return f.rotateResult, f.rotateErr
}
func (f *fakeHandlerService) ListAccessUsers(context.Context, string) ([]models.ClientAccessUser, error) {
	return f.accessUsers, f.accessUsersErr
}
func (f *fakeHandlerService) ReplaceAccessUsers(_ context.Context, _ string, req models.ReplaceClientAccessUsersRequest, _ audit.MutationAudit) ([]models.ClientAccessUser, error) {
	f.replaceAccessReq = req
	return f.accessUsers, f.accessUsersErr
}

func withTestMutationAudit(request *http.Request) *http.Request {
	return withTestMutationAuditEvent(request, models.AuditClientSecretRotated)
}

func withTestMutationAuditEvent(request *http.Request, event string) *http.Request {
	return request.WithContext(audit.WithMutationAudit(request.Context(), audit.MutationAudit{
		Event: event, ActorID: uuid.New(), ActorName: "admin",
		TargetType: "client", TargetID: "client-1", Result: "success", RiskLevel: "high",
	}))
}

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
		request = withTestMutationAuditEvent(request, models.AuditClientCreated)
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

func TestCreateRequiresAuditContext(t *testing.T) {
	t.Parallel()
	handler := &Handler{service: &fakeHandlerService{}}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test"}`))
	response := httptest.NewRecorder()
	handler.Create(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestRotateSecretResponseIsNeverCacheable(t *testing.T) {
	t.Parallel()
	service := &fakeHandlerService{rotateResult: &models.RotateClientSecretResponse{
		ClientID: "client-1", Secret: "new-secret", SecretHint: "secret", SecretVersion: 2,
	}}
	handler := &Handler{service: service}
	router := chi.NewRouter()
	router.Post("/clients/{id}/rotate-secret", handler.RotateSecret)

	request := withTestMutationAudit(httptest.NewRequest(http.MethodPost, "/clients/client-1/rotate-secret", nil))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := response.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q", got)
	}
	if body := response.Body.String(); !strings.Contains(body, `"secret":"new-secret"`) {
		t.Fatalf("rotated secret missing from one-time response: %s", body)
	}
}

func TestRotateSecretMapsSafeErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "missing", err: pgx.ErrNoRows, status: http.StatusNotFound},
		{name: "public", err: ErrPublicClientSecret, status: http.StatusConflict},
		{name: "internal", err: errors.New("database password leaked"), status: http.StatusInternalServerError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &Handler{service: &fakeHandlerService{rotateErr: test.err}}
			request := httptest.NewRequest(http.MethodPost, "/clients/client-1/rotate-secret", nil)
			routeContext := chi.NewRouteContext()
			routeContext.URLParams.Add("id", "client-1")
			request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
			request = withTestMutationAudit(request)
			response := httptest.NewRecorder()
			handler.RotateSecret(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if test.status == http.StatusInternalServerError && strings.Contains(response.Body.String(), "password") {
				t.Fatalf("internal error leaked: %s", response.Body.String())
			}
		})
	}
}

func TestUpdateOwnerAcceptsNullAndReturnsCompleteClient(t *testing.T) {
	t.Parallel()
	updated := &models.OAuthClient{
		ID: "client-1", Name: "Ownerless client", RedirectURIs: []string{"https://client.example/callback"},
		PostLogoutRedirectURIs: []string{}, Grants: []string{models.GrantAuthorizationCode},
		Scopes: []string{"openid"}, Metadata: map[string]string{"environment": "test"},
	}
	service := &fakeHandlerService{updateOwnerResult: updated}
	handler := &Handler{service: service}
	router := chi.NewRouter()
	router.Put("/clients/{id}/owner", handler.UpdateOwner)

	request := httptest.NewRequest(http.MethodPut, "/clients/client-1/owner", strings.NewReader(`{"owner_id":null}`))
	request = withTestMutationAuditEvent(request, models.AuditClientOwnerChanged)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if service.updateOwnerReq.OwnerID != nil {
		t.Fatalf("owner ID = %v, want nil", service.updateOwnerReq.OwnerID)
	}
	var body models.OAuthClient
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.ID != updated.ID || body.Name != updated.Name || body.Metadata["environment"] != "test" {
		t.Fatalf("response did not contain the complete client: %#v", body)
	}
}

func TestUpdateOwnerMapsSafeErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "invalid owner", err: fmt.Errorf("%w: owner_id must be a UUID or null", ErrInvalidClient), status: http.StatusBadRequest},
		{name: "missing client", err: pgx.ErrNoRows, status: http.StatusNotFound},
		{name: "inactive owner", err: ErrClientOwnerUnavailable, status: http.StatusConflict},
		{name: "quota", err: ErrClientQuotaExceeded, status: http.StatusConflict},
		{name: "internal", err: errors.New("database password leaked"), status: http.StatusInternalServerError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ownerID := uuid.NewString()
			handler := &Handler{service: &fakeHandlerService{updateOwnerErr: test.err}}
			request := httptest.NewRequest(http.MethodPut, "/clients/client-1/owner", strings.NewReader(`{"owner_id":"`+ownerID+`"}`))
			routeContext := chi.NewRouteContext()
			routeContext.URLParams.Add("id", "client-1")
			request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
			request = withTestMutationAuditEvent(request, models.AuditClientOwnerChanged)
			response := httptest.NewRecorder()
			handler.UpdateOwner(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if test.status == http.StatusInternalServerError && strings.Contains(response.Body.String(), "password") {
				t.Fatalf("internal error leaked: %s", response.Body.String())
			}
		})
	}
}

func TestUpdateOwnerRequiresAuditContext(t *testing.T) {
	t.Parallel()
	handler := &Handler{service: &fakeHandlerService{}}
	request := httptest.NewRequest(http.MethodPut, "/clients/client-1/owner", strings.NewReader(`{"owner_id":null}`))
	response := httptest.NewRecorder()
	handler.UpdateOwner(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestUpdateRequiresAuditContext(t *testing.T) {
	t.Parallel()
	handler := &Handler{service: &fakeHandlerService{}}
	request := httptest.NewRequest(http.MethodPut, "/clients/client-1", strings.NewReader(`{"name":"updated"}`))
	response := httptest.NewRecorder()
	handler.Update(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestUpdateOwnerRequiresExplicitOwnerField(t *testing.T) {
	t.Parallel()
	for _, body := range []string{`{}`, `{"owner_id":null,"unexpected":true}`} {
		handler := &Handler{service: &fakeHandlerService{}}
		request := httptest.NewRequest(http.MethodPut, "/clients/client-1/owner", strings.NewReader(body))
		response := httptest.NewRecorder()
		handler.UpdateOwner(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %s: status = %d, response = %s", body, response.Code, response.Body.String())
		}
	}
}
