package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestDescribeMutation(t *testing.T) {
	actor := &models.User{ID: uuid.New(), Username: "admin"}
	tests := []struct {
		method, path, route, id string
		event, targetType       string
		successAlreadyAudited   bool
	}{
		{http.MethodPut, "/api/me", "/api/me", "", models.AuditUserProfileUpdated, "user", false},
		{http.MethodPost, "/api/admin/users", "/api/admin/users", "", models.AuditUserCreated, "user", false},
		{http.MethodPost, "/api/admin/users/target/suspend", "/api/admin/users/{id}/suspend", "target", models.AuditUserSuspended, "user", true},
		{http.MethodPut, "/api/admin/clients/client-1", "/api/admin/clients/{id}", "client-1", models.AuditClientUpdated, "client", false},
		{http.MethodPost, "/api/admin/providers/github/test", "/api/admin/providers/{id}/test", "github", models.AuditProviderTested, "provider", true},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			routeContext := chi.NewRouteContext()
			routeContext.RoutePatterns = append(routeContext.RoutePatterns, test.route)
			if test.id != "" {
				routeContext.URLParams.Add("id", test.id)
			}
			r := httptest.NewRequest(test.method, test.path, nil)
			r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routeContext))
			descriptor, ok := describeMutation(r, actor)
			if !ok {
				t.Fatal("mutation was not described")
			}
			if descriptor.event != test.event || descriptor.targetType != test.targetType || descriptor.successAlreadyAudited != test.successAlreadyAudited {
				t.Fatalf("unexpected descriptor: %#v", descriptor)
			}
			if test.id != "" && descriptor.targetID != test.id {
				t.Fatalf("target ID = %q, want %q", descriptor.targetID, test.id)
			}
		})
	}
}
