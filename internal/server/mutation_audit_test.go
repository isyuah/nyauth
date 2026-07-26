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
		{http.MethodPost, "/api/me/password/set", "/api/me/password/set", "", models.AuditUserPasswordSet, "user", true},
		{http.MethodDelete, "/api/me/identities/identity-1", "/api/me/identities/{id}", "identity-1", models.AuditIdentityUnbound, "identity", true},
		{http.MethodPost, "/api/admin/users", "/api/admin/users", "", models.AuditUserCreated, "user", false},
		{http.MethodPost, "/api/admin/users/target/suspend", "/api/admin/users/{id}/suspend", "target", models.AuditUserSuspended, "user", true},
		{http.MethodPost, "/api/admin/users/target/reset-password", "/api/admin/users/{id}/reset-password", "target", models.AuditUserPasswordReset, "user", true},
		{http.MethodDelete, "/api/admin/users/target/sessions", "/api/admin/users/{id}/sessions", "target", models.AuditUserSessionsRevoked, "user", true},
		{http.MethodDelete, "/api/admin/users/target", "/api/admin/users/{id}", "target", models.AuditUserDeleted, "user", true},
		{http.MethodPost, "/api/admin/clients", "/api/admin/clients", "", models.AuditClientCreated, "client", true},
		{http.MethodPut, "/api/admin/clients/client-1", "/api/admin/clients/{id}", "client-1", models.AuditClientUpdated, "client", true},
		{http.MethodPut, "/api/admin/clients/client-1/owner", "/api/admin/clients/{id}/owner", "client-1", models.AuditClientOwnerChanged, "client", true},
		{http.MethodPost, "/api/admin/clients/client-1/rotate-secret", "/api/admin/clients/{id}/rotate-secret", "client-1", models.AuditClientSecretRotated, "client", true},
		{http.MethodDelete, "/api/admin/clients/client-1", "/api/admin/clients/{id}", "client-1", models.AuditClientDeleted, "client", true},
		{http.MethodPost, "/api/my/clients/client-1/rotate-secret", "/api/my/clients/{id}/rotate-secret", "client-1", models.AuditClientSecretRotated, "client", true},
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

func TestDescribeAdminSessionRevocationIsTransactionalHighRisk(t *testing.T) {
	actor := &models.User{ID: uuid.New(), Username: "admin"}
	routeContext := chi.NewRouteContext()
	routeContext.RoutePatterns = append(routeContext.RoutePatterns, "/api/admin/users/{id}/sessions")
	routeContext.URLParams.Add("id", "user-1")
	request := httptest.NewRequest(http.MethodDelete, "/api/admin/users/user-1/sessions", nil)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))

	descriptor, ok := describeMutation(request, actor)
	if !ok {
		t.Fatal("administrator session revocation was not described")
	}
	if descriptor.event != models.AuditUserSessionsRevoked || descriptor.targetType != "user" ||
		descriptor.targetID != "user-1" || descriptor.riskLevel != "high" || !descriptor.successAlreadyAudited {
		t.Fatalf("unexpected descriptor: %#v", descriptor)
	}
}

func TestDescribeClientOwnerMutationIsTransactionalHighRisk(t *testing.T) {
	actor := &models.User{ID: uuid.New(), Username: "admin"}
	routeContext := chi.NewRouteContext()
	routeContext.RoutePatterns = append(routeContext.RoutePatterns, "/api/admin/clients/{id}/owner")
	routeContext.URLParams.Add("id", "client-1")
	request := httptest.NewRequest(http.MethodPut, "/api/admin/clients/client-1/owner", nil)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))

	descriptor, ok := describeMutation(request, actor)
	if !ok {
		t.Fatal("client owner mutation was not described")
	}
	if descriptor.event != models.AuditClientOwnerChanged || descriptor.riskLevel != "high" || !descriptor.successAlreadyAudited {
		t.Fatalf("unexpected descriptor: %#v", descriptor)
	}
}

func TestDescribeAdminIdentityRemoval(t *testing.T) {
	actor := &models.User{ID: uuid.New(), Username: "admin"}
	routeContext := chi.NewRouteContext()
	routeContext.RoutePatterns = append(routeContext.RoutePatterns, "/api/admin/users/{id}/identities/{identity_id}")
	routeContext.URLParams.Add("id", "user-1")
	routeContext.URLParams.Add("identity_id", "identity-1")
	request := httptest.NewRequest(http.MethodDelete, "/api/admin/users/user-1/identities/identity-1", nil)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))

	descriptor, ok := describeMutation(request, actor)
	if !ok {
		t.Fatal("admin identity removal was not described")
	}
	if descriptor.event != models.AuditIdentityUnbound || descriptor.targetType != "identity" || descriptor.targetID != "identity-1" || !descriptor.successAlreadyAudited {
		t.Fatalf("unexpected descriptor: %#v", descriptor)
	}
}

func TestDescribeAuthorizationRevocation(t *testing.T) {
	actor := &models.User{ID: uuid.New(), Username: "alice"}
	routeContext := chi.NewRouteContext()
	routeContext.RoutePatterns = append(routeContext.RoutePatterns, "/api/me/authorizations/{client_id}")
	routeContext.URLParams.Add("client_id", "client-1")
	request := httptest.NewRequest(http.MethodDelete, "/api/me/authorizations/client-1", nil)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))

	descriptor, ok := describeMutation(request, actor)
	if !ok {
		t.Fatal("authorization revocation was not described")
	}
	if descriptor.event != models.AuditAuthorizationRevoked || descriptor.targetType != "client" || descriptor.targetID != "client-1" || !descriptor.successAlreadyAudited {
		t.Fatalf("unexpected descriptor: %#v", descriptor)
	}
}

func TestDescribeRegistrationAdministrationMutations(t *testing.T) {
	actor := &models.User{ID: uuid.New(), Username: "admin"}
	for _, test := range []struct {
		method, path, route, id string
		event, targetType       string
		riskLevel               string
		successAlreadyAudited   bool
	}{
		{http.MethodPut, "/api/admin/settings/registration", "/api/admin/settings/registration", "", models.AuditSettingsUpdated, "settings", "high", false},
		{http.MethodPost, "/api/admin/invites", "/api/admin/invites", "", models.AuditInviteCreated, "invite", "medium", true},
		{http.MethodDelete, "/api/admin/invites/invite-1", "/api/admin/invites/{id}", "invite-1", models.AuditInviteRevoked, "invite", "medium", true},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			routeContext := chi.NewRouteContext()
			routeContext.RoutePatterns = append(routeContext.RoutePatterns, test.route)
			if test.id != "" {
				routeContext.URLParams.Add("id", test.id)
			}
			request := httptest.NewRequest(test.method, test.path, nil)
			request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
			descriptor, ok := describeMutation(request, actor)
			if !ok {
				t.Fatal("registration administration mutation was not described")
			}
			if descriptor.event != test.event || descriptor.targetType != test.targetType || descriptor.riskLevel != test.riskLevel || descriptor.successAlreadyAudited != test.successAlreadyAudited {
				t.Fatalf("unexpected descriptor: %#v", descriptor)
			}
			if test.id != "" && descriptor.targetID != test.id {
				t.Fatalf("target ID = %q, want %q", descriptor.targetID, test.id)
			}
		})
	}
}

func TestDescribeMailAdministrationMutations(t *testing.T) {
	actor := &models.User{ID: uuid.New(), Username: "admin"}
	tests := []struct {
		method, path, event, targetType, targetID string
	}{
		{http.MethodPut, "/api/admin/settings/mail/candidate", models.AuditMailSettingsSaved, "mail_config", ""},
		{http.MethodPost, "/api/admin/settings/mail/candidate/test", models.AuditMailSettingsTested, "mail_config", ""},
		{http.MethodPost, "/api/admin/settings/mail/activate", models.AuditMailSettingsActivated, "mail_config", ""},
		{http.MethodPost, "/api/admin/settings/mail/rollback", models.AuditMailSettingsRolledBack, "mail_runtime", "singleton"},
		{http.MethodPost, "/api/admin/settings/mail/disable", models.AuditMailSettingsDisabled, "mail_runtime", "singleton"},
	}

	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			descriptor, ok := describeMutation(request, actor)
			if !ok {
				t.Fatal("mail administration mutation was not described")
			}
			if descriptor.event != test.event || descriptor.targetType != test.targetType ||
				descriptor.targetID != test.targetID || descriptor.riskLevel != "high" ||
				!descriptor.successAlreadyAudited {
				t.Fatalf("unexpected descriptor: %#v", descriptor)
			}
		})
	}
}
