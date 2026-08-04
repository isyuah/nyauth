package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
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
		{http.MethodDelete, "/api/me/sessions/session-1", "/api/me/sessions/{id}", "session-1", models.AuditSessionRevoked, "session", true},
		{http.MethodPost, "/api/me/sessions/revoke-others", "/api/me/sessions/revoke-others", "", models.AuditSessionOthersRevoked, "user", true},
		{http.MethodPost, "/api/me/reauth/password", "/api/me/reauth/password", "", models.AuditUserReauthenticated, "user", true},
		{http.MethodPost, "/api/me/reauth/passkey/verify", "/api/me/reauth/passkey/verify", "", models.AuditUserReauthenticated, "user", true},
		{http.MethodPost, "/api/me/reauth/github", "/api/me/reauth/{provider}", "", models.AuditUserReauthenticated, "user", true},
		{http.MethodPost, "/api/me/email/verification", "/api/me/email/verification", "", models.AuditEmailVerifyRequested, "user", false},
		{http.MethodPost, "/api/me/email/change", "/api/me/email/change", "", models.AuditEmailChangeRequested, "user", false},
		{http.MethodPost, "/api/device-authorization/prepare", "/api/device-authorization/prepare", "", models.AuditDeviceAuthorizationStarted, "oauth_device_authorization", false},
		{http.MethodPost, "/api/admin/users", "/api/admin/users", "", models.AuditUserCreated, "user", true},
		{http.MethodPost, "/api/admin/users/target/suspend", "/api/admin/users/{id}/suspend", "target", models.AuditUserSuspended, "user", true},
		{http.MethodPost, "/api/admin/users/target/reset-password", "/api/admin/users/{id}/reset-password", "target", models.AuditUserPasswordReset, "user", true},
		{http.MethodDelete, "/api/admin/users/target/sessions", "/api/admin/users/{id}/sessions", "target", models.AuditUserSessionsRevoked, "user", true},
		{http.MethodDelete, "/api/admin/users/target/sessions/session-1", "/api/admin/users/{id}/sessions/{session_id}", "target", models.AuditSessionRevoked, "user", true},
		{http.MethodDelete, "/api/admin/users/target", "/api/admin/users/{id}", "target", models.AuditUserDeleted, "user", true},
		{http.MethodPost, "/api/admin/clients", "/api/admin/clients", "", models.AuditClientCreated, "client", true},
		{http.MethodPut, "/api/admin/clients/client-1", "/api/admin/clients/{id}", "client-1", models.AuditClientUpdated, "client", true},
		{http.MethodPut, "/api/admin/clients/client-1/owner", "/api/admin/clients/{id}/owner", "client-1", models.AuditClientOwnerChanged, "client", true},
		{http.MethodPost, "/api/admin/clients/client-1/publisher-verification", "/api/admin/clients/{id}/publisher-verification", "client-1", models.AuditClientPublisherVerified, "client", true},
		{http.MethodDelete, "/api/admin/clients/client-1/publisher-verification", "/api/admin/clients/{id}/publisher-verification", "client-1", models.AuditClientPublisherRevoked, "client", true},
		{http.MethodPost, "/api/admin/clients/client-1/rotate-secret", "/api/admin/clients/{id}/rotate-secret", "client-1", models.AuditClientSecretRotated, "client", true},
		{http.MethodPost, "/api/admin/clients/client-1/logo", "/api/admin/clients/{id}/logo", "client-1", models.AuditClientUpdated, "client", false},
		{http.MethodDelete, "/api/admin/clients/client-1/logo", "/api/admin/clients/{id}/logo", "client-1", models.AuditClientUpdated, "client", false},
		{http.MethodDelete, "/api/admin/clients/client-1", "/api/admin/clients/{id}", "client-1", models.AuditClientDeleted, "client", true},
		{http.MethodPut, "/api/my/clients/client-1", "/api/my/clients/{id}", "client-1", models.AuditClientUpdated, "client", true},
		{http.MethodPost, "/api/my/clients/client-1/logo", "/api/my/clients/{id}/logo", "client-1", models.AuditClientUpdated, "client", false},
		{http.MethodDelete, "/api/my/clients/client-1/logo", "/api/my/clients/{id}/logo", "client-1", models.AuditClientUpdated, "client", false},
		{http.MethodPost, "/api/my/clients/client-1/rotate-secret", "/api/my/clients/{id}/rotate-secret", "client-1", models.AuditClientSecretRotated, "client", true},
		{http.MethodPost, "/api/admin/providers/github/test", "/api/admin/providers/{id}/test", "github", models.AuditProviderTested, "provider", true},
		{http.MethodPost, "/api/admin/announcements", "/api/admin/announcements", "", models.AuditAnnouncementCreated, "announcement", true},
		{http.MethodPut, "/api/admin/announcements/announcement-1", "/api/admin/announcements/{id}", "announcement-1", models.AuditAnnouncementUpdated, "announcement", true},
		{http.MethodPost, "/api/admin/announcements/announcement-1/publish", "/api/admin/announcements/{id}/publish", "announcement-1", models.AuditAnnouncementPublished, "announcement", true},
		{http.MethodPost, "/api/admin/announcements/announcement-1/archive", "/api/admin/announcements/{id}/archive", "announcement-1", models.AuditAnnouncementArchived, "announcement", true},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			routeContext := chi.NewRouteContext()
			routeContext.RoutePatterns = append(routeContext.RoutePatterns, test.route)
			if test.id != "" {
				routeContext.URLParams.Add("id", test.id)
			}
			if strings.Contains(test.route, "{session_id}") {
				routeContext.URLParams.Add("session_id", "session-1")
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

func TestCommunicationReadStateMutationsAreNotAudited(t *testing.T) {
	for _, path := range []string{
		"/api/messages/read-all?kind=all",
		"/api/announcements/announcement-1/read",
		"/api/notifications/notification-1/read",
		"/api/notifications/read-all",
	} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		if !isCommunicationReadStateMutation(request) {
			t.Fatalf("read state mutation %q was not recognized", path)
		}
	}
	if isCommunicationReadStateMutation(httptest.NewRequest(http.MethodPost, "/api/admin/announcements/announcement-1/publish", nil)) {
		t.Fatal("announcement publication was classified as read state")
	}
}

func TestCommunicationPreviewsAreNotAuditedAsMutations(t *testing.T) {
	for _, path := range []string{
		"/api/admin/announcements/preview",
		"/api/admin/settings/communications/site-banner/preview",
		"/api/admin/settings/communications/email/preview",
	} {
		if !isCommunicationPreviewRequest(httptest.NewRequest(http.MethodPost, path, nil)) {
			t.Fatalf("communication preview %q was not recognized", path)
		}
	}
	if isCommunicationPreviewRequest(httptest.NewRequest(http.MethodPost, "/api/admin/settings/communications/email/test", nil)) {
		t.Fatal("test email was classified as a preview")
	}
}

func TestMutationAuditMiddlewareDefaultsUnknownMutationToGenericAudit(t *testing.T) {
	actor := &models.User{ID: uuid.New(), Username: "admin"}
	request := httptest.NewRequest(http.MethodPatch, "/api/admin/future-setting", nil)
	routeContext := chi.NewRouteContext()
	routeContext.RoutePatterns = []string{"/api/admin/future-setting"}
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
	request = request.WithContext(context.WithValue(request.Context(), currentUserContextKey, actor))

	var captured audit.MutationAudit
	handler := (&Server{}).mutationAuditMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		captured, ok = audit.MutationAuditFromContext(r.Context())
		if !ok {
			t.Fatal("generic mutation audit context was not installed")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), request)

	if captured.Event != models.AuditMutationUnclassified || captured.TargetType != "route" || captured.TargetID != "PATCH /api/admin/future-setting" {
		t.Fatalf("generic mutation audit = %#v", captured)
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
		{http.MethodPut, "/api/admin/settings/branding", "/api/admin/settings/branding", "", models.AuditSettingsUpdated, "settings", "medium", true},
		{http.MethodPut, "/api/admin/settings/registration", "/api/admin/settings/registration", "", models.AuditSettingsUpdated, "settings", "high", true},
		{http.MethodPut, "/api/admin/settings/security", "/api/admin/settings/security", "", models.AuditSettingsUpdated, "settings", "high", true},
		{http.MethodPut, "/api/admin/settings/protection", "/api/admin/settings/protection", "", models.AuditSettingsUpdated, "settings", "critical", true},
		{http.MethodPut, "/api/admin/settings/lifecycle", "/api/admin/settings/lifecycle", "", models.AuditSettingsUpdated, "settings", "high", true},
		{http.MethodPut, "/api/admin/settings/oauth", "/api/admin/settings/oauth", "", models.AuditSettingsUpdated, "settings", "high", true},
		{http.MethodPut, "/api/admin/settings/communications", "/api/admin/settings/communications", "", models.AuditSettingsUpdated, "settings", "high", true},
		{http.MethodPost, "/api/admin/settings/communications/email/test", "/api/admin/settings/communications/email/test", "", models.AuditMailTemplateTested, "email_template", "high", true},
		{http.MethodPut, "/api/admin/settings/observability", "/api/admin/settings/observability", "", models.AuditSettingsUpdated, "settings", "high", true},
		{http.MethodPut, "/api/admin/settings/observability/otlp/candidate", "/api/admin/settings/observability/otlp/candidate", "", models.AuditTelemetrySettingsSaved, "telemetry_config", "high", true},
		{http.MethodPost, "/api/admin/settings/observability/otlp/candidate/test", "/api/admin/settings/observability/otlp/candidate/test", "", models.AuditTelemetrySettingsTested, "telemetry_config", "high", true},
		{http.MethodPost, "/api/admin/settings/observability/otlp/activate", "/api/admin/settings/observability/otlp/activate", "", models.AuditTelemetrySettingsActivated, "telemetry_config", "high", true},
		{http.MethodPost, "/api/admin/settings/observability/otlp/rollback", "/api/admin/settings/observability/otlp/rollback", "", models.AuditTelemetrySettingsRolledBack, "telemetry_config", "high", true},
		{http.MethodPost, "/api/admin/settings/observability/otlp/disable", "/api/admin/settings/observability/otlp/disable", "", models.AuditTelemetrySettingsDisabled, "telemetry_runtime", "high", true},
		{http.MethodPut, "/api/admin/settings/human-verification/candidate", "/api/admin/settings/human-verification/candidate", "", models.AuditHumanVerificationSaved, "human_verification_config", "high", true},
		{http.MethodPost, "/api/admin/settings/human-verification/candidate/test", "/api/admin/settings/human-verification/candidate/test", "", models.AuditHumanVerificationTested, "human_verification_config", "high", true},
		{http.MethodPost, "/api/admin/settings/human-verification/activate", "/api/admin/settings/human-verification/activate", "", models.AuditHumanVerificationActivated, "human_verification_runtime", "critical", true},
		{http.MethodPut, "/api/admin/settings/human-verification/policy", "/api/admin/settings/human-verification/policy", "", models.AuditHumanVerificationUpdated, "human_verification_runtime", "critical", true},
		{http.MethodPost, "/api/admin/settings/human-verification/rollback", "/api/admin/settings/human-verification/rollback", "", models.AuditHumanVerificationRolledBack, "human_verification_runtime", "critical", true},
		{http.MethodPost, "/api/admin/settings/human-verification/disable", "/api/admin/settings/human-verification/disable", "", models.AuditHumanVerificationDisabled, "human_verification_runtime", "critical", true},
		{http.MethodPost, "/api/admin/settings/human-verification/enable", "/api/admin/settings/human-verification/enable", "", models.AuditHumanVerificationEnabled, "human_verification_runtime", "critical", true},
		{http.MethodPut, "/api/admin/users/user-1/client-quota", "/api/admin/users/{id}/client-quota", "user-1", models.AuditUserClientQuotaUpdated, "user", "medium", true},
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

func TestDescribeMediaAdministrationMutations(t *testing.T) {
	actor := &models.User{ID: uuid.New(), Username: "admin"}
	tests := []struct {
		method, path, route, id string
		event, targetType       string
	}{
		{http.MethodPut, "/api/admin/settings/media/candidate", "/api/admin/settings/media/candidate", "", models.AuditMediaSettingsSaved, "media_config"},
		{http.MethodPost, "/api/admin/settings/media/candidate/test", "/api/admin/settings/media/candidate/test", "", models.AuditMediaSettingsTested, "media_config"},
		{http.MethodPost, "/api/admin/settings/media/migrations", "/api/admin/settings/media/migrations", "", models.AuditMediaMigrationStarted, "media_migration"},
		{http.MethodPost, "/api/admin/settings/media/fallback/migrate", "/api/admin/settings/media/fallback/migrate", "", models.AuditMediaMigrationStarted, "media_migration"},
		{http.MethodPost, "/api/admin/settings/media/migrations/migration-1/retry", "/api/admin/settings/media/migrations/{id}/retry", "migration-1", models.AuditMediaMigrationRetried, "media_migration"},
	}

	for _, test := range tests {
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
				t.Fatal("media administration mutation was not described")
			}
			if descriptor.event != test.event || descriptor.targetType != test.targetType ||
				descriptor.targetID != test.id || descriptor.riskLevel != "critical" ||
				!descriptor.successAlreadyAudited {
				t.Fatalf("unexpected descriptor: %#v", descriptor)
			}
		})
	}
}
