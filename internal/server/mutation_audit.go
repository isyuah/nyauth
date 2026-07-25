package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

const maxAuditUserAgentLength = 512

type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *auditResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *auditResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type mutationAuditDescriptor struct {
	event                 string
	targetType            string
	targetID              string
	successAlreadyAudited bool
}

func (s *Server) mutationAuditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		recorder := &auditResponseWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, r)

		actor := currentUserFromContext(r)
		descriptor, ok := describeMutation(r, actor)
		if !ok || actor == nil || s.auditStore == nil {
			return
		}
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		if status < http.StatusBadRequest && descriptor.successAlreadyAudited {
			return
		}
		result := "success"
		riskLevel := "low"
		if status >= http.StatusBadRequest {
			result = "failure"
			riskLevel = "medium"
		}

		actorName := actor.Username
		entry := &models.AuditLog{
			ID:        uuid.New(),
			Event:     descriptor.event,
			ActorID:   &actor.ID,
			ActorName: &actorName,
			Result:    result,
			RiskLevel: riskLevel,
			Metadata: map[string]any{
				"method": r.Method,
				"path":   routePattern(r),
				"status": status,
			},
			CreatedAt: time.Now(),
		}
		if descriptor.targetType != "" {
			targetType := descriptor.targetType
			entry.TargetType = &targetType
		}
		if descriptor.targetID != "" {
			targetID := descriptor.targetID
			entry.TargetID = &targetID
		}
		if ip := requestIP(r); ip != "" {
			entry.IPAddress = &ip
		}
		if userAgent := truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength); userAgent != "" {
			entry.UserAgent = &userAgent
		}
		_ = s.auditStore.Record(r.Context(), entry)
	})
}

func describeMutation(r *http.Request, actor *models.User) (mutationAuditDescriptor, bool) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	param := func(name string) string { return chi.URLParam(r, name) }

	switch {
	case r.Method == http.MethodPost && path == "/api/logout":
		return userMutation(models.AuditUserLogout, actor, false), true
	case r.Method == http.MethodPut && path == "/api/me":
		return userMutation(models.AuditUserProfileUpdated, actor, false), true
	case r.Method == http.MethodPost && path == "/api/me/password":
		return userMutation("user.password_changed", actor, true), true
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/me/identities/") && strings.HasSuffix(path, "/bind"):
		return mutationAuditDescriptor{event: models.AuditIdentityBindStarted, targetType: "provider", targetID: param("provider")}, true
	case r.Method == http.MethodPost && path == "/api/consent/accept":
		return mutationAuditDescriptor{event: models.AuditConsentAccepted, targetType: "oauth_consent"}, true
	case r.Method == http.MethodPost && path == "/api/consent/deny":
		return mutationAuditDescriptor{event: models.AuditConsentDenied, targetType: "oauth_consent"}, true
	case r.Method == http.MethodPost && path == "/api/my/clients":
		return mutationAuditDescriptor{event: models.AuditClientCreated, targetType: "client", successAlreadyAudited: true}, true
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/my/clients/"):
		return mutationAuditDescriptor{event: models.AuditClientDeleted, targetType: "client", targetID: param("id"), successAlreadyAudited: true}, true

	case r.Method == http.MethodPost && path == "/api/admin/users":
		return mutationAuditDescriptor{event: models.AuditUserCreated, targetType: "user"}, true
	case r.Method == http.MethodPut && strings.HasSuffix(path, "/role") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserRoleChanged, targetType: "user", targetID: param("id"), successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/suspend") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserSuspended, targetType: "user", targetID: param("id"), successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/activate") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserActivated, targetType: "user", targetID: param("id"), successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/reset-password") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserPasswordReset, targetType: "user", targetID: param("id")}, true
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserUpdated, targetType: "user", targetID: param("id")}, true
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserDeleted, targetType: "user", targetID: param("id")}, true

	case r.Method == http.MethodPost && path == "/api/admin/clients":
		return mutationAuditDescriptor{event: models.AuditClientCreated, targetType: "client"}, true
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/admin/clients/"):
		return mutationAuditDescriptor{event: models.AuditClientUpdated, targetType: "client", targetID: param("id")}, true
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/admin/clients/"):
		return mutationAuditDescriptor{event: models.AuditClientDeleted, targetType: "client", targetID: param("id")}, true

	case r.Method == http.MethodPost && path == "/api/admin/providers":
		return mutationAuditDescriptor{event: models.AuditProviderCreated, targetType: "provider", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/test") && strings.HasPrefix(path, "/api/admin/providers/"):
		return mutationAuditDescriptor{event: models.AuditProviderTested, targetType: "provider", targetID: param("id"), successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/admin/providers/"):
		return mutationAuditDescriptor{event: models.AuditProviderUpdated, targetType: "provider", targetID: param("id"), successAlreadyAudited: true}, true
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/admin/providers/"):
		return mutationAuditDescriptor{event: models.AuditProviderDeleted, targetType: "provider", targetID: param("id"), successAlreadyAudited: true}, true
	default:
		return mutationAuditDescriptor{}, false
	}
}

func userMutation(event string, actor *models.User, successAlreadyAudited bool) mutationAuditDescriptor {
	descriptor := mutationAuditDescriptor{event: event, targetType: "user", successAlreadyAudited: successAlreadyAudited}
	if actor != nil {
		descriptor.targetID = actor.ID.String()
	}
	return descriptor
}

func routePattern(r *http.Request) string {
	if routeContext := chi.RouteContext(r.Context()); routeContext != nil {
		if pattern := routeContext.RoutePattern(); pattern != "" {
			return pattern
		}
	}
	return r.URL.Path
}

func truncateAuditValue(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
