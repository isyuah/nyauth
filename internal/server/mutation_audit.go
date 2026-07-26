package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	maxAuditActorNameLength = 128
	maxAuditUserAgentLength = 512
)

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
	riskLevel             string
	successAlreadyAudited bool
}

func (s *Server) mutationAuditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		actor := currentUserFromContext(r)
		descriptor, ok := describeMutation(r, actor)
		if ok && actor != nil {
			riskLevel := descriptor.riskLevel
			if riskLevel == "" {
				riskLevel = "low"
			}
			r = r.WithContext(audit.WithMutationAudit(r.Context(), audit.MutationAudit{
				Event: descriptor.event, ActorID: actor.ID, ActorName: actor.Username,
				TargetType: descriptor.targetType, TargetID: descriptor.targetID,
				Result: "success", RiskLevel: riskLevel, IPAddress: requestIP(r),
				UserAgent: truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength),
				Details:   map[string]any{"method": r.Method, "path": routePattern(r)},
			}))
		}

		recorder := &auditResponseWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, r)

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
			if descriptor.riskLevel == "high" || descriptor.riskLevel == "critical" {
				riskLevel = descriptor.riskLevel
			}
		}

		actorName := actor.Username
		entry := &models.AuditLog{
			ID:        uuid.New(),
			Event:     descriptor.event,
			ActorID:   &actor.ID,
			ActorName: &actorName,
			Result:    result,
			RiskLevel: riskLevel,
			Details: map[string]any{
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
		s.enqueueAuditLog(r.Context(), entry)
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
		return highRiskUserMutation(models.AuditUserPasswordChanged, actor), true
	case r.Method == http.MethodPost && path == "/api/me/password/set":
		return highRiskUserMutation(models.AuditUserPasswordSet, actor), true
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/me/identities/"):
		return mutationAuditDescriptor{event: models.AuditIdentityUnbound, targetType: "identity", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/me/identities/") && strings.HasSuffix(path, "/bind"):
		return mutationAuditDescriptor{event: models.AuditIdentityBindStarted, targetType: "provider", targetID: param("provider")}, true
	case r.Method == http.MethodPost && path == "/api/consent/accept":
		return mutationAuditDescriptor{event: models.AuditConsentAccepted, targetType: "oauth_consent"}, true
	case r.Method == http.MethodPost && path == "/api/consent/deny":
		return mutationAuditDescriptor{event: models.AuditConsentDenied, targetType: "oauth_consent"}, true
	case r.Method == http.MethodPost && path == "/api/my/clients":
		return mutationAuditDescriptor{event: models.AuditClientCreated, targetType: "client", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/rotate-secret") && strings.HasPrefix(path, "/api/my/clients/"):
		return mutationAuditDescriptor{event: models.AuditClientSecretRotated, targetType: "client", targetID: param("id"), successAlreadyAudited: true}, true
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/my/clients/"):
		return mutationAuditDescriptor{event: models.AuditClientDeleted, targetType: "client", targetID: param("id"), successAlreadyAudited: true}, true
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/me/authorizations/"):
		return mutationAuditDescriptor{event: models.AuditAuthorizationRevoked, targetType: "client", targetID: param("client_id"), successAlreadyAudited: true}, true

	case r.Method == http.MethodPost && path == "/api/admin/users":
		return mutationAuditDescriptor{event: models.AuditUserCreated, targetType: "user"}, true
	case r.Method == http.MethodPut && strings.HasSuffix(path, "/role") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserRoleChanged, targetType: "user", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/suspend") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserSuspended, targetType: "user", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/activate") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserActivated, targetType: "user", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/reset-password") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserPasswordReset, targetType: "user", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodDelete && strings.HasSuffix(path, "/sessions") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserSessionsRevoked, targetType: "user", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserUpdated, targetType: "user", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodDelete && param("identity_id") != "" && strings.Contains(path, "/identities/") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditIdentityUnbound, targetType: "identity", targetID: param("identity_id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserDeleted, targetType: "user", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true

	case r.Method == http.MethodPost && path == "/api/admin/clients":
		return mutationAuditDescriptor{event: models.AuditClientCreated, targetType: "client", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/rotate-secret") && strings.HasPrefix(path, "/api/admin/clients/"):
		return mutationAuditDescriptor{event: models.AuditClientSecretRotated, targetType: "client", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && strings.HasSuffix(path, "/owner") && strings.HasPrefix(path, "/api/admin/clients/"):
		return mutationAuditDescriptor{event: models.AuditClientOwnerChanged, targetType: "client", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/admin/clients/"):
		return mutationAuditDescriptor{event: models.AuditClientUpdated, targetType: "client", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/admin/clients/"):
		return mutationAuditDescriptor{event: models.AuditClientDeleted, targetType: "client", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true

	case r.Method == http.MethodPost && path == "/api/admin/providers":
		return mutationAuditDescriptor{event: models.AuditProviderCreated, targetType: "provider", riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/test") && strings.HasPrefix(path, "/api/admin/providers/"):
		return mutationAuditDescriptor{event: models.AuditProviderTested, targetType: "provider", targetID: param("id"), successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/admin/providers/"):
		return mutationAuditDescriptor{event: models.AuditProviderUpdated, targetType: "provider", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/admin/providers/"):
		return mutationAuditDescriptor{event: models.AuditProviderDeleted, targetType: "provider", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
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

func highRiskUserMutation(event string, actor *models.User) mutationAuditDescriptor {
	descriptor := userMutation(event, actor, true)
	descriptor.riskLevel = "high"
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
