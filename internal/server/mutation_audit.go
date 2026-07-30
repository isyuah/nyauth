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
		if !ok {
			descriptor = mutationAuditDescriptor{
				event:      models.AuditMutationUnclassified,
				targetType: "route",
				targetID:   r.Method + " " + routePattern(r),
				riskLevel:  "medium",
			}
			ok = true
		}
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

		if actor == nil || s.auditStore == nil {
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
	case r.Method == http.MethodPost && path == "/api/me/avatar":
		return userMutation(models.AuditUserAvatarUpdated, actor, false), true
	case r.Method == http.MethodDelete && path == "/api/me/avatar":
		return userMutation(models.AuditUserAvatarRemoved, actor, false), true
	case r.Method == http.MethodPost && path == "/api/me/password":
		return highRiskUserMutation(models.AuditUserPasswordChanged, actor), true
	case r.Method == http.MethodPost && path == "/api/me/password/set":
		return highRiskUserMutation(models.AuditUserPasswordSet, actor), true
	case r.Method == http.MethodPost && path == "/api/me/mfa/totp/enroll/confirm":
		return highRiskUserMutation(models.AuditMFAEnrolled, actor), true
	case r.Method == http.MethodPost && path == "/api/me/mfa/recovery-codes":
		return highRiskUserMutation(models.AuditRecoveryCodesGenerated, actor), true
	case r.Method == http.MethodDelete && path == "/api/me/mfa/totp":
		return highRiskUserMutation(models.AuditMFADisabled, actor), true
	case r.Method == http.MethodPost && path == "/api/me/passkeys/registration/verify":
		return mutationAuditDescriptor{event: models.AuditPasskeyRegistered, targetType: "passkey", riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/me/passkeys/"):
		return mutationAuditDescriptor{event: models.AuditPasskeyRenamed, targetType: "passkey", targetID: param("id"), successAlreadyAudited: true}, true
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/me/passkeys/"):
		return mutationAuditDescriptor{event: models.AuditPasskeyRemoved, targetType: "passkey", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/me/identities/"):
		return mutationAuditDescriptor{event: models.AuditIdentityUnbound, targetType: "identity", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/me/identities/") && strings.HasSuffix(path, "/bind"):
		return mutationAuditDescriptor{event: models.AuditIdentityBindStarted, targetType: "provider", targetID: param("provider")}, true
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/me/sessions/"):
		return mutationAuditDescriptor{event: models.AuditSessionRevoked, targetType: "session", targetID: param("id"), riskLevel: "medium", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && path == "/api/me/sessions/revoke-others":
		descriptor := userMutation(models.AuditSessionOthersRevoked, actor, true)
		descriptor.riskLevel = "medium"
		return descriptor, true
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/me/reauth/"):
		descriptor := userMutation(models.AuditUserReauthenticated, actor, true)
		descriptor.riskLevel = "medium"
		return descriptor, true
	case r.Method == http.MethodPost && path == "/api/me/email/verification":
		descriptor := userMutation(models.AuditEmailVerifyRequested, actor, false)
		descriptor.riskLevel = "medium"
		return descriptor, true
	case r.Method == http.MethodPost && path == "/api/me/email/change":
		descriptor := userMutation(models.AuditEmailChangeRequested, actor, false)
		descriptor.riskLevel = "high"
		return descriptor, true
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
		return mutationAuditDescriptor{event: models.AuditUserCreated, targetType: "user", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && strings.HasSuffix(path, "/role") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserRoleChanged, targetType: "user", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/suspend") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserSuspended, targetType: "user", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/activate") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserActivated, targetType: "user", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/reset-password") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserPasswordReset, targetType: "user", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && strings.HasSuffix(path, "/client-quota") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserClientQuotaUpdated, targetType: "user", targetID: param("id"), riskLevel: "medium", successAlreadyAudited: true}, true
	case r.Method == http.MethodDelete && strings.HasSuffix(path, "/sessions") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditUserSessionsRevoked, targetType: "user", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodDelete && param("session_id") != "" && strings.Contains(path, "/sessions/") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditSessionRevoked, targetType: "user", targetID: param("id"), riskLevel: "medium", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/avatar") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditAdminUserAvatarUpdated, targetType: "user", targetID: param("id"), riskLevel: "medium"}, true
	case r.Method == http.MethodDelete && strings.HasSuffix(path, "/avatar") && strings.HasPrefix(path, "/api/admin/users/"):
		return mutationAuditDescriptor{event: models.AuditAdminUserAvatarRemoved, targetType: "user", targetID: param("id"), riskLevel: "medium"}, true
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
	case r.Method == http.MethodPut && strings.HasSuffix(path, "/access-users") && strings.HasPrefix(path, "/api/admin/clients/"):
		return mutationAuditDescriptor{event: models.AuditClientAccessChanged, targetType: "client", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/admin/clients/"):
		return mutationAuditDescriptor{event: models.AuditClientUpdated, targetType: "client", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/admin/clients/"):
		return mutationAuditDescriptor{event: models.AuditClientDeleted, targetType: "client", targetID: param("id"), riskLevel: "high", successAlreadyAudited: true}, true

	case r.Method == http.MethodPut && path == "/api/admin/settings/branding":
		return mutationAuditDescriptor{event: models.AuditSettingsUpdated, targetType: "settings", targetID: "branding", riskLevel: "medium", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && path == "/api/admin/settings/registration":
		return mutationAuditDescriptor{event: models.AuditSettingsUpdated, targetType: "settings", targetID: "registration", riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && path == "/api/admin/settings/security":
		return mutationAuditDescriptor{event: models.AuditSettingsUpdated, targetType: "settings", targetID: "security", riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && path == "/api/admin/settings/protection":
		return mutationAuditDescriptor{event: models.AuditSettingsUpdated, targetType: "settings", targetID: "protection", riskLevel: "critical", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && path == "/api/admin/settings/lifecycle":
		return mutationAuditDescriptor{event: models.AuditSettingsUpdated, targetType: "settings", targetID: "lifecycle", riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && path == "/api/admin/settings/oauth":
		return mutationAuditDescriptor{event: models.AuditSettingsUpdated, targetType: "settings", targetID: "oauth", riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && path == "/api/admin/settings/communications":
		return mutationAuditDescriptor{event: models.AuditSettingsUpdated, targetType: "settings", targetID: "communications", riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && path == "/api/admin/settings/communications/email/test":
		return mutationAuditDescriptor{event: models.AuditMailTemplateTested, targetType: "email_template", riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && path == "/api/admin/settings/operations":
		return mutationAuditDescriptor{event: models.AuditServiceControlUpdated, targetType: "settings", targetID: "operations", riskLevel: "critical", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && path == "/api/admin/settings/mail/candidate":
		return mutationAuditDescriptor{event: models.AuditMailSettingsSaved, targetType: "mail_config", riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && path == "/api/admin/settings/mail/candidate/test":
		return mutationAuditDescriptor{event: models.AuditMailSettingsTested, targetType: "mail_config", riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && path == "/api/admin/settings/mail/activate":
		return mutationAuditDescriptor{event: models.AuditMailSettingsActivated, targetType: "mail_config", riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && path == "/api/admin/settings/mail/rollback":
		return mutationAuditDescriptor{event: models.AuditMailSettingsRolledBack, targetType: "mail_runtime", targetID: "singleton", riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && path == "/api/admin/settings/mail/disable":
		return mutationAuditDescriptor{event: models.AuditMailSettingsDisabled, targetType: "mail_runtime", targetID: "singleton", riskLevel: "high", successAlreadyAudited: true}, true
	case r.Method == http.MethodPut && path == "/api/admin/settings/media/candidate":
		return mutationAuditDescriptor{event: models.AuditMediaSettingsSaved, targetType: "media_config", riskLevel: "critical", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && path == "/api/admin/settings/media/candidate/test":
		return mutationAuditDescriptor{event: models.AuditMediaSettingsTested, targetType: "media_config", riskLevel: "critical", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && path == "/api/admin/settings/media/migrations":
		return mutationAuditDescriptor{event: models.AuditMediaMigrationStarted, targetType: "media_migration", riskLevel: "critical", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && path == "/api/admin/settings/media/fallback/migrate":
		return mutationAuditDescriptor{event: models.AuditMediaMigrationStarted, targetType: "media_migration", riskLevel: "critical", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/retry") && strings.HasPrefix(path, "/api/admin/settings/media/migrations/"):
		return mutationAuditDescriptor{event: models.AuditMediaMigrationRetried, targetType: "media_migration", targetID: param("id"), riskLevel: "critical", successAlreadyAudited: true}, true
	case r.Method == http.MethodPost && path == "/api/admin/invites":
		return mutationAuditDescriptor{event: models.AuditInviteCreated, targetType: "invite", riskLevel: "medium", successAlreadyAudited: true}, true
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/admin/invites/"):
		return mutationAuditDescriptor{event: models.AuditInviteRevoked, targetType: "invite", targetID: param("id"), riskLevel: "medium", successAlreadyAudited: true}, true

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
