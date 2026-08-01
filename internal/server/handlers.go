package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/authorization"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/humanverification"
	"github.com/nyasharp/nyauth/internal/identity"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

const maxRequestBody = 1 << 20

type clientQuotaPage[T any] struct {
	*models.PaginatedResponse[T]
	*client.OwnerQuota
	ClientPolicy *settings.OAuthPolicy `json:"client_policy,omitempty"`
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("request body must contain one JSON value")
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeAPIError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message, "code": apiErrorCodeForMessage(message)})
}
func sessionResponse(current *models.User, data *session.SessionData) *models.SessionResponse {
	authenticatedAt := data.AuthenticatedAt
	sessionExpiresAt := data.SessionExpiresAt
	sessionIdleExpiresAt := data.SessionIdleExpiresAt
	recentAuthenticationExpiresAt := data.RecentAuthenticationExpiresAt
	if sessionExpiresAt.IsZero() || sessionIdleExpiresAt.IsZero() || recentAuthenticationExpiresAt.IsZero() {
		fallback := settings.DefaultLifecycle(365)
		sessionExpiresAt = data.CreatedAt.Add(fallback.SessionAbsoluteDuration())
		sessionIdleExpiresAt = data.LastSeenAt.Add(fallback.SessionIdleDuration())
		recentAuthenticationExpiresAt = data.AuthenticatedAt.Add(fallback.RecentAuthenticationDuration())
	}
	return &models.SessionResponse{
		User: current, CSRFToken: data.CSRFToken, MustChangePassword: current.MustChangePassword,
		HasPassword: current.PasswordHash != nil, EmailVerified: current.EmailVerifiedAt != nil,
		AuthenticatedAt:               &authenticatedAt,
		SessionExpiresAt:              &sessionExpiresAt,
		SessionIdleExpiresAt:          &sessionIdleExpiresAt,
		RecentAuthenticationExpiresAt: &recentAuthenticationExpiresAt,
	}
}

func setSessionNoStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	if !s.validSameOriginRequest(r) {
		writeAPIError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	var request struct {
		models.LoginRequest
		HumanVerification *humanVerificationProof `json:"human_verification,omitempty"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	ip := requestIP(r)
	allowed, retry, err := s.loginLimiter.Reserve(r.Context(), ip, strings.ToLower(request.Username))
	if err != nil {
		s.telemetry.RecordRateLimit(r.Context(), "login", "login", "error")
		s.telemetry.RecordAuthEvent(r.Context(), "login", "unavailable")
		writeAPIError(w, http.StatusServiceUnavailable, "login temporarily unavailable")
		return
	}
	if !allowed {
		s.telemetry.RecordRateLimit(r.Context(), "login", "login", "rejected")
		s.telemetry.RecordAuthEvent(r.Context(), "login", "rate_limited")
		seconds := int64((retry + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeAPIError(w, http.StatusTooManyRequests, "too many login attempts")
		return
	}
	s.telemetry.RecordRateLimit(r.Context(), "login", "login", "allowed")
	normalizedUsername := strings.ToLower(request.Username)
	failureCount, err := s.humanLoginFailures.FailureCount(r.Context(), ip, normalizedUsername)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "login temporarily unavailable")
		return
	}
	if !s.requireHumanVerification(w, r, humanverification.ActionLogin, failureCount, request.HumanVerification) {
		return
	}
	current, err := s.userService.Authenticate(r.Context(), request.Username, request.Password)
	if err != nil {
		var failureActorID *uuid.UUID
		failureActorName := truncateAuditValue(request.Username, maxAuditActorNameLength)
		if actorID, actorName, known := user.AuthenticationFailureActor(err); known {
			failureActorID = &actorID
			failureActorName = actorName
		}
		if errors.Is(err, user.ErrEmailVerificationPending) {
			s.telemetry.RecordAuthEvent(r.Context(), "login", "email_unverified")
			s.enqueueAuditResult(r.Context(), models.AuditUserLoginFailed, failureActorID, failureActorName, "failure", "low", ip, truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), map[string]any{"authentication_method": "password", "reason": "email_unverified"})
			writeAPIError(w, http.StatusForbidden, "email verification is required before signing in")
			return
		}
		if recordErr := s.humanLoginFailures.RecordFailure(r.Context(), ip, normalizedUsername); recordErr != nil {
			slog.WarnContext(r.Context(), "recording login failure for human verification failed", "error_class", "redis_unavailable")
		}
		s.telemetry.RecordAuthEvent(r.Context(), "login", "invalid_credentials")
		s.enqueueAuditResult(r.Context(), models.AuditUserLoginFailed, failureActorID, failureActorName, "failure", "medium", ip, truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), map[string]any{"authentication_method": "password"})
		writeAPIError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	returnTo := safeReturnPath(request.ReturnTo, "/dashboard")
	mfaResponse, mfaRequired, trustedDevice, err := s.beginMFAPending(w, r, current, "password", "", returnTo)
	if err != nil {
		if errors.Is(err, errMFAEnrollmentRequired) {
			s.telemetry.RecordAuthEvent(r.Context(), "login", "mfa_enrollment_required")
			writeAPIError(w, http.StatusForbidden, "MFA enrollment is required; contact an administrator")
		} else {
			s.telemetry.RecordAuthEvent(r.Context(), "login", "mfa_unavailable")
			writeAPIError(w, http.StatusServiceUnavailable, "MFA verification temporarily unavailable")
		}
		return
	}
	if mfaRequired {
		_ = s.loginLimiter.ResetIdentity(r.Context(), ip, strings.ToLower(request.Username))
		_ = s.humanLoginFailures.ResetIdentity(r.Context(), normalizedUsername)
		s.telemetry.RecordAuthEvent(r.Context(), "login", "mfa_required")
		writeJSON(w, http.StatusAccepted, mfaResponse)
		return
	}
	authenticated, err := s.sessionMiddleware.CreateSession(w, r, current)
	if err != nil {
		s.telemetry.RecordAuthEvent(r.Context(), "login", "session_error")
		writeAPIError(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	_ = s.loginLimiter.ResetIdentity(r.Context(), ip, strings.ToLower(request.Username))
	_ = s.humanLoginFailures.ResetIdentity(r.Context(), normalizedUsername)
	details := map[string]any{"authentication_method": "password"}
	if trustedDevice {
		details["second_factor"] = "trusted_device"
	}
	s.enqueueAuditResult(r.Context(), models.AuditUserLogin, &current.ID, current.Username, "success", "low", ip, truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), details)
	_ = s.userService.RecordLogin(r.Context(), current.ID, ip)
	s.telemetry.RecordAuthEvent(r.Context(), "login", "success")
	writeJSON(w, http.StatusOK, sessionResponse(current, authenticated.Data))
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	if current == nil || authenticated == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse(current, authenticated.Data))
}
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sessionMiddleware.DestroySession(w, r)
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	writeJSON(w, http.StatusOK, current)
}
func (s *Server) handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var request struct {
		DisplayName *string `json:"display_name,omitempty"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	updated, err := s.userService.Update(r.Context(), current.ID, models.UpdateUserRequest{DisplayName: request.DisplayName})
	if err != nil {
		if user.IsInvalidInput(err) {
			writeAPIError(w, http.StatusBadRequest, err.Error())
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to update profile")
		}
		return
	}
	writeJSON(w, http.StatusOK, updated)
}
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var request models.ChangePasswordRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	updated, err := s.userService.ChangePassword(r.Context(), current.ID, request.CurrentPassword, request.NewPassword, mutation)
	if err != nil {
		switch {
		case errors.Is(err, user.ErrInvalidCredentials):
			writeAPIError(w, http.StatusUnauthorized, "current password is incorrect")
		case errors.Is(err, user.ErrPasswordUnavailable):
			writeAPIError(w, http.StatusConflict, err.Error())
		case user.IsInvalidInput(err):
			writeAPIError(w, http.StatusBadRequest, err.Error())
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to change password")
		}
		return
	}
	s.revokeUserSecurityState(r.Context(), current.ID, "password_change")
	authenticated, err := s.sessionMiddleware.RotateSession(w, r, updated)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "password changed; please sign in again")
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse(updated, authenticated.Data))
}

func (s *Server) handleListProviders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.providerMgr.List())
}
func (s *Server) handleMyIdentities(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	items, err := s.identityStore.ListByUser(r.Context(), current.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to list identities")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleUserIdentities(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	items, err := s.identityStore.ListByUser(r.Context(), id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to list identities")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleAdminDeleteUserIdentity(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	identityID, err := uuid.Parse(chi.URLParam(r, "identity_id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid identity ID")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	if err := s.identityStore.DeleteOwned(r.Context(), userID, identityID, mutation); err != nil {
		switch {
		case errors.Is(err, identity.ErrLastAuthenticationMethod):
			writeAPIError(w, http.StatusConflict, err.Error())
		case identity.IsNotFound(err):
			writeAPIError(w, http.StatusNotFound, "identity not found")
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to remove identity")
		}
		return
	}
	s.revokeUserSecurityState(r.Context(), userID, "admin_identity_removal")
	if current := currentUserFromContext(r); current != nil && current.ID == userID {
		s.sessionMiddleware.DestroySession(w, r)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	var request models.AdminUpdateUserRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	before, err := s.userService.GetByID(r.Context(), id)
	if err != nil {
		if user.IsNotFound(err) {
			writeAPIError(w, http.StatusNotFound, "user not found")
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to get user")
		}
		return
	}
	if request.Username != nil {
		if !s.requireRecentAuthentication(w, r) {
			return
		}
	}
	updated, err := s.userService.AdminUpdate(r.Context(), id, request, mutation)
	if err != nil {
		switch {
		case errors.Is(err, user.ErrLastActiveAdmin):
			writeAPIError(w, http.StatusConflict, err.Error())
		case user.IsInvalidInput(err):
			writeAPIError(w, http.StatusBadRequest, err.Error())
		case user.IsUsernameConflict(err):
			writeAPIError(w, http.StatusConflict, "username is already taken")
		case user.IsConflict(err):
			writeAPIError(w, http.StatusConflict, "email is already taken")
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to update user")
		}
		return
	}
	if request.Email != nil && !strings.EqualFold(strings.TrimSpace(stringValue(before.Email)), strings.TrimSpace(*request.Email)) {
		s.revokeUserSecurityState(r.Context(), id, "admin_email_change")
		if current := currentUserFromContext(r); current != nil && current.ID == id {
			s.sessionMiddleware.DestroySession(w, r)
		}
	}
	writeJSON(w, http.StatusOK, updated)
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func (s *Server) handleSuspendUser(w http.ResponseWriter, r *http.Request) {
	s.handleUserStatus(w, r, models.UserStatusSuspended)
}
func (s *Server) handleActivateUser(w http.ResponseWriter, r *http.Request) {
	s.handleUserStatus(w, r, models.UserStatusActive)
}
func (s *Server) handleUserStatus(w http.ResponseWriter, r *http.Request, status models.UserStatus) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	updated, err := s.userService.AdminUpdate(r.Context(), id, models.AdminUpdateUserRequest{Status: &status}, mutation)
	if err != nil {
		if errors.Is(err, user.ErrLastActiveAdmin) || errors.Is(err, user.ErrAdminMFARequired) {
			writeAPIError(w, http.StatusConflict, err.Error())
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to update user status")
		}
		return
	}
	s.revokeUserSecurityState(r.Context(), id, "status_change")
	if current := currentUserFromContext(r); current != nil && current.ID == id {
		s.sessionMiddleware.DestroySession(w, r)
	}
	writeJSON(w, http.StatusOK, updated)
}
func (s *Server) handleUpdateUserRole(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	var request struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(w, r, &request); err != nil || (request.Role != "admin" && request.Role != "user") {
		writeAPIError(w, http.StatusBadRequest, "role must be admin or user")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	updated, err := s.userService.AdminUpdate(r.Context(), id, models.AdminUpdateUserRequest{Role: &request.Role}, mutation)
	if err != nil {
		if errors.Is(err, user.ErrLastActiveAdmin) || errors.Is(err, user.ErrAdminMFARequired) {
			writeAPIError(w, http.StatusConflict, err.Error())
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to update role")
		}
		return
	}
	s.revokeUserSecurityState(r.Context(), id, "role_change")
	if current := currentUserFromContext(r); current != nil && current.ID == id {
		s.sessionMiddleware.DestroySession(w, r)
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleAdminResetPassword(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	var request struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	if _, err := s.userService.ResetPassword(r.Context(), id, request.Password, mutation); err != nil {
		if user.IsInvalidInput(err) {
			writeAPIError(w, http.StatusBadRequest, err.Error())
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to reset password")
		}
		return
	}
	s.revokeUserSecurityState(r.Context(), id, "admin_password_reset")
	if current := currentUserFromContext(r); current != nil && current.ID == id {
		s.sessionMiddleware.DestroySession(w, r)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) revokeUserSecurityState(ctx context.Context, userID uuid.UUID, operation string) {
	authVersion, sessionVersion, err := s.securityVersions(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "security generation lookup failed",
			"operation", operation, "error_class", "database_error")
		return
	}
	if _, err := s.sessionStore.DeleteUserSessionsBeforeSecurityVersion(
		ctx, userID.String(), authVersion, sessionVersion,
	); err != nil {
		slog.ErrorContext(ctx, "user session cleanup failed", "operation", operation, "error_class", "redis_error")
	}
	if _, err := s.sessionStore.RevokeRefreshFamiliesBeforeAuthVersion(
		ctx, userID.String(), authVersion, s.tokenRevocationTTL(),
	); err != nil {
		slog.ErrorContext(ctx, "refresh family cleanup failed", "operation", operation, "error_class", "redis_error")
	}
}

func (s *Server) handleListMyClients(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	result, err := s.clientService.ListByOwner(r.Context(), current.ID.String(), 1, 50)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to list applications")
		return
	}
	quota, err := s.clientService.GetOwnerQuota(r.Context(), current.ID.String())
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load application quota")
		return
	}
	policy := s.settingsMgr.OAuthPolicy().SelfServiceView()
	writeJSON(w, http.StatusOK, clientQuotaPage[models.OAuthClient]{
		PaginatedResponse: result, OwnerQuota: quota, ClientPolicy: &policy,
	})
}

func (s *Server) handleRotateMyClientSecret(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id := chi.URLParam(r, "id")
	result, err := s.clientService.RotateSecretForOwner(r.Context(), id, current.ID.String())
	if err != nil {
		switch {
		case errors.Is(err, client.ErrClientNotOwned), errors.Is(err, pgx.ErrNoRows):
			writeAPIError(w, http.StatusNotFound, "application not found")
		case errors.Is(err, client.ErrPublicClientSecret):
			writeAPIError(w, http.StatusConflict, err.Error())
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to rotate application secret")
		}
		return
	}
	s.enqueueAuditTargetResult(r.Context(), models.AuditClientSecretRotated, &current.ID, current.Username, "client", id, "success", "medium", requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), nil)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleListMyAuthorizations(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	items, err := s.authorizationStore.ListByUser(r.Context(), current.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to list OAuth authorizations")
		return
	}
	active := items[:0]
	for index := range items {
		revoked, checkErr := s.sessionStore.IsUserClientAuthorizationRevoked(
			r.Context(), current.ID.String(), items[index].ClientID, items[index].GrantedAt.UnixMicro(),
		)
		if checkErr != nil {
			writeAPIError(w, http.StatusServiceUnavailable, "OAuth authorizations temporarily unavailable")
			return
		}
		if !revoked {
			active = append(active, items[index])
		}
	}
	writeJSON(w, http.StatusOK, active)
}

func (s *Server) handleRevokeMyAuthorization(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	clientID := strings.TrimSpace(chi.URLParam(r, "client_id"))
	if clientID == "" || len(clientID) > 64 {
		writeAPIError(w, http.StatusBadRequest, "invalid client ID")
		return
	}

	revokedAt, err := s.sessionStore.RevokeUserClientAuthorization(r.Context(), current.ID.String(), clientID, s.tokenRevocationTTL()+5*time.Minute)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "authorization revocation temporarily unavailable")
		return
	}
	if err := s.authorizationStore.Revoke(r.Context(), current.ID, clientID, time.UnixMicro(revokedAt).UTC()); err != nil {
		switch {
		case authorization.IsNotFound(err):
			writeAPIError(w, http.StatusNotFound, "OAuth authorization not found")
		case errors.Is(err, authorization.ErrAuthorizationNewer):
			writeAPIError(w, http.StatusConflict, "OAuth authorization changed; retry revocation")
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to revoke OAuth authorization")
		}
		return
	}
	s.enqueueAuditTargetResult(r.Context(), models.AuditAuthorizationRevoked, &current.ID, current.Username, "client", clientID, "success", "medium", requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) tokenRevocationTTL() time.Duration {
	if s.tokenService != nil {
		return s.tokenService.RevocationTTL()
	}
	if s.cfg == nil {
		return 30 * 24 * time.Hour
	}
	ttl := s.cfg.Auth.RefreshTokenTTL
	if s.cfg.Auth.AccessTokenTTL > ttl {
		ttl = s.cfg.Auth.AccessTokenTTL
	}
	if ttl <= 0 {
		return 30 * 24 * time.Hour
	}
	return ttl
}

func (s *Server) handleCreateMyClient(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	var request models.CreateClientRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := s.clientService.CreateForOwner(r.Context(), current.ID.String(), request)
	if err != nil {
		switch {
		case errors.Is(err, client.ErrSelfServiceDisabled):
			writeAPIError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, client.ErrOAuthPolicyChanged):
			writeAPIError(w, http.StatusConflict, "OAuth client policy changed; reload and retry")
		case errors.Is(err, client.ErrClientQuotaExceeded):
			writeAPIError(w, http.StatusForbidden, "application limit reached")
		case client.IsInvalidClient(err):
			writeAPIError(w, http.StatusBadRequest, err.Error())
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to create application")
		}
		return
	}
	s.enqueueAuditTargetResult(r.Context(), models.AuditClientCreated, &current.ID, current.Username, "client", result.ID, "success", "low", requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), nil)
	writeJSON(w, http.StatusCreated, result)
}
func (s *Server) handleDeleteMyClient(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	id := chi.URLParam(r, "id")
	registered, err := s.clientService.GetByID(r.Context(), id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "application not found")
		return
	}
	if registered.OwnerID == nil || *registered.OwnerID != current.ID.String() {
		writeAPIError(w, http.StatusForbidden, "application is not owned by current user")
		return
	}
	if err := s.clientService.DeleteForOwner(r.Context(), id, current.ID.String()); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to delete application")
		return
	}
	s.enqueueAuditTargetResult(r.Context(), models.AuditClientDeleted, &current.ID, current.Username, "client", id, "success", "medium", requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), nil)
	w.WriteHeader(http.StatusNoContent)
}
