package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/pkg/models"
)

type accountActionService interface {
	RequestPasswordReset(context.Context, string, account.RequestMetadata) error
	ConfirmPasswordReset(context.Context, string, string) (*models.User, error)
	RequestEmailVerification(context.Context, uuid.UUID, account.RequestMetadata) error
	ConfirmEmailVerification(context.Context, string) (*models.User, error)
	RequestEmailChange(context.Context, uuid.UUID, string, time.Time, account.RequestMetadata) error
	ConfirmEmailChange(context.Context, string) (*models.User, error)
}

type passwordResetRequest struct {
	Email string `json:"email"`
}

type passwordResetConfirmation struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type accountTokenConfirmation struct {
	Token string `json:"token"`
}

type emailChangeRequest struct {
	Email string `json:"email"`
}

func (s *Server) handleRequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	if !s.validSameOriginRequest(r) {
		writeAPIError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	if s.accountService == nil || s.accountLimiter == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "account recovery is unavailable")
		return
	}
	var request passwordResetRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	subject := strings.ToLower(strings.TrimSpace(request.Email))
	allowed, retry, err := s.accountLimiter.Reserve(r.Context(), "password-reset", requestIP(r), subject)
	if err != nil {
		s.telemetry.RecordRateLimit(r.Context(), "account_action", "password_reset", "error")
		s.telemetry.RecordAuthEvent(r.Context(), "password_reset_request", "unavailable")
		writeAPIError(w, http.StatusServiceUnavailable, "account recovery is temporarily unavailable")
		return
	}
	if !allowed {
		s.telemetry.RecordRateLimit(r.Context(), "account_action", "password_reset", "rejected")
		s.telemetry.RecordAuthEvent(r.Context(), "password_reset_request", "rate_limited")
		w.Header().Set("Retry-After", retryAfterSeconds(retry))
		writeAPIError(w, http.StatusTooManyRequests, "too many account recovery requests")
		return
	}
	s.telemetry.RecordRateLimit(r.Context(), "account_action", "password_reset", "allowed")
	if err := s.accountService.RequestPasswordReset(r.Context(), request.Email, accountRequestMetadata(r)); err != nil {
		// The public response deliberately remains indistinguishable from an
		// unknown account. Operators still receive a structured error signal.
		slog.ErrorContext(r.Context(), "password reset request could not be queued", "error", err)
		s.telemetry.RecordAuthEvent(r.Context(), "password_reset_request", "queue_error")
	} else {
		s.telemetry.RecordAuthEvent(r.Context(), "password_reset_request", "accepted")
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s *Server) handleConfirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	if !s.validSameOriginRequest(r) {
		writeAPIError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	if s.accountService == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "account recovery is unavailable")
		return
	}
	var request passwordResetConfirmation
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	updated, err := s.accountService.ConfirmPasswordReset(r.Context(), request.Token, request.NewPassword)
	if err != nil {
		s.writeAccountActionError(w, r, "password_reset", err)
		return
	}
	s.revokeSessionsAfterAccountChange(w, r, updated.ID, "password_reset")
	s.telemetry.RecordAuthEvent(r.Context(), "password_reset", "success")
	writeJSON(w, http.StatusOK, map[string]string{"status": "password_reset"})
}

func (s *Server) handleRequestEmailVerification(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	if s.accountService == nil || s.accountLimiter == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "email verification is unavailable")
		return
	}
	current := currentUserFromContext(r)
	allowed, retry, err := s.accountLimiter.Reserve(r.Context(), "email-verification", requestIP(r), current.ID.String())
	if err != nil {
		s.telemetry.RecordRateLimit(r.Context(), "account_action", "email_verification", "error")
		writeAPIError(w, http.StatusServiceUnavailable, "email verification is temporarily unavailable")
		return
	}
	if !allowed {
		s.telemetry.RecordRateLimit(r.Context(), "account_action", "email_verification", "rejected")
		w.Header().Set("Retry-After", retryAfterSeconds(retry))
		writeAPIError(w, http.StatusTooManyRequests, "too many email verification requests")
		return
	}
	s.telemetry.RecordRateLimit(r.Context(), "account_action", "email_verification", "allowed")
	if err := s.accountService.RequestEmailVerification(r.Context(), current.ID, accountRequestMetadata(r)); err != nil {
		s.writeAccountActionError(w, r, "email_verification_request", err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s *Server) handleConfirmEmailVerification(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	if !s.validSameOriginRequest(r) {
		writeAPIError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	if s.accountService == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "email verification is unavailable")
		return
	}
	var request accountTokenConfirmation
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if _, err := s.accountService.ConfirmEmailVerification(r.Context(), request.Token); err != nil {
		s.writeAccountActionError(w, r, "email_verification", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "email_verified"})
}

func (s *Server) handleRequestEmailChange(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	if s.accountService == nil || s.accountLimiter == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "email change is unavailable")
		return
	}
	var request emailChangeRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	allowed, retry, err := s.accountLimiter.Reserve(r.Context(), "email-change", requestIP(r), current.ID.String())
	if err != nil {
		s.telemetry.RecordRateLimit(r.Context(), "account_action", "email_change", "error")
		writeAPIError(w, http.StatusServiceUnavailable, "email change is temporarily unavailable")
		return
	}
	if !allowed {
		s.telemetry.RecordRateLimit(r.Context(), "account_action", "email_change", "rejected")
		w.Header().Set("Retry-After", retryAfterSeconds(retry))
		writeAPIError(w, http.StatusTooManyRequests, "too many email change requests")
		return
	}
	s.telemetry.RecordRateLimit(r.Context(), "account_action", "email_change", "allowed")
	if err := s.accountService.RequestEmailChange(r.Context(), current.ID, request.Email, authenticated.Data.AuthenticatedAt, accountRequestMetadata(r)); err != nil {
		s.writeAccountActionError(w, r, "email_change_request", err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s *Server) handleConfirmEmailChange(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	if !s.validSameOriginRequest(r) {
		writeAPIError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	if s.accountService == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "email change is unavailable")
		return
	}
	var request accountTokenConfirmation
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	updated, err := s.accountService.ConfirmEmailChange(r.Context(), request.Token)
	if err != nil {
		s.writeAccountActionError(w, r, "email_change", err)
		return
	}
	s.revokeSessionsAfterAccountChange(w, r, updated.ID, "email_change")
	writeJSON(w, http.StatusOK, map[string]string{"status": "email_changed"})
}

func (s *Server) revokeSessionsAfterAccountChange(w http.ResponseWriter, r *http.Request, userID uuid.UUID, operation string) {
	// auth_version is already incremented transactionally, so Redis failure
	// cannot make old credentials valid again. The explicit cleanup keeps the
	// security-center state and Redis memory consistent immediately.
	s.revokeUserSecurityState(r.Context(), userID, operation)
	s.sessionMiddleware.DestroySession(w, r)
}

func (s *Server) writeAccountActionError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	switch {
	case errors.Is(err, account.ErrInvalidActionToken):
		s.telemetry.RecordAuthEvent(r.Context(), operation, "invalid_token")
		writeAPIError(w, http.StatusBadRequest, "invalid or expired account action token")
	case errors.Is(err, account.ErrInvalidInput):
		s.telemetry.RecordAuthEvent(r.Context(), operation, "invalid_input")
		writeAPIError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, account.ErrEmailInUse):
		s.telemetry.RecordAuthEvent(r.Context(), operation, "email_conflict")
		writeAPIError(w, http.StatusConflict, "email address is already in use")
	case errors.Is(err, account.ErrRecentAuthenticationRequired):
		s.telemetry.RecordAuthEvent(r.Context(), operation, "reauthentication_required")
		writeAPIError(w, http.StatusForbidden, "recent authentication is required")
	case errors.Is(err, account.ErrAccountUnavailable):
		s.telemetry.RecordAuthEvent(r.Context(), operation, "account_unavailable")
		writeAPIError(w, http.StatusConflict, "account is unavailable")
	default:
		s.telemetry.RecordAuthEvent(r.Context(), operation, "error")
		slog.ErrorContext(r.Context(), "account action failed", "operation", operation, "error", err)
		writeAPIError(w, http.StatusInternalServerError, "account action failed")
	}
}

func accountRequestMetadata(r *http.Request) account.RequestMetadata {
	return account.RequestMetadata{IPAddress: requestIP(r), UserAgent: r.UserAgent()}
}

func retryAfterSeconds(retry time.Duration) string {
	seconds := int64((retry + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return strconv.FormatInt(seconds, 10)
}
