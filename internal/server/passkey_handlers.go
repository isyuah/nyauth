package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/mfa"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	webAuthnCeremonyHeader = "X-WebAuthn-Ceremony"
	webAuthnCeremonyTTL    = 5 * time.Minute

	passkeyPurposeLogin        = "login"
	passkeyPurposeMFA          = "mfa"
	passkeyPurposeReauth       = "reauthentication"
	passkeyPurposeRegistration = "registration"
)

type webAuthnOptionsResponse struct {
	CeremonyID string    `json:"ceremony_id"`
	PublicKey  any       `json:"public_key"`
	Mediation  string    `json:"mediation,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type passkeyRegistrationResponse struct {
	*models.SessionResponse
	Passkey mfa.PasskeyCredential `json:"passkey"`
}

func (s *Server) handleBeginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	if !s.validSameOriginRequest(r) {
		writeAPIError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	var request struct {
		Conditional bool   `json:"conditional"`
		ReturnTo    string `json:"return_to,omitempty"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !s.reservePasskeyCeremony(w, r) {
		return
	}
	options, err := s.mfaService.BeginDiscoverablePasskeyLogin(request.Conditional)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "Passkey login temporarily unavailable")
		return
	}
	data := &session.WebAuthnCeremonyData{
		SessionData: options.Session, Purpose: passkeyPurposeLogin,
		ReturnTo: safeReturnPath(request.ReturnTo, "/dashboard"), ExpiresAt: options.ExpiresAt,
	}
	ceremonyID, err := s.saveWebAuthnCeremony(r.Context(), data)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "Passkey login temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, webAuthnOptionsResponse{
		CeremonyID: ceremonyID, PublicKey: options.PublicKey,
		Mediation: string(options.Mediation), ExpiresAt: data.ExpiresAt,
	})
}

func (s *Server) handleFinishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	if !s.validSameOriginRequest(r) {
		writeAPIError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	ceremonyID, ceremony, ok := s.loadWebAuthnCeremony(w, r, passkeyPurposeLogin)
	if !ok {
		return
	}
	allowed, retry, err := s.loginLimiter.ReserveIP(r.Context(), requestIP(r))
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "Passkey login temporarily unavailable")
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", strconv.FormatInt(int64((retry+time.Second-1)/time.Second), 10))
		writeAPIError(w, http.StatusTooManyRequests, "too many login attempts")
		return
	}
	parsed, err := parsePasskeyAssertion(w, r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid Passkey response")
		return
	}
	authentication, err := s.mfaService.FinishDiscoverablePasskeyLogin(
		r.Context(), ceremony.SessionData, parsed,
		s.consumeWebAuthnCeremony(ceremonyID, ceremony),
		mfa.AuditContext{IPAddress: requestIP(r), UserAgent: truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength)},
		time.Now().UTC(),
	)
	if err != nil {
		s.handlePasskeyAuthenticationError(w, r, err, "login", nil, "")
		return
	}
	current, err := s.userService.GetByID(r.Context(), authentication.UserID)
	if err != nil {
		if user.IsNotFound(err) {
			writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		} else {
			writeAPIError(w, http.StatusServiceUnavailable, "Passkey login temporarily unavailable")
		}
		return
	}
	if current.Status != models.UserStatusActive ||
		current.AuthVersion != authentication.AuthVersion || current.SessionVersion != authentication.SessionVersion {
		writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		return
	}
	authenticated, err := s.sessionMiddleware.CreateSession(w, r, current)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "failed to create session")
		return
	}
	ip := requestIP(r)
	s.enqueueAuditResult(r.Context(), models.AuditUserLogin, &current.ID, current.Username, "success", "low", ip, truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), map[string]any{"authentication_method": "passkey"})
	_ = s.userService.RecordLogin(r.Context(), current.ID, ip)
	s.telemetry.RecordAuthEvent(r.Context(), "login", "success")
	writeJSON(w, http.StatusOK, sessionResponse(current, authenticated.Data))
}

func (s *Server) handleBeginMFAPasskey(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	if !s.validSameOriginRequest(r) {
		writeAPIError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	pending, current, methods, _, err := s.loadMFAPendingUser(w, r)
	if err != nil {
		s.writeMFAChallengeUnavailable(w, r, err)
		return
	}
	releaseIssuance, allowed := s.acquireMFAIssuance(w, pending.Data.Purpose)
	if !allowed {
		return
	}
	defer releaseIssuance()
	if !validPendingCSRF(pending, r) {
		writeAPIError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}
	if !containsString(methods, "passkey") {
		writeAPIError(w, http.StatusBadRequest, "Passkey is not available for this challenge")
		return
	}
	if !s.reservePasskeyCeremony(w, r) {
		return
	}
	options, err := s.mfaService.BeginKnownPasskeyAuthentication(r.Context(), current)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "Passkey verification temporarily unavailable")
		return
	}
	data := &session.WebAuthnCeremonyData{
		SessionData: options.Session, Purpose: passkeyPurposeMFA,
		UserID: current.ID.String(), Username: current.Username,
		AuthVersion: pending.Data.AuthVersion, SessionVersion: pending.Data.SessionVersion,
		ParentDigest: providerSessionDigest(pending.Token), ExpiresAt: options.ExpiresAt,
	}
	ceremonyID, err := s.saveWebAuthnCeremony(r.Context(), data)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "Passkey verification temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, webAuthnOptionsResponse{
		CeremonyID: ceremonyID, PublicKey: options.PublicKey,
		Mediation: string(options.Mediation), ExpiresAt: data.ExpiresAt,
	})
}

func (s *Server) handleFinishMFAPasskey(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	if !s.validSameOriginRequest(r) {
		writeAPIError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	pending, current, methods, authenticated, err := s.loadMFAPendingUser(w, r)
	if err != nil {
		s.writeMFAChallengeUnavailable(w, r, err)
		return
	}
	releaseIssuance, allowed := s.acquireMFAIssuance(w, pending.Data.Purpose)
	if !allowed {
		return
	}
	defer releaseIssuance()
	if !validPendingCSRF(pending, r) {
		writeAPIError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}
	if !containsString(methods, "passkey") {
		writeAPIError(w, http.StatusBadRequest, "Passkey is not available for this challenge")
		return
	}
	ceremonyID, ceremony, ok := s.loadWebAuthnCeremony(w, r, passkeyPurposeMFA)
	if !ok {
		return
	}
	if ceremony.UserID != current.ID.String() || ceremony.AuthVersion != pending.Data.AuthVersion ||
		ceremony.SessionVersion != pending.Data.SessionVersion ||
		!sameSessionDigest(ceremony.ParentDigest, providerSessionDigest(pending.Token)) {
		s.writeMFAChallengeUnavailable(w, r, session.ErrValueMismatch)
		return
	}
	limitIdentity := "mfa:" + current.ID.String()
	allowed, retry, err := s.loginLimiter.Reserve(r.Context(), requestIP(r), limitIdentity)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "Passkey verification temporarily unavailable")
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", strconv.FormatInt(int64((retry+time.Second-1)/time.Second), 10))
		writeAPIError(w, http.StatusTooManyRequests, "too many MFA attempts")
		return
	}
	parsed, err := parsePasskeyAssertion(w, r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid Passkey response")
		return
	}
	gate := mfa.ChallengeCommitGate{
		AuthVersion: pending.Data.AuthVersion, SessionVersion: pending.Data.SessionVersion,
		Consume: func(ctx context.Context) error {
			return s.sessionStore.ConsumeWebAuthnCeremonyAndMFAPending(
				ctx, ceremonyID, ceremony, pending.Token, pending.Data,
			)
		},
	}
	_, err = s.mfaService.FinishKnownPasskeyAuthentication(
		r.Context(), current, ceremony.SessionData, parsed, gate,
		"mfa_"+pending.Data.Purpose, s.mfaAuditContext(r, current), time.Now().UTC(),
	)
	if err != nil {
		s.handlePasskeyAuthenticationError(w, r, err, "mfa", current, pending.Data.PrimaryMethod)
		return
	}
	s.sessionMiddleware.clearNamedCookie(w, mfaPendingCookieName)
	s.completeMFAChallenge(w, r, pending, current, authenticated, "passkey", limitIdentity)
}

func (s *Server) handleBeginPasskeyReauthentication(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	if !s.reservePasskeyCeremony(w, r) {
		return
	}
	options, err := s.mfaService.BeginKnownPasskeyAuthentication(r.Context(), current)
	if err != nil {
		if errors.Is(err, mfa.ErrPasskeyNotFound) {
			writeAPIError(w, http.StatusConflict, "no Passkey is registered")
		} else {
			writeAPIError(w, http.StatusServiceUnavailable, "Passkey reauthentication temporarily unavailable")
		}
		return
	}
	data := &session.WebAuthnCeremonyData{
		SessionData: options.Session, Purpose: passkeyPurposeReauth,
		UserID: current.ID.String(), Username: current.Username,
		AuthVersion: authenticated.Data.AuthVersion, SessionVersion: authenticated.Data.SessionVersion,
		SessionDigest: providerSessionDigest(authenticated.ID), ExpiresAt: options.ExpiresAt,
	}
	ceremonyID, err := s.saveWebAuthnCeremony(r.Context(), data)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "Passkey reauthentication temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, webAuthnOptionsResponse{
		CeremonyID: ceremonyID, PublicKey: options.PublicKey,
		Mediation: string(options.Mediation), ExpiresAt: data.ExpiresAt,
	})
}

func (s *Server) handleFinishPasskeyReauthentication(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	ceremonyID, ceremony, ok := s.loadWebAuthnCeremony(w, r, passkeyPurposeReauth)
	if !ok {
		return
	}
	if ceremony.UserID != current.ID.String() || ceremony.AuthVersion != authenticated.Data.AuthVersion ||
		ceremony.SessionVersion != authenticated.Data.SessionVersion ||
		!sameSessionDigest(ceremony.SessionDigest, providerSessionDigest(authenticated.ID)) {
		writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		return
	}
	limitIdentity := "passkey-reauth:" + current.ID.String()
	allowed, retry, err := s.loginLimiter.Reserve(r.Context(), requestIP(r), limitIdentity)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "Passkey reauthentication temporarily unavailable")
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", strconv.FormatInt(int64((retry+time.Second-1)/time.Second), 10))
		writeAPIError(w, http.StatusTooManyRequests, "too many reauthentication attempts")
		return
	}
	parsed, err := parsePasskeyAssertion(w, r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid Passkey response")
		return
	}
	gate := mfa.ChallengeCommitGate{
		AuthVersion: ceremony.AuthVersion, SessionVersion: ceremony.SessionVersion,
		Consume: s.consumeWebAuthnCeremony(ceremonyID, ceremony),
	}
	credential, err := s.mfaService.FinishKnownPasskeyAuthentication(
		r.Context(), current, ceremony.SessionData, parsed, gate,
		passkeyPurposeReauth, s.mfaAuditContext(r, current), time.Now().UTC(),
	)
	if err != nil {
		s.handlePasskeyAuthenticationError(w, r, err, "reauthentication", current, "passkey")
		return
	}
	current, err = s.userService.GetByID(r.Context(), current.ID)
	if err != nil {
		if user.IsNotFound(err) {
			writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		} else {
			writeAPIError(w, http.StatusServiceUnavailable, "Passkey reauthentication temporarily unavailable")
		}
		return
	}
	if current.Status != models.UserStatusActive ||
		current.AuthVersion != ceremony.AuthVersion || current.SessionVersion != ceremony.SessionVersion {
		writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		return
	}
	updated, err := s.userService.RecordAuthentication(r.Context(), current.ID, ceremony.AuthVersion, ceremony.SessionVersion)
	if err != nil {
		if errors.Is(err, user.ErrAuthStateChanged) {
			writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		} else {
			writeAPIError(w, http.StatusServiceUnavailable, "reauthentication failed")
		}
		return
	}
	marked, err := s.sessionMiddleware.MarkReauthenticated(w, r, updated)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "reauthentication session could not be updated")
		return
	}
	s.enqueueAuditTargetResult(r.Context(), models.AuditUserReauthenticated, &updated.ID, updated.Username, "user", updated.ID.String(), "success", "medium", requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), map[string]any{
		"authentication_method": "passkey", "passkey_id": credential.ID.String(),
	})
	s.telemetry.RecordAuthEvent(r.Context(), "reauthentication", "success")
	writeJSON(w, http.StatusOK, sessionResponse(updated, marked.Data))
}

func (s *Server) handleListPasskeys(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	credentials, err := s.mfaService.ListPasskeys(r.Context(), current.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load Passkeys")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": credentials})
}

func (s *Server) handleBeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	if !s.requireRecentAuthentication(w, r) {
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	name, err := mfa.ValidatePasskeyName(request.Name)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "Passkey name must contain 1 to 64 characters")
		return
	}
	if !s.reservePasskeyCeremony(w, r) {
		return
	}
	options, err := s.mfaService.BeginPasskeyRegistration(r.Context(), current)
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrPasskeysDisabled):
			writeAPIError(w, http.StatusConflict, "Passkey enrollment is disabled")
		default:
			writeAPIError(w, http.StatusServiceUnavailable, "Passkey registration temporarily unavailable")
		}
		return
	}
	data := &session.WebAuthnCeremonyData{
		SessionData: options.Session, Purpose: passkeyPurposeRegistration,
		UserID: current.ID.String(), Username: current.Username,
		AuthVersion: authenticated.Data.AuthVersion, SessionVersion: authenticated.Data.SessionVersion,
		SessionDigest: providerSessionDigest(authenticated.ID), CredentialName: name,
		ExpiresAt: options.ExpiresAt,
	}
	ceremonyID, err := s.saveWebAuthnCeremony(r.Context(), data)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "Passkey registration temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, webAuthnOptionsResponse{
		CeremonyID: ceremonyID, PublicKey: options.PublicKey,
		ExpiresAt: data.ExpiresAt,
	})
}

func (s *Server) handleFinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	if !s.requireRecentAuthentication(w, r) {
		return
	}
	ceremonyID, ceremony, ok := s.loadWebAuthnCeremony(w, r, passkeyPurposeRegistration)
	if !ok {
		return
	}
	if ceremony.UserID != current.ID.String() || ceremony.AuthVersion != authenticated.Data.AuthVersion ||
		ceremony.SessionVersion != authenticated.Data.SessionVersion ||
		!sameSessionDigest(ceremony.SessionDigest, providerSessionDigest(authenticated.ID)) {
		writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		return
	}
	parsed, err := parsePasskeyCreation(w, r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid Passkey response")
		return
	}
	binding := mfa.AuthenticationBinding{AuthVersion: ceremony.AuthVersion, SessionVersion: ceremony.SessionVersion}
	credential, err := s.mfaService.FinishPasskeyRegistration(
		r.Context(), current, binding, ceremony.CredentialName, ceremony.SessionData, parsed,
		mfa.ChallengeCommitGate{
			AuthVersion: ceremony.AuthVersion, SessionVersion: ceremony.SessionVersion,
			Consume: s.consumeWebAuthnCeremony(ceremonyID, ceremony),
		},
		s.mfaAuditContext(r, current), time.Now().UTC(),
	)
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrInvalidPasskey):
			writeAPIError(w, http.StatusUnauthorized, "Passkey registration could not be verified")
		case errors.Is(err, mfa.ErrPasskeyAlreadyRegistered):
			writeAPIError(w, http.StatusConflict, "this Passkey is already registered")
		case errors.Is(err, mfa.ErrPasskeysDisabled):
			writeAPIError(w, http.StatusConflict, "Passkey enrollment is disabled")
		case errors.Is(err, mfa.ErrAuthenticationChanged), errors.Is(err, session.ErrValueMismatch), errors.Is(err, session.ErrNotFound):
			writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to register Passkey")
		}
		return
	}
	s.revokeUserSecurityState(r.Context(), current.ID, "passkey_registered")
	updated, err := s.userService.GetByID(r.Context(), current.ID)
	if err != nil {
		s.sessionMiddleware.DestroySession(w, r)
		if user.IsNotFound(err) {
			writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		} else {
			writeAPIError(w, http.StatusInternalServerError, "Passkey registered; please sign in again")
		}
		return
	}
	if updated.Status != models.UserStatusActive ||
		updated.AuthVersion != binding.AuthVersion+1 || updated.SessionVersion != binding.SessionVersion {
		s.sessionMiddleware.DestroySession(w, r)
		writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		return
	}
	rotated, err := s.sessionMiddleware.RotateSession(w, r, updated)
	if err != nil {
		s.sessionMiddleware.DestroySession(w, r)
		writeAPIError(w, http.StatusInternalServerError, "Passkey registered; please sign in again")
		return
	}
	writeJSON(w, http.StatusOK, passkeyRegistrationResponse{
		SessionResponse: sessionResponse(updated, rotated.Data), Passkey: credential,
	})
}

func (s *Server) handleRenamePasskey(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	passkeyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid Passkey ID")
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	credential, err := s.mfaService.RenamePasskey(r.Context(), current.ID, passkeyID, request.Name, s.mfaAuditContext(r, current), time.Now().UTC())
	if err != nil {
		if errors.Is(err, mfa.ErrInvalidPasskeyName) {
			writeAPIError(w, http.StatusBadRequest, "Passkey name must contain 1 to 64 characters")
		} else if errors.Is(err, mfa.ErrPasskeyNotFound) {
			writeAPIError(w, http.StatusNotFound, "Passkey not found")
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to rename Passkey")
		}
		return
	}
	writeJSON(w, http.StatusOK, credential)
}

func (s *Server) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	if !s.requireRecentAuthentication(w, r) {
		return
	}
	passkeyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid Passkey ID")
		return
	}
	binding := mfa.AuthenticationBinding{AuthVersion: authenticated.Data.AuthVersion, SessionVersion: authenticated.Data.SessionVersion}
	err = s.mfaService.DeletePasskey(r.Context(), current.ID, passkeyID, binding, s.mfaAuditContext(r, current), time.Now().UTC())
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrPasskeyNotFound):
			writeAPIError(w, http.StatusNotFound, "Passkey not found")
		case errors.Is(err, mfa.ErrLastAuthenticationMethod):
			writeAPIError(w, http.StatusConflict, "add a password, Provider identity, or another Passkey before removing this Passkey")
		case errors.Is(err, mfa.ErrRequiredByPolicy):
			writeAPIError(w, http.StatusConflict, "MFA is required for active administrators")
		case errors.Is(err, mfa.ErrAuthenticationChanged):
			s.sessionMiddleware.DestroySession(w, r)
			writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to remove Passkey")
		}
		return
	}
	s.revokeUserSecurityState(r.Context(), current.ID, "passkey_removed")
	updated, err := s.userService.GetByID(r.Context(), current.ID)
	if err != nil {
		s.sessionMiddleware.DestroySession(w, r)
		if user.IsNotFound(err) {
			writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		} else {
			writeAPIError(w, http.StatusInternalServerError, "Passkey removed; please sign in again")
		}
		return
	}
	if updated.Status != models.UserStatusActive ||
		updated.AuthVersion != binding.AuthVersion+1 || updated.SessionVersion != binding.SessionVersion {
		s.sessionMiddleware.DestroySession(w, r)
		writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		return
	}
	rotated, err := s.sessionMiddleware.RotateSession(w, r, updated)
	if err != nil {
		s.sessionMiddleware.DestroySession(w, r)
		writeAPIError(w, http.StatusInternalServerError, "Passkey removed; please sign in again")
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse(updated, rotated.Data))
}

func (s *Server) saveWebAuthnCeremony(ctx context.Context, data *session.WebAuthnCeremonyData) (string, error) {
	ceremonyID, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", err
	}
	ttl := time.Until(data.ExpiresAt)
	if ttl <= 0 {
		return "", session.ErrInvalidTokenData
	}
	if ttl > webAuthnCeremonyTTL {
		ttl = webAuthnCeremonyTTL
	}
	if err := s.sessionStore.SaveWebAuthnCeremony(ctx, ceremonyID, data, ttl); err != nil {
		return "", err
	}
	return ceremonyID, nil
}

func (s *Server) loadWebAuthnCeremony(w http.ResponseWriter, r *http.Request, purpose string) (string, *session.WebAuthnCeremonyData, bool) {
	ceremonyID := strings.TrimSpace(r.Header.Get(webAuthnCeremonyHeader))
	if ceremonyID == "" {
		writeAPIError(w, http.StatusBadRequest, "WebAuthn ceremony ID is required")
		return "", nil, false
	}
	data, err := s.sessionStore.GetWebAuthnCeremony(r.Context(), ceremonyID)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			writeAPIError(w, http.StatusUnauthorized, "WebAuthn ceremony expired")
		} else {
			writeAPIError(w, http.StatusServiceUnavailable, "WebAuthn ceremony temporarily unavailable")
		}
		return "", nil, false
	}
	if data.Purpose != purpose {
		writeAPIError(w, http.StatusUnauthorized, "WebAuthn ceremony is invalid")
		return "", nil, false
	}
	return ceremonyID, data, true
}

func (s *Server) consumeWebAuthnCeremony(ceremonyID string, expected *session.WebAuthnCeremonyData) func(context.Context) error {
	return func(ctx context.Context) error {
		consumed, err := s.sessionStore.ConsumeWebAuthnCeremony(ctx, ceremonyID)
		if err != nil {
			return err
		}
		if !sameWebAuthnCeremony(expected, consumed) {
			return session.ErrValueMismatch
		}
		return nil
	}
}

func sameWebAuthnCeremony(left, right *session.WebAuthnCeremonyData) bool {
	if left == nil || right == nil {
		return false
	}
	return bytes.Equal(left.SessionData, right.SessionData) &&
		left.Purpose == right.Purpose && left.UserID == right.UserID && left.Username == right.Username &&
		left.AuthVersion == right.AuthVersion && left.SessionVersion == right.SessionVersion &&
		left.SessionDigest == right.SessionDigest && left.ParentDigest == right.ParentDigest &&
		left.CredentialName == right.CredentialName && left.ReturnTo == right.ReturnTo &&
		left.CreatedAt.Equal(right.CreatedAt) && left.ExpiresAt.Equal(right.ExpiresAt)
}

func parsePasskeyAssertion(w http.ResponseWriter, r *http.Request) (*protocol.ParsedCredentialAssertionData, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	return protocol.ParseCredentialRequestResponseBody(r.Body)
}

func parsePasskeyCreation(w http.ResponseWriter, r *http.Request) (*protocol.ParsedCredentialCreationData, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	return protocol.ParseCredentialCreationResponseBody(r.Body)
}

func (s *Server) reservePasskeyCeremony(w http.ResponseWriter, r *http.Request) bool {
	allowed, retry, err := s.loginLimiter.ReservePasskeyCeremony(r.Context(), requestIP(r))
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "Passkey ceremony temporarily unavailable")
		return false
	}
	if !allowed {
		w.Header().Set("Retry-After", strconv.FormatInt(int64((retry+time.Second-1)/time.Second), 10))
		writeAPIError(w, http.StatusTooManyRequests, "too many Passkey ceremonies")
		return false
	}
	return true
}

func (s *Server) handlePasskeyAuthenticationError(
	w http.ResponseWriter,
	r *http.Request,
	err error,
	purpose string,
	current *models.User,
	primaryMethod string,
) {
	switch {
	case errors.Is(err, mfa.ErrInvalidPasskey):
		var actorID *uuid.UUID
		actorName := ""
		if current != nil {
			actorID = &current.ID
			actorName = current.Username
		}
		details := map[string]any{"authentication_method": "passkey", "purpose": purpose}
		if primaryMethod != "" {
			details["primary_method"] = primaryMethod
		}
		s.enqueueAuditResult(r.Context(), models.AuditUserLoginFailed, actorID, actorName, "failure", "medium", requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), details)
		writeAPIError(w, http.StatusUnauthorized, "Passkey verification failed")
	case errors.Is(err, mfa.ErrAuthenticationChanged), errors.Is(err, session.ErrValueMismatch), errors.Is(err, session.ErrNotFound):
		writeAPIError(w, http.StatusUnauthorized, "authentication challenge expired")
	default:
		writeAPIError(w, http.StatusServiceUnavailable, "Passkey verification temporarily unavailable")
	}
}
