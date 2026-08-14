package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/mfa"
	"github.com/nyasharp/nyauth/internal/notification"
	"github.com/nyasharp/nyauth/internal/oauthstepup"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

var errMFAEnrollmentRequired = errors.New("MFA enrollment is required by policy")

const (
	mfaPurposeLogin            = "login"
	mfaPurposeReauthentication = "reauthentication"
	mfaPurposeOAuthStepUp      = "oauth_step_up"
)

type myMFAResponse struct {
	LoginMFAEnabled        bool `json:"login_mfa_enabled"`
	LoginMFARequired       bool `json:"login_mfa_required"`
	CanEnableLoginMFA      bool `json:"can_enable_login_mfa"`
	TOTPAvailable          bool `json:"totp_available"`
	TOTPEnrolled           bool `json:"totp_enrolled"`
	CanDisableTOTP         bool `json:"can_disable_totp"`
	PasskeysAvailable      bool `json:"passkeys_available"`
	PasskeysEnrolled       int  `json:"passkeys_enrolled"`
	RecoveryCodesRemaining int  `json:"recovery_codes_remaining"`
	RequireMFAForAdmins    bool `json:"require_mfa_for_admins"`
	RequiredForCurrentUser bool `json:"required_for_current_user"`
}

type totpConfirmationResponse struct {
	*models.SessionResponse
	RecoveryCodes []string `json:"recovery_codes"`
}

type recoveryCodesResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

func (s *Server) loginMFARequirement(r *http.Request, current *models.User) ([]string, bool, error) {
	if s.mfaService == nil {
		return []string{}, false, nil
	}
	methods, err := s.mfaService.LoginMethods(r.Context(), current.ID)
	if err != nil {
		return nil, false, err
	}
	required := current.LoginMFAEnabled || (current.Role == "admin" && s.settingsMgr.Security().RequireMFAForAdmins)
	if required && len(methods) == 0 {
		return nil, true, errMFAEnrollmentRequired
	}
	return methods, required, nil
}

func (s *Server) beginMFAPending(
	w http.ResponseWriter,
	r *http.Request,
	current *models.User,
	primaryMethod, provider, returnTo string,
) (*models.MFARequiredResponse, bool, bool, error) {
	methods, required, err := s.loginMFARequirement(r, current)
	if err != nil || !required {
		return nil, required, false, err
	}
	if s.useTrustedDevice(w, r, current) {
		return nil, false, true, nil
	}
	pending, err := s.sessionMiddleware.CreateMFAPending(w, r, &session.MFAPendingData{
		UserID: current.ID.String(), Username: current.Username,
		AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
		Purpose: mfaPurposeLogin, PrimaryMethod: primaryMethod, Provider: provider,
		ReturnTo: safeReturnPath(returnTo, "/dashboard"), CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		return nil, true, false, err
	}
	security := s.settingsMgr.Security()
	return &models.MFARequiredResponse{
		Status: "mfa_required", Purpose: mfaPurposeLogin, Username: current.Username, Methods: methods,
		CSRFToken: pending.Data.CSRFToken, ExpiresAt: pending.Data.ExpiresAt,
		TrustedDeviceAvailable:  security.TrustedDevicesEnabled,
		TrustedDeviceTTLSeconds: int64(security.TrustedDeviceDuration() / time.Second),
	}, true, false, nil
}

func (s *Server) beginReauthenticationMFAPending(
	w http.ResponseWriter,
	r *http.Request,
	current *models.User,
	primaryMethod, provider, returnTo string,
) (*models.MFARequiredResponse, bool, error) {
	if s.mfaService == nil {
		return nil, false, nil
	}
	methods, err := s.mfaService.LoginMethods(r.Context(), current.ID)
	if err != nil || len(methods) == 0 {
		return nil, false, err
	}
	authenticated := sessionFromContext(r.Context())
	if authenticated == nil {
		return nil, true, session.ErrNotFound
	}
	pending, err := s.sessionMiddleware.CreateMFAPending(w, r, &session.MFAPendingData{
		UserID: current.ID.String(), Username: current.Username,
		AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
		Purpose: mfaPurposeReauthentication, PrimaryMethod: primaryMethod, Provider: provider,
		SessionDigest: providerSessionDigest(authenticated.ID),
		ReturnTo:      safeReturnPath(returnTo, "/profile"), CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		return nil, true, err
	}
	return &models.MFARequiredResponse{
		Status: "mfa_required", Purpose: mfaPurposeReauthentication,
		Username: current.Username, Methods: methods,
		CSRFToken: pending.Data.CSRFToken, ExpiresAt: pending.Data.ExpiresAt,
	}, true, nil
}

func (s *Server) beginOAuthStepUpMFAPending(
	w http.ResponseWriter,
	r *http.Request,
	current *models.User,
	requiredAuthContext, returnTo string,
) (*models.MFARequiredResponse, error) {
	if s.mfaService == nil || requiredAuthContext != oauthstepup.ACRLevel2 {
		return nil, errMFAEnrollmentRequired
	}
	methods, err := s.mfaService.LoginMethods(r.Context(), current.ID)
	if err != nil {
		return nil, err
	}
	if len(methods) == 0 {
		return nil, errMFAEnrollmentRequired
	}
	authenticated := sessionFromContext(r.Context())
	if authenticated == nil || authenticated.Data == nil {
		return nil, session.ErrNotFound
	}
	pending, err := s.sessionMiddleware.CreateMFAPending(w, r, &session.MFAPendingData{
		UserID: current.ID.String(), Username: current.Username,
		AuthVersion: current.AuthVersion, SessionVersion: current.SessionVersion,
		Purpose: mfaPurposeOAuthStepUp, PrimaryMethod: "session",
		RequiredAuthContext:   requiredAuthContext,
		AuthenticationMethods: append([]string(nil), authenticated.Data.AuthenticationMethods...),
		SessionDigest:         providerSessionDigest(authenticated.ID),
		ReturnTo:              safeReturnPath(returnTo, "/dashboard"), CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		return nil, err
	}
	return &models.MFARequiredResponse{
		Status: "mfa_required", Purpose: mfaPurposeOAuthStepUp,
		Username: current.Username, Methods: methods,
		CSRFToken: pending.Data.CSRFToken, ExpiresAt: pending.Data.ExpiresAt,
		RequiredACR: requiredAuthContext,
	}, nil
}

func (s *Server) loadMFAPendingUser(w http.ResponseWriter, r *http.Request) (*MFAPendingSession, *models.User, []string, *AuthenticatedSession, error) {
	pending, err := s.sessionMiddleware.GetMFAPending(r)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	userID, err := uuid.Parse(pending.Data.UserID)
	if err != nil {
		return nil, nil, nil, nil, session.ErrNotFound
	}
	current, err := s.userService.GetByID(r.Context(), userID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if current.Status != models.UserStatusActive ||
		current.AuthVersion != pending.Data.AuthVersion ||
		current.SessionVersion != pending.Data.SessionVersion {
		return nil, nil, nil, nil, session.ErrValueMismatch
	}
	methods, err := s.mfaService.LoginMethods(r.Context(), current.ID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(methods) == 0 {
		return nil, nil, nil, nil, session.ErrValueMismatch
	}
	var authenticated *AuthenticatedSession
	switch pending.Data.Purpose {
	case mfaPurposeLogin:
	case mfaPurposeReauthentication, mfaPurposeOAuthStepUp:
		authenticated, err = s.sessionMiddleware.GetSession(w, r)
		if err != nil || authenticated.Data.UserID != current.ID.String() ||
			authenticated.Data.AuthVersion != current.AuthVersion ||
			authenticated.Data.SessionVersion != current.SessionVersion ||
			!sameSessionDigest(providerSessionDigest(authenticated.ID), pending.Data.SessionDigest) {
			return nil, nil, nil, nil, session.ErrValueMismatch
		}
		if pending.Data.Purpose == mfaPurposeOAuthStepUp && pending.Data.RequiredAuthContext != oauthstepup.ACRLevel2 {
			return nil, nil, nil, nil, session.ErrValueMismatch
		}
	default:
		return nil, nil, nil, nil, session.ErrValueMismatch
	}
	return pending, current, methods, authenticated, nil
}

func (s *Server) writeMFAChallengeUnavailable(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, http.ErrNoCookie), errors.Is(err, session.ErrNotFound), errors.Is(err, session.ErrValueMismatch), user.IsNotFound(err):
		s.sessionMiddleware.DestroyMFAPending(w, r)
		writeAPIError(w, http.StatusUnauthorized, "MFA challenge expired")
	default:
		writeAPIError(w, http.StatusServiceUnavailable, "MFA challenge temporarily unavailable")
	}
}

func (s *Server) handleGetMFAChallenge(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	if !s.validSameOriginRequest(r) {
		writeAPIError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	pending, _, methods, _, err := s.loadMFAPendingUser(w, r)
	if err != nil {
		s.writeMFAChallengeUnavailable(w, r, err)
		return
	}
	response := models.MFARequiredResponse{
		Status: "mfa_required", Purpose: pending.Data.Purpose,
		Username: pending.Data.Username, Methods: methods,
		CSRFToken: pending.Data.CSRFToken, ExpiresAt: pending.Data.ExpiresAt,
	}
	response.RequiredACR = pending.Data.RequiredAuthContext
	security := s.settingsMgr.Security()
	if pending.Data.Purpose == mfaPurposeLogin && security.TrustedDevicesEnabled {
		response.TrustedDeviceAvailable = true
		response.TrustedDeviceTTLSeconds = int64(security.TrustedDeviceDuration() / time.Second)
	}
	writeJSON(w, http.StatusOK, response)
}

func validPendingCSRF(pending *MFAPendingSession, r *http.Request) bool {
	provided := r.Header.Get("X-CSRF-Token")
	if pending == nil || pending.Data == nil || provided == "" {
		return false
	}
	expected := pending.Data.CSRFToken
	return len(provided) == len(expected) && subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func sameMFAPendingChallenge(expected, consumed *MFAPendingSession) bool {
	if expected == nil || expected.Data == nil || consumed == nil || consumed.Data == nil {
		return false
	}
	return expected.Token == consumed.Token &&
		expected.Data.UserID == consumed.Data.UserID &&
		expected.Data.AuthVersion == consumed.Data.AuthVersion &&
		expected.Data.SessionVersion == consumed.Data.SessionVersion &&
		expected.Data.Purpose == consumed.Data.Purpose &&
		expected.Data.RequiredAuthContext == consumed.Data.RequiredAuthContext &&
		slices.Equal(expected.Data.AuthenticationMethods, consumed.Data.AuthenticationMethods) &&
		expected.Data.PrimaryMethod == consumed.Data.PrimaryMethod &&
		expected.Data.Provider == consumed.Data.Provider &&
		expected.Data.SessionDigest == consumed.Data.SessionDigest &&
		expected.Data.CSRFToken == consumed.Data.CSRFToken
}

func (s *Server) handleVerifyMFAChallenge(w http.ResponseWriter, r *http.Request) {
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
	var request struct {
		Method      string `json:"method"`
		Code        string `json:"code"`
		TrustDevice bool   `json:"trust_device"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	request.Method = strings.TrimSpace(request.Method)
	if !containsString(methods, request.Method) {
		writeAPIError(w, http.StatusBadRequest, "unsupported MFA method")
		return
	}
	ip := requestIP(r)
	limitIdentity := "mfa:" + current.ID.String()
	allowed, retry, err := s.loginLimiter.Reserve(r.Context(), ip, limitIdentity)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "MFA verification temporarily unavailable")
		return
	}
	if !allowed {
		seconds := int64((retry + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeAPIError(w, http.StatusTooManyRequests, "too many MFA attempts")
		return
	}
	auditContext := s.mfaAuditContext(r, current)
	gate := mfa.ChallengeCommitGate{
		AuthVersion: pending.Data.AuthVersion, SessionVersion: pending.Data.SessionVersion,
		Consume: func(ctx context.Context) error {
			consumed, err := s.sessionMiddleware.ConsumeMFAPending(w, r.WithContext(ctx))
			if err != nil {
				return err
			}
			if !sameMFAPendingChallenge(pending, consumed) {
				return session.ErrValueMismatch
			}
			return nil
		},
	}
	verificationErr := error(nil)
	switch request.Method {
	case "totp":
		verificationErr = s.mfaService.VerifyTOTPChallenge(r.Context(), current.ID, request.Code, time.Now().UTC(), gate)
	case "recovery_code":
		verificationErr = s.mfaService.ConsumeRecoveryCodeChallenge(r.Context(), current.ID, request.Code, auditContext, time.Now().UTC(), gate)
	}
	if verificationErr != nil {
		switch {
		case errors.Is(verificationErr, mfa.ErrInvalidCode), errors.Is(verificationErr, mfa.ErrCodeReplayed):
			reason := "invalid_code"
			if errors.Is(verificationErr, mfa.ErrCodeReplayed) {
				reason = "replayed_code"
			}
			s.enqueueAuditTargetResult(r.Context(), models.AuditMFAChallengeFailed, &current.ID, current.Username, "user", current.ID.String(), "failure", "medium", ip, truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), map[string]any{
				"purpose": pending.Data.Purpose, "primary_method": pending.Data.PrimaryMethod, "mfa_method": request.Method, "reason": reason,
			})
			writeAPIError(w, http.StatusUnauthorized, "invalid MFA code")
			return
		case errors.Is(verificationErr, mfa.ErrAuthenticationChanged):
			s.writeMFAChallengeUnavailable(w, r, session.ErrValueMismatch)
			return
		case errors.Is(verificationErr, session.ErrNotFound), errors.Is(verificationErr, session.ErrValueMismatch):
			s.writeMFAChallengeUnavailable(w, r, verificationErr)
			return
		}
		writeAPIError(w, http.StatusServiceUnavailable, "MFA verification temporarily unavailable")
		return
	}
	s.completeMFAChallenge(w, r, pending, current, authenticated, request.Method, limitIdentity, request.TrustDevice)
}

func (s *Server) completeMFAChallenge(
	w http.ResponseWriter,
	r *http.Request,
	pending *MFAPendingSession,
	current *models.User,
	authenticated *AuthenticatedSession,
	secondFactor string,
	limitIdentity string,
	trustDevice bool,
) {
	ip := requestIP(r)
	var err error
	current, err = s.userService.GetByID(r.Context(), current.ID)
	if err != nil || current.Status != models.UserStatusActive ||
		current.AuthVersion != pending.Data.AuthVersion || current.SessionVersion != pending.Data.SessionVersion {
		writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		return
	}
	if pending.Data.Purpose == mfaPurposeReauthentication || pending.Data.Purpose == mfaPurposeOAuthStepUp {
		if authenticated == nil || !sameSessionDigest(providerSessionDigest(authenticated.ID), pending.Data.SessionDigest) {
			writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
			return
		}
		updated, err := s.userService.RecordAuthentication(
			r.Context(), current.ID, pending.Data.AuthVersion, pending.Data.SessionVersion,
		)
		if err != nil {
			if errors.Is(err, user.ErrAuthStateChanged) {
				writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
			} else {
				writeAPIError(w, http.StatusServiceUnavailable, "reauthentication failed")
			}
			return
		}
		requestWithSession := r.WithContext(withAuthenticatedSession(r.Context(), authenticated))
		methods := oauthAuthenticationMethods(pending.Data.PrimaryMethod, secondFactor)
		if pending.Data.Purpose == mfaPurposeOAuthStepUp {
			methods = mergeAuthenticationMethods(pending.Data.AuthenticationMethods, methods...)
		}
		marked, err := s.sessionMiddleware.MarkReauthenticatedWithAuthentication(w, requestWithSession, updated, oauthstepup.ACRLevel2, methods)
		if err != nil {
			writeAPIError(w, http.StatusServiceUnavailable, "reauthentication session could not be updated")
			return
		}
		details := map[string]any{
			"authentication_method": pending.Data.PrimaryMethod,
			"second_factor":         secondFactor,
			"purpose":               pending.Data.Purpose,
		}
		if pending.Data.Provider != "" {
			details["provider"] = pending.Data.Provider
			s.telemetry.RecordProviderEvent(r.Context(), "mfa", "reauth", "success", "none", -1)
		}
		s.enqueueAuditTargetResult(r.Context(), models.AuditUserReauthenticated, &current.ID, current.Username, "user", current.ID.String(), "success", "medium", ip, truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), details)
		s.telemetry.RecordAuthEvent(r.Context(), "reauthentication", "success")
		writeJSON(w, http.StatusOK, sessionResponse(updated, marked.Data))
		return
	}
	createdSession, err := s.sessionMiddleware.CreateSessionWithAuthentication(w, r, current, oauthstepup.ACRLevel2, oauthAuthenticationMethods(pending.Data.PrimaryMethod, secondFactor))
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "failed to create session")
		return
	}
	_ = s.loginLimiter.ResetIdentity(r.Context(), ip, limitIdentity)
	details := map[string]any{
		"authentication_method": pending.Data.PrimaryMethod,
		"second_factor":         secondFactor,
	}
	if pending.Data.Provider != "" {
		details["provider"] = pending.Data.Provider
		s.telemetry.RecordProviderEvent(r.Context(), "mfa", "login", "success", "none", -1)
	}
	if trustDevice {
		s.issueTrustedDevice(w, r, current)
	}
	s.enqueueAuditResult(r.Context(), models.AuditUserLogin, &current.ID, current.Username, "success", "low", ip, truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), details)
	_ = s.userService.RecordLogin(r.Context(), current.ID, ip)
	s.telemetry.RecordAuthEvent(r.Context(), "login", "success")
	writeJSON(w, http.StatusOK, sessionResponse(current, createdSession.Data))
}

func oauthAuthenticationMethods(primaryMethod, secondFactor string) []string {
	methods := make([]string, 0, 2)
	switch primaryMethod {
	case "password":
		methods = append(methods, "pwd")
	case "provider":
		methods = append(methods, "federated")
	}
	switch secondFactor {
	case "totp", "recovery_code":
		methods = append(methods, "otp")
	case "passkey":
		methods = append(methods, "hwk")
	}
	return methods
}

func mergeAuthenticationMethods(existing []string, additions ...string) []string {
	methods := make([]string, 0, len(existing)+len(additions))
	seen := make(map[string]struct{}, len(existing)+len(additions))
	for _, method := range append(append([]string(nil), existing...), additions...) {
		switch method {
		case "pwd", "otp", "hwk", "federated", "mfa", "swk":
		default:
			continue
		}
		if _, exists := seen[method]; exists {
			continue
		}
		seen[method] = struct{}{}
		methods = append(methods, method)
	}
	return methods
}

func (s *Server) handleCancelMFAChallenge(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	if !s.validSameOriginRequest(r) {
		writeAPIError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	pending, err := s.sessionMiddleware.GetMFAPending(r)
	if err == nil && !validPendingCSRF(pending, r) {
		writeAPIError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}
	s.sessionMiddleware.DestroyMFAPending(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetMyMFA(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	status, err := s.mfaService.Status(r.Context(), current.ID)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "failed to load MFA status")
		return
	}
	security := s.settingsMgr.Security()
	adminRequired := current.Role == "admin" && security.RequireMFAForAdmins
	loginMFARequired := status.LoginMFAEnabled || adminRequired
	writeJSON(w, http.StatusOK, myMFAResponse{
		LoginMFAEnabled: status.LoginMFAEnabled, LoginMFARequired: loginMFARequired,
		CanEnableLoginMFA: status.TOTPEnrolled || status.PasskeysEnrolled > 0,
		TOTPAvailable:     security.TOTPEnabled, TOTPEnrolled: status.TOTPEnrolled,
		CanDisableTOTP:    !(loginMFARequired && status.PasskeysEnrolled == 0),
		PasskeysAvailable: security.PasskeysEnabled, PasskeysEnrolled: status.PasskeysEnrolled,
		RecoveryCodesRemaining: status.RecoveryCodesRemaining,
		RequireMFAForAdmins:    security.RequireMFAForAdmins,
		RequiredForCurrentUser: adminRequired,
	})
}

func (s *Server) handleUpdateLoginMFARequirement(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	if !s.requireRecentAuthentication(w, r) {
		return
	}
	var request struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	binding := mfa.AuthenticationBinding{
		AuthVersion: authenticated.Data.AuthVersion, SessionVersion: authenticated.Data.SessionVersion,
	}
	changed, err := s.mfaService.SetLoginMFARequirement(
		r.Context(), current.ID, binding, request.Enabled,
		s.mfaAuditContext(r, current), time.Now().UTC(),
	)
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrLoginMFAFactorRequired):
			writeAPIError(w, http.StatusConflict, "enroll a TOTP or Passkey before requiring login MFA")
		case errors.Is(err, mfa.ErrAuthenticationChanged):
			s.sessionMiddleware.DestroySession(w, r)
			writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to update login MFA requirement")
		}
		return
	}
	if !changed {
		writeJSON(w, http.StatusOK, sessionResponse(current, authenticated.Data))
		return
	}
	title, body, reason := "登录两步验证已开启", "密码或外部身份登录现在需要额外完成动态验证码或 Passkey 验证。", "login_mfa_enabled"
	if !request.Enabled {
		title = "登录两步验证已关闭"
		body = "密码或外部身份登录不再默认要求第二因素；Passkey、重新认证和应用请求的额外验证仍然可用。"
		reason = "login_mfa_disabled"
	}
	s.notifySecurityChange(r.Context(), current.ID, notification.TypeMFAChanged, title, body, "/profile/security")
	s.revokeUserSecurityState(r.Context(), current.ID, reason)
	updated, err := s.userService.GetByID(r.Context(), current.ID)
	if err != nil || updated.Status != models.UserStatusActive ||
		updated.AuthVersion != binding.AuthVersion+1 || updated.SessionVersion != binding.SessionVersion {
		s.sessionMiddleware.DestroySession(w, r)
		writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		return
	}
	rotated, err := s.sessionMiddleware.RotateSession(w, r, updated)
	if err != nil {
		s.sessionMiddleware.DestroySession(w, r)
		writeAPIError(w, http.StatusInternalServerError, "login MFA updated; please sign in again")
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse(updated, rotated.Data))
}

func (s *Server) handleBeginTOTPEnrollment(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	if !s.requireRecentAuthentication(w, r) {
		return
	}
	issuer := strings.TrimSpace(s.settingsMgr.Branding().Title)
	if issuer == "" {
		issuer = "Nyauth"
	}
	enrollment, err := s.mfaService.BeginEnrollment(r.Context(), current.ID, issuer, current.Username, time.Now().UTC())
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrTOTPDisabled):
			writeAPIError(w, http.StatusConflict, "TOTP enrollment is disabled")
		case errors.Is(err, mfa.ErrAlreadyEnrolled):
			writeAPIError(w, http.StatusConflict, "TOTP is already enrolled")
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to start TOTP enrollment")
		}
		return
	}
	writeJSON(w, http.StatusOK, enrollment)
}

func (s *Server) handleConfirmTOTPEnrollment(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	if !s.requireRecentAuthentication(w, r) {
		return
	}
	var request struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	binding := mfa.AuthenticationBinding{
		AuthVersion: authenticated.Data.AuthVersion, SessionVersion: authenticated.Data.SessionVersion,
	}
	codes, err := s.mfaService.ConfirmEnrollment(
		r.Context(), current.ID, binding, request.Code, s.mfaAuditContext(r, current), time.Now().UTC(),
	)
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrInvalidCode):
			s.enqueueAuditTargetResult(r.Context(), models.AuditMFAChallengeFailed, &current.ID, current.Username, "user", current.ID.String(), "failure", "medium", requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), map[string]any{"phase": "enrollment", "mfa_method": "totp"})
			writeAPIError(w, http.StatusUnauthorized, "invalid TOTP code")
		case errors.Is(err, mfa.ErrTOTPDisabled):
			writeAPIError(w, http.StatusConflict, "TOTP enrollment is disabled")
		case errors.Is(err, mfa.ErrNotEnrolled), errors.Is(err, mfa.ErrEnrollmentChanged):
			writeAPIError(w, http.StatusConflict, "TOTP enrollment must be restarted")
		case errors.Is(err, mfa.ErrAuthenticationChanged):
			s.sessionMiddleware.DestroySession(w, r)
			writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to confirm TOTP enrollment")
		}
		return
	}
	s.notifySecurityChange(r.Context(), current.ID, notification.TypeMFAChanged, "动态验证码已添加", "您的账户已添加 TOTP 动态验证码。请妥善保存恢复码；是否用于每次登录由登录两步验证设置决定。", "/profile/security")
	s.revokeUserSecurityState(r.Context(), current.ID, "totp_enrolled")
	updated, err := s.userService.GetByID(r.Context(), current.ID)
	if err != nil || updated.Status != models.UserStatusActive ||
		updated.AuthVersion != binding.AuthVersion+1 || updated.SessionVersion != binding.SessionVersion {
		s.sessionMiddleware.DestroySession(w, r)
		writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		return
	}
	rotated, err := s.sessionMiddleware.RotateSession(w, r, updated)
	if err != nil {
		s.sessionMiddleware.DestroySession(w, r)
		writeAPIError(w, http.StatusInternalServerError, "MFA enabled; please sign in again")
		return
	}
	writeJSON(w, http.StatusOK, totpConfirmationResponse{
		SessionResponse: sessionResponse(updated, rotated.Data), RecoveryCodes: codes,
	})
}

func (s *Server) handleRegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	if !s.requireRecentAuthentication(w, r) {
		return
	}
	codes, err := s.mfaService.RegenerateRecoveryCodes(
		r.Context(), current.ID,
		mfa.AuthenticationBinding{AuthVersion: authenticated.Data.AuthVersion, SessionVersion: authenticated.Data.SessionVersion},
		s.mfaAuditContext(r, current), time.Now().UTC(),
	)
	if err != nil {
		if errors.Is(err, mfa.ErrAuthenticationChanged) {
			s.sessionMiddleware.DestroySession(w, r)
			writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		} else if errors.Is(err, mfa.ErrNotEnrolled) {
			writeAPIError(w, http.StatusConflict, "TOTP is not enrolled")
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to regenerate recovery codes")
		}
		return
	}
	writeJSON(w, http.StatusOK, recoveryCodesResponse{RecoveryCodes: codes})
}

func (s *Server) handleDisableTOTP(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	if !s.requireRecentAuthentication(w, r) {
		return
	}
	binding := mfa.AuthenticationBinding{
		AuthVersion: authenticated.Data.AuthVersion, SessionVersion: authenticated.Data.SessionVersion,
	}
	err := s.mfaService.Disable(r.Context(), current.ID, binding, s.mfaAuditContext(r, current), time.Now().UTC())
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrRequiredByPolicy):
			writeAPIError(w, http.StatusConflict, "MFA is required for active administrators")
		case errors.Is(err, mfa.ErrLoginMFAFactorRequired):
			writeAPIError(w, http.StatusConflict, "turn off login MFA or add another factor before disabling TOTP")
		case errors.Is(err, mfa.ErrNotEnrolled):
			writeAPIError(w, http.StatusConflict, "TOTP is not enrolled")
		case errors.Is(err, mfa.ErrAuthenticationChanged):
			s.sessionMiddleware.DestroySession(w, r)
			writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to disable TOTP")
		}
		return
	}
	s.notifySecurityChange(r.Context(), current.ID, notification.TypeMFAChanged, "动态验证码已移除", "您的账户已移除 TOTP 动态验证码。如果这不是您本人操作，请立即检查账户安全。", "/profile/security")
	s.revokeUserSecurityState(r.Context(), current.ID, "totp_disabled")
	updated, err := s.userService.GetByID(r.Context(), current.ID)
	if err != nil || updated.Status != models.UserStatusActive ||
		updated.AuthVersion != binding.AuthVersion+1 || updated.SessionVersion != binding.SessionVersion {
		s.sessionMiddleware.DestroySession(w, r)
		writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		return
	}
	rotated, err := s.sessionMiddleware.RotateSession(w, r, updated)
	if err != nil {
		s.sessionMiddleware.DestroySession(w, r)
		writeAPIError(w, http.StatusInternalServerError, "TOTP disabled; please sign in again")
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse(updated, rotated.Data))
}

func (s *Server) handleGetSecuritySettings(w http.ResponseWriter, r *http.Request) {
	snapshot := s.settingsMgr.SecuritySnapshot()
	writeJSON(w, http.StatusOK, struct {
		Revision int64 `json:"revision"`
		settings.Security
	}{Revision: snapshot.Revision, Security: snapshot.Value})
}

func (s *Server) handleUpdateSecuritySettings(w http.ResponseWriter, r *http.Request) {
	current, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request struct {
		ExpectedRevision int64 `json:"expected_revision"`
		settings.Security
	}
	request.Security = settings.DefaultSecurity()
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	revision, err := s.settingsMgr.SetSecurity(
		r.Context(), request.Security, request.ExpectedRevision, current.Username, mutation,
	)
	if err != nil {
		var missing *settings.AdminsMissingMFAError
		switch {
		case errors.Is(err, settings.ErrRevisionConflict):
			writeAPIError(w, http.StatusConflict, "settings revision conflict")
		case errors.Is(err, settings.ErrInvalidSecurity):
			writeAPIError(w, http.StatusBadRequest, err.Error())
		case errors.As(err, &missing):
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":          "all active administrators must enroll MFA before it can be required",
				"missing_admins": missing.Usernames,
			})
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to store security settings")
		}
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Revision int64 `json:"revision"`
		settings.Security
	}{Revision: revision, Security: request.Security})
}

func (s *Server) mfaAuditContext(r *http.Request, current *models.User) mfa.AuditContext {
	return mfa.AuditContext{
		ActorID: current.ID, ActorName: current.Username, IPAddress: requestIP(r),
		UserAgent: truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength),
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sameSessionDigest(actual, expected string) bool {
	return expected != "" && len(actual) == len(expected) &&
		subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}
