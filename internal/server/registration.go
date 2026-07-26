package server

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/invite"
	"github.com/nyasharp/nyauth/internal/mailruntime"
	"github.com/nyasharp/nyauth/internal/registration"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	inviteMaxUsesLimit        = 1000
	inviteMinTTL              = time.Hour
	inviteMaxTTL              = 8760 * time.Hour
	pendingRegistrationMinTTL = time.Hour
	pendingRegistrationMaxTTL = 720 * time.Hour
	registrationNoteLimit     = 200
	maxAllowedDomains         = 50
)

type registrationOptionsResponse struct {
	Available                bool     `json:"available"`
	Mode                     string   `json:"mode"`
	RequireEmailVerification bool     `json:"require_email_verification"`
	AllowedEmailDomains      []string `json:"allowed_email_domains"`
}

// registrationVerificationRequired reports whether new registrations must
// verify email. Open registration always requires it regardless of the flag.
func registrationVerificationRequired(reg settings.Registration) bool {
	return reg.RequireEmailVerification || reg.Mode == settings.RegistrationOpen
}

func (s *Server) handleRegistrationOptions(w http.ResponseWriter, r *http.Request) {
	reg := s.settingsMgr.Registration()
	if !settings.ValidRegistrationMode(reg.Mode) {
		writeAPIError(w, http.StatusServiceUnavailable, "registration is temporarily unavailable")
		return
	}
	domains := reg.AllowedEmailDomains
	if domains == nil {
		domains = []string{}
	}
	writeJSON(w, http.StatusOK, registrationOptionsResponse{
		Available:                reg.Mode != settings.RegistrationClosed && s.mailRuntimeStatus().Available,
		Mode:                     reg.Mode,
		RequireEmailVerification: registrationVerificationRequired(reg),
		AllowedEmailDomains:      domains,
	})
}

func emailDomainAllowed(email string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	for _, candidate := range allowed {
		if domain == strings.ToLower(strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func isUniqueViolationError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	if !s.validSameOriginRequest(r) {
		writeAPIError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	reg := s.settingsMgr.Registration()
	switch reg.Mode {
	case settings.RegistrationClosed:
		writeAPIError(w, http.StatusForbidden, "registration is closed")
		return
	case settings.RegistrationInviteOnly, settings.RegistrationOpen:
		// Continue below using the explicit supported mode.
	default:
		writeAPIError(w, http.StatusServiceUnavailable, "registration is temporarily unavailable")
		return
	}
	mailGate, mailStatus, mailAvailable := s.registrationMailState()
	if !mailAvailable {
		if mailStatus.CircuitState == mailruntime.CircuitOpen {
			w.Header().Set("Retry-After", "60")
		}
		writeAPIError(w, http.StatusServiceUnavailable, "registration is temporarily unavailable")
		return
	}
	var request models.RegisterRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	request.Email = strings.TrimSpace(request.Email)

	ip := requestIP(r)
	allowed, retry, err := s.accountLimiter.Reserve(r.Context(), "register", ip, strings.ToLower(request.Username))
	if err != nil {
		s.telemetry.RecordRateLimit(r.Context(), "account_action", "register", "error")
		writeAPIError(w, http.StatusServiceUnavailable, "registration temporarily unavailable")
		return
	}
	if !allowed {
		s.telemetry.RecordRateLimit(r.Context(), "account_action", "register", "blocked")
		w.Header().Set("Retry-After", retryAfterSeconds(retry))
		writeAPIError(w, http.StatusTooManyRequests, "too many registration attempts")
		return
	}
	s.telemetry.RecordRateLimit(r.Context(), "account_action", "register", "allowed")

	verificationRequired := registrationVerificationRequired(reg)
	if verificationRequired && s.accountService == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "registration requires email delivery, which is not configured")
		return
	}
	if err := s.userService.ValidateRegistration(request); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !emailDomainAllowed(request.Email, reg.AllowedEmailDomains) {
		writeAPIError(w, http.StatusBadRequest, "email domain is not allowed")
		return
	}

	var inviteCodeHash *string
	if reg.Mode == settings.RegistrationInviteOnly {
		code := strings.TrimSpace(request.InviteCode)
		if code == "" {
			writeAPIError(w, http.StatusBadRequest, "invite code is required")
			return
		}
		hash := invite.HashCode(code)
		inviteCodeHash = &hash
	}

	pendingTTL, err := time.ParseDuration(strings.TrimSpace(reg.PendingRegistrationTTL))
	if err != nil || pendingTTL < pendingRegistrationMinTTL || pendingTTL > pendingRegistrationMaxTTL {
		slog.ErrorContext(r.Context(), "stored pending registration TTL is invalid", "value", reg.PendingRegistrationTTL)
		writeAPIError(w, http.StatusServiceUnavailable, "registration is temporarily unavailable")
		return
	}
	now := time.Now().UTC()
	verificationExpiresAt := now.Add(pendingTTL)
	registerOptions := user.RegisterOptions{
		PendingVerification: verificationRequired,
		InviteCodeHash:      inviteCodeHash,
		ExpiresAt:           verificationExpiresAt,
		Now:                 now,
		Registration:        reg,
		MailGate:            mailGate,
		Audit:               registrationAuditContext(r),
	}
	if verificationRequired {
		metadata := accountRequestMetadata(r)
		registerOptions.PrepareVerification = func(created *models.User) (*account.PreparedActionEmail, error) {
			return s.accountService.PrepareEmailVerification(created, metadata, verificationExpiresAt)
		}
	}
	_, _, err = s.userService.Register(r.Context(), request, registerOptions)
	if err != nil {
		switch {
		case user.IsInvalidInput(err):
			writeAPIError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, user.ErrInviteInvalid):
			s.telemetry.RecordAuthEvent(r.Context(), "register", "invalid_invite")
			writeAPIError(w, http.StatusBadRequest, "invalid or expired invite code")
		case isUniqueViolationError(err):
			writeAPIError(w, http.StatusConflict, "username or email is already taken")
		case errors.Is(err, runtimecoord.ErrMailCircuitOpen):
			w.Header().Set("Retry-After", "60")
			slog.WarnContext(r.Context(), "mail circuit opened while committing self-registration")
			writeAPIError(w, http.StatusServiceUnavailable, "registration temporarily unavailable")
		default:
			slog.ErrorContext(r.Context(), "self-registration failed", "error", err)
			writeAPIError(w, http.StatusServiceUnavailable, "registration temporarily unavailable")
		}
		return
	}

	s.telemetry.RecordAuthEvent(r.Context(), "register", "success")

	if verificationRequired {
		writeJSON(w, http.StatusCreated, models.RegisterResponse{
			Status: "pending_verification", VerificationExpiresAt: &verificationExpiresAt,
		})
		return
	}
	writeJSON(w, http.StatusCreated, models.RegisterResponse{Status: "registered"})
}

func (s *Server) handleGetRegistrationSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.settingsMgr.Registration())
}

func (s *Server) handleUpdateRegistrationSettings(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !s.requireRecentAuthentication(w, r) {
		return
	}
	var request settings.Registration
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	validated, err := s.validateRegistrationSettings(request)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	fallbackConfigured := s.mailManager != nil && s.mailManager.FallbackConfigured()
	if err := s.settingsMgr.SetRegistration(r.Context(), validated, current.Username, fallbackConfigured); err != nil {
		if errors.Is(err, settings.ErrMailConfigurationNeeded) {
			writeAPIError(w, http.StatusConflict, "mail configuration changed; reload and try again")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "failed to store registration settings")
		return
	}
	writeJSON(w, http.StatusOK, validated)
}

func (s *Server) registrationMailState() (runtimecoord.MailDeliveryGate, mailruntime.RuntimeStatus, bool) {
	if s.mailManager != nil {
		return s.mailManager.RegistrationDeliveryState()
	}
	configured := s.accountService != nil
	status := mailruntime.RuntimeStatus{
		Mode: mailruntime.ModeFallback, Configured: configured, Available: configured,
		CircuitState: mailruntime.CircuitClosed,
	}
	return runtimecoord.MailDeliveryGate{Mode: runtimecoord.MailModeFallback}, status, configured
}

func (s *Server) validateRegistrationSettings(request settings.Registration) (settings.Registration, error) {
	if !settings.ValidRegistrationMode(request.Mode) {
		return settings.Registration{}, errors.New("unsupported registration mode")
	}
	if request.Mode == settings.RegistrationOpen {
		// Open registration without verified emails invites abuse.
		request.RequireEmailVerification = true
	}
	if request.Mode != settings.RegistrationClosed && !s.mailRuntimeStatus().Configured {
		return settings.Registration{}, errors.New("self-registration requires an active mail configuration")
	}
	if len(request.AllowedEmailDomains) > maxAllowedDomains {
		return settings.Registration{}, errors.New("too many allowed email domains")
	}
	cleaned := make([]string, 0, len(request.AllowedEmailDomains))
	seen := map[string]bool{}
	for _, raw := range request.AllowedEmailDomains {
		domain := strings.ToLower(strings.TrimSpace(raw))
		if domain == "" {
			continue
		}
		if len(domain) > 255 || !validEmailDomain(domain) {
			return settings.Registration{}, errors.New("invalid email domain: " + domain)
		}
		if !seen[domain] {
			seen[domain] = true
			cleaned = append(cleaned, domain)
		}
	}
	request.AllowedEmailDomains = cleaned
	if strings.TrimSpace(request.PendingRegistrationTTL) == "" {
		request.PendingRegistrationTTL = settings.DefaultRegistration().PendingRegistrationTTL
	}
	pendingTTL, err := time.ParseDuration(request.PendingRegistrationTTL)
	if err != nil || pendingTTL < pendingRegistrationMinTTL || pendingTTL > pendingRegistrationMaxTTL {
		return settings.Registration{}, errors.New("pending_registration_ttl must be a duration between 1h and 720h")
	}

	if strings.TrimSpace(request.InviteDefaultTTL) == "" {
		request.InviteDefaultTTL = settings.DefaultRegistration().InviteDefaultTTL
	}
	ttl, err := time.ParseDuration(request.InviteDefaultTTL)
	if err != nil || ttl < inviteMinTTL || ttl > inviteMaxTTL {
		return settings.Registration{}, errors.New("invite_default_ttl must be a duration between 1h and 8760h")
	}
	if request.InviteDefaultMaxUses == 0 {
		request.InviteDefaultMaxUses = 1
	}
	if request.InviteDefaultMaxUses < 1 || request.InviteDefaultMaxUses > inviteMaxUsesLimit {
		return settings.Registration{}, errors.New("invite_default_max_uses must be between 1 and 1000")
	}
	return request, nil
}

func registrationAuditContext(r *http.Request) registration.AuditContext {
	return registration.AuditContext{
		IPAddress: requestIP(r),
		UserAgent: truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength),
	}
}

func validEmailDomain(domain string) bool {
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") ||
		strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") {
		return false
	}
	for _, r := range domain {
		if !(r == '.' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	return true
}
