package server

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/mailruntime"
	"github.com/nyasharp/nyauth/pkg/models"
)

type runtimeSecurityNotificationBuilder struct {
	manager *mailruntime.Manager
	service *account.Service
}

func (b runtimeSecurityNotificationBuilder) BuildSecurityNotification(user *models.User, notice account.SecurityNotice) (*account.OutboxEmail, error) {
	if b.manager == nil || b.service == nil || !b.manager.Status().Configured {
		return nil, nil
	}
	return b.service.BuildSecurityNotification(user, notice)
}

type mailConfigResponse struct {
	Source             string     `json:"source"`
	ID                 *uuid.UUID `json:"id,omitempty"`
	Revision           *int64     `json:"revision,omitempty"`
	Host               string     `json:"host"`
	Port               int        `json:"port"`
	Username           string     `json:"username"`
	TLSMode            string     `json:"tls_mode"`
	FromAddress        string     `json:"from_address"`
	FromName           string     `json:"from_name"`
	PublicBaseURL      string     `json:"public_base_url"`
	ConnectTimeout     string     `json:"connect_timeout"`
	SendTimeout        string     `json:"send_timeout"`
	PasswordConfigured bool       `json:"password_configured"`
	CreatedBy          *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt          *time.Time `json:"created_at,omitempty"`
}

type mailCircuitResponse struct {
	State        string     `json:"state"`
	OpenCategory *string    `json:"open_category,omitempty"`
	OpenReason   *string    `json:"open_reason,omitempty"`
	OpenedAt     *time.Time `json:"opened_at,omitempty"`
	NextProbeAt  *time.Time `json:"next_probe_at,omitempty"`
	FailureCount int        `json:"transport_failure_count"`
}

type mailSettingsResponse struct {
	Mode          string              `json:"mode"`
	Configured    bool                `json:"configured"`
	Available     bool                `json:"available"`
	StateRevision int64               `json:"state_revision"`
	Circuit       mailCircuitResponse `json:"circuit"`
	Active        *mailConfigResponse `json:"active,omitempty"`
	Candidate     *mailConfigResponse `json:"candidate,omitempty"`
	Previous      *mailConfigResponse `json:"previous,omitempty"`
}

type saveMailCandidateRequest struct {
	ExpectedRevision int64   `json:"expected_revision"`
	Host             string  `json:"host"`
	Port             int     `json:"port"`
	Username         string  `json:"username"`
	Password         *string `json:"password"`
	TLSMode          string  `json:"tls_mode"`
	FromAddress      string  `json:"from_address"`
	FromName         string  `json:"from_name"`
	PublicBaseURL    string  `json:"public_base_url"`
	ConnectTimeout   string  `json:"connect_timeout"`
	SendTimeout      string  `json:"send_timeout"`
}

type mailVersionMutationRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	VersionID        string `json:"version_id"`
}

type mailStateMutationRequest struct {
	ExpectedRevision int64 `json:"expected_revision"`
}

type testMailCandidateRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	VersionID        string `json:"version_id"`
	Email            string `json:"email"`
}

type mailTestResponse struct {
	Result        string    `json:"result"`
	ErrorCategory *string   `json:"error_category,omitempty"`
	TestedAt      time.Time `json:"tested_at"`
	StateRevision int64     `json:"state_revision"`
}

type mailMutationResponse struct {
	Status        string `json:"status"`
	StateRevision int64  `json:"state_revision"`
}

func (s *Server) handleGetMailSettings(w http.ResponseWriter, r *http.Request) {
	if !s.requireRecentAuthentication(w, r) {
		return
	}
	response, err := s.currentMailSettings(r)
	if err != nil {
		slog.ErrorContext(r.Context(), "loading runtime mail settings failed", "error", err)
		writeAPIError(w, http.StatusServiceUnavailable, "mail settings are temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) currentMailSettings(r *http.Request) (mailSettingsResponse, error) {
	if s.mailManager == nil {
		return mailSettingsResponse{}, mailruntime.ErrStoreUnavailable
	}
	loadErr := s.mailManager.Load(r.Context())
	state, err := s.mailManager.LoadState(r.Context())
	if err != nil {
		return mailSettingsResponse{}, err
	}
	status := s.mailManager.Status()
	response := mailSettingsResponse{
		Mode: state.Mode, Configured: status.Configured, Available: status.Available,
		StateRevision: state.Revision,
		Circuit: mailCircuitResponse{
			State: state.CircuitState, OpenCategory: state.CircuitOpenCategory,
			OpenReason: state.CircuitOpenReason, OpenedAt: state.CircuitOpenedAt,
			NextProbeAt: state.NextProbeAt, FailureCount: state.TransportFailureCount,
		},
	}
	if state.Mode == mailruntime.ModeFallback {
		if settingsValue, passwordConfigured := s.mailManager.EffectiveSettings(); settingsValue != nil {
			active := mailConfigResponseFromSettings("environment", *settingsValue, passwordConfigured)
			response.Active = &active
		}
	} else if state.ActiveVersionID != nil {
		version, versionErr := s.mailManager.LoadVersion(r.Context(), *state.ActiveVersionID)
		if versionErr != nil {
			return mailSettingsResponse{}, versionErr
		}
		active := mailConfigResponseFromVersion("database", version)
		response.Active = &active
	}
	if state.CandidateVersionID != nil {
		version, versionErr := s.mailManager.LoadVersion(r.Context(), *state.CandidateVersionID)
		if versionErr != nil {
			return mailSettingsResponse{}, versionErr
		}
		candidate := mailConfigResponseFromVersion("database", version)
		response.Candidate = &candidate
	}
	if state.PreviousVersionID != nil {
		version, versionErr := s.mailManager.LoadVersion(r.Context(), *state.PreviousVersionID)
		if versionErr != nil {
			return mailSettingsResponse{}, versionErr
		}
		previous := mailConfigResponseFromVersion("database", version)
		response.Previous = &previous
	}
	if loadErr != nil {
		response.Available = false
		slog.WarnContext(r.Context(), "runtime mail snapshot refresh failed", "error", loadErr)
	}
	return response, nil
}

func (s *Server) handleSaveMailCandidate(w http.ResponseWriter, r *http.Request) {
	mutation, ok := s.authorizeMailMutation(w, r, mailSettingsActionCandidateSave)
	if !ok {
		return
	}
	var request saveMailCandidateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	settingsValue, err := s.mailSettingsFromRequest(request)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := s.mailManager.CreateCandidate(r.Context(), mailruntime.CreateCandidateInput{
		ExpectedRevision: request.ExpectedRevision, Settings: settingsValue,
		Password: request.Password, Audit: mutation,
	})
	if err != nil {
		s.writeMailMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"candidate":      mailConfigResponseFromVersion("database", result.Version),
		"state_revision": result.State.Revision,
	})
}

func (s *Server) mailSettingsFromRequest(request saveMailCandidateRequest) (mailruntime.Settings, error) {
	connectTimeout, err := time.ParseDuration(strings.TrimSpace(request.ConnectTimeout))
	if err != nil {
		return mailruntime.Settings{}, errors.New("connect_timeout must be a valid duration")
	}
	sendTimeout, err := time.ParseDuration(strings.TrimSpace(request.SendTimeout))
	if err != nil {
		return mailruntime.Settings{}, errors.New("send_timeout must be a valid duration")
	}
	settingsValue := mailruntime.Settings{
		Host: request.Host, Port: request.Port, Username: request.Username,
		TLSMode: request.TLSMode, FromAddress: request.FromAddress, FromName: request.FromName,
		PublicBaseURL: request.PublicBaseURL, ConnectTimeout: connectTimeout, SendTimeout: sendTimeout,
	}
	if s.cfg.IsProduction() {
		if strings.EqualFold(strings.TrimSpace(settingsValue.TLSMode), mailruntime.TLSModePlain) {
			return mailruntime.Settings{}, errors.New("plain SMTP is forbidden in production")
		}
		parsed, parseErr := url.Parse(strings.TrimSpace(settingsValue.PublicBaseURL))
		if parseErr != nil || parsed.Scheme != "https" {
			return mailruntime.Settings{}, errors.New("public_base_url must use HTTPS in production")
		}
	}
	return settingsValue, nil
}

func (s *Server) handleTestMailCandidate(w http.ResponseWriter, r *http.Request) {
	mutation, ok := s.authorizeMailMutation(w, r, mailSettingsActionCandidateTest)
	if !ok {
		return
	}
	var request testMailCandidateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	versionID, err := uuid.Parse(strings.TrimSpace(request.VersionID))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "version_id is invalid")
		return
	}
	recipient, err := normalizeMailTestRecipient(request.Email)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	state, err := s.mailManager.LoadState(r.Context())
	if err != nil {
		s.writeMailMutationError(w, err)
		return
	}
	if state.Revision != request.ExpectedRevision || state.CandidateVersionID == nil || *state.CandidateVersionID != versionID {
		s.writeMailMutationError(w, mailruntime.ErrStateConflict)
		return
	}

	version, _, sender, sendErr := s.mailManager.SenderForVersion(r.Context(), versionID)
	if sendErr == nil {
		sendErr = sender.Send(r.Context(), account.EmailMessage{
			To: recipient, Subject: "Nyauth SMTP 配置测试",
			TextBody: fmt.Sprintf("这是 Nyauth SMTP 配置版本 %d 的测试邮件。收到此邮件表示连接、TLS、认证和投递均已成功。", version.Revision),
			HTMLBody: fmt.Sprintf("<p>这是 Nyauth SMTP 配置版本 %d 的测试邮件。</p><p>收到此邮件表示连接、TLS、认证和投递均已成功。</p>", version.Revision),
		})
	}
	testResult := mailruntime.TestResultSuccess
	var category *string
	if sendErr != nil {
		testResult = mailruntime.TestResultFailure
		value := mailTestErrorCategory(sendErr)
		category = &value
	}
	digest := sha256.Sum256([]byte(strings.ToLower(recipient)))
	recorded, err := s.mailManager.RecordTest(r.Context(), mailruntime.RecordTestInput{
		ExpectedRevision: request.ExpectedRevision, VersionID: versionID, RecipientHash: digest[:],
		Result: testResult, ErrorCategory: category, Audit: mutation,
	})
	if err != nil {
		s.writeMailMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, mailTestResponse{
		Result: testResult, ErrorCategory: category, TestedAt: recorded.Record.CreatedAt,
		StateRevision: recorded.State.Revision,
	})
}

func (s *Server) handleActivateMailCandidate(w http.ResponseWriter, r *http.Request) {
	mutation, ok := s.authorizeMailMutation(w, r, mailSettingsActionActivate)
	if !ok {
		return
	}
	var request mailVersionMutationRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	versionID, err := uuid.Parse(strings.TrimSpace(request.VersionID))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "version_id is invalid")
		return
	}
	state, err := s.mailManager.Activate(r.Context(), mailruntime.VersionMutationInput{
		ExpectedRevision: request.ExpectedRevision, VersionID: versionID, Audit: mutation,
	})
	if err != nil {
		s.writeMailMutationError(w, err)
		return
	}
	s.reloadMailAfterMutation(r)
	writeJSON(w, http.StatusOK, mailMutationResponse{Status: "activated", StateRevision: state.Revision})
}

func (s *Server) handleRollbackMailSettings(w http.ResponseWriter, r *http.Request) {
	mutation, ok := s.authorizeMailMutation(w, r, mailSettingsActionRollback)
	if !ok {
		return
	}
	var request mailStateMutationRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	state, err := s.mailManager.Rollback(r.Context(), mailruntime.StateMutationInput{
		ExpectedRevision: request.ExpectedRevision, Audit: mutation,
	})
	if err != nil {
		s.writeMailMutationError(w, err)
		return
	}
	s.reloadMailAfterMutation(r)
	writeJSON(w, http.StatusOK, mailMutationResponse{Status: "rolled_back", StateRevision: state.Revision})
}

func (s *Server) handleDisableMail(w http.ResponseWriter, r *http.Request) {
	mutation, ok := s.authorizeMailMutation(w, r, mailSettingsActionDisable)
	if !ok {
		return
	}
	var request mailStateMutationRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	state, err := s.mailManager.Disable(r.Context(), mailruntime.StateMutationInput{
		ExpectedRevision: request.ExpectedRevision, Audit: mutation,
	})
	if err != nil {
		s.writeMailMutationError(w, err)
		return
	}
	s.reloadMailAfterMutation(r)
	writeJSON(w, http.StatusOK, mailMutationResponse{Status: "disabled", StateRevision: state.Revision})
}

func (s *Server) authorizeMailMutation(w http.ResponseWriter, r *http.Request, action string) (audit.MutationAudit, bool) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return audit.MutationAudit{}, false
	}
	if !s.requireRecentAuthentication(w, r) {
		return audit.MutationAudit{}, false
	}
	if s.mailSettingsLimiter == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "mail settings are temporarily unavailable")
		return audit.MutationAudit{}, false
	}
	allowed, retry, err := s.mailSettingsLimiter.Reserve(r.Context(), action, requestIP(r), current.ID.String())
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "mail settings are temporarily unavailable")
		return audit.MutationAudit{}, false
	}
	if !allowed {
		w.Header().Set("Retry-After", retryAfterSeconds(retry))
		writeAPIError(w, http.StatusTooManyRequests, "too many mail settings operations")
		return audit.MutationAudit{}, false
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return audit.MutationAudit{}, false
	}
	return mutation, true
}

func (s *Server) reloadMailAfterMutation(r *http.Request) {
	if err := s.mailManager.Load(r.Context()); err != nil {
		slog.ErrorContext(r.Context(), "runtime mail mutation committed but local reload failed", "error", err)
	}
}

func (s *Server) writeMailMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, mailruntime.ErrInvalidConfig), errors.Is(err, mailruntime.ErrPasswordInheritance):
		writeAPIError(w, http.StatusBadRequest, "mail configuration is invalid")
	case errors.Is(err, mailruntime.ErrVersionNotFound), errors.Is(err, mailruntime.ErrCandidateNotFound):
		writeAPIError(w, http.StatusNotFound, "mail configuration version was not found")
	case errors.Is(err, mailruntime.ErrStateConflict), errors.Is(err, mailruntime.ErrCandidateChanged):
		writeAPIError(w, http.StatusConflict, "mail settings changed; reload and try again")
	case errors.Is(err, mailruntime.ErrCandidateTestRequired):
		writeAPIError(w, http.StatusConflict, "a successful candidate test is required")
	case errors.Is(err, mailruntime.ErrCandidateTestExpired):
		writeAPIError(w, http.StatusConflict, "the successful candidate test has expired")
	case errors.Is(err, mailruntime.ErrNoPreviousVersion):
		writeAPIError(w, http.StatusConflict, "no previous mail configuration is available")
	case errors.Is(err, mailruntime.ErrAlreadyDisabled):
		writeAPIError(w, http.StatusConflict, "mail is already disabled")
	case errors.Is(err, mailruntime.ErrRegistrationOpen):
		writeAPIError(w, http.StatusConflict, "close self-registration before disabling mail")
	default:
		writeAPIError(w, http.StatusServiceUnavailable, "mail settings are temporarily unavailable")
	}
}

func (s *Server) mailRuntimeStatus() mailruntime.RuntimeStatus {
	if s.mailManager != nil {
		return s.mailManager.Status()
	}
	configured := s.accountService != nil
	return mailruntime.RuntimeStatus{
		Mode: mailruntime.ModeFallback, Configured: configured, Available: configured,
		CircuitState: mailruntime.CircuitClosed,
	}
}

func mailConfigResponseFromVersion(source string, version mailruntime.Version) mailConfigResponse {
	response := mailConfigResponseFromSettings(source, version.Settings, version.PasswordConfigured)
	versionID := version.ID
	revision := version.Revision
	createdAt := version.CreatedAt
	response.ID = &versionID
	response.Revision = &revision
	response.CreatedBy = version.CreatedBy
	response.CreatedAt = &createdAt
	return response
}

func mailConfigResponseFromSettings(source string, settingsValue mailruntime.Settings, passwordConfigured bool) mailConfigResponse {
	return mailConfigResponse{
		Source: source, Host: settingsValue.Host, Port: settingsValue.Port, Username: settingsValue.Username,
		TLSMode: settingsValue.TLSMode, FromAddress: settingsValue.FromAddress, FromName: settingsValue.FromName,
		PublicBaseURL: settingsValue.PublicBaseURL, ConnectTimeout: settingsValue.ConnectTimeout.String(),
		SendTimeout: settingsValue.SendTimeout.String(), PasswordConfigured: passwordConfigured,
	}
}

func normalizeMailTestRecipient(value string) (string, error) {
	value = strings.TrimSpace(value)
	parsed, err := mail.ParseAddress(value)
	if err != nil || !strings.EqualFold(parsed.Address, value) || len(value) > 255 {
		return "", errors.New("email is invalid")
	}
	return strings.ToLower(parsed.Address), nil
}

func mailTestErrorCategory(err error) string {
	category, _ := account.SMTPErrorDetails(err)
	switch category {
	case account.SMTPErrorConfiguration:
		return mailruntime.ErrorCategoryConfiguration
	case account.SMTPErrorAuthentication:
		return mailruntime.ErrorCategoryAuthentication
	case account.SMTPErrorTLS:
		return mailruntime.ErrorCategoryTLS
	case account.SMTPErrorTransport:
		return mailruntime.ErrorCategoryTransport
	case account.SMTPErrorRecipient:
		return mailruntime.ErrorCategoryRecipient
	default:
		return mailruntime.ErrorCategoryUnknown
	}
}
