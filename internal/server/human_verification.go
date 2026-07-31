package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/humanverification"
)

type humanVerificationProof struct {
	Token          string `json:"token"`
	IdempotencyKey string `json:"idempotency_key"`
}

type humanVerificationRuntime interface {
	LoadState(context.Context) (humanverification.State, error)
	LoadVersion(context.Context, uuid.UUID) (humanverification.Version, error)
	LoadLatestTest(context.Context, uuid.UUID) (*humanverification.TestRecord, error)
	CreateCandidate(context.Context, humanverification.CreateCandidateInput) (humanverification.CandidateResult, error)
	RecordTest(context.Context, humanverification.RecordTestInput) (humanverification.TestResult, error)
	Activate(context.Context, humanverification.ActivateInput) (humanverification.State, error)
	UpdatePolicy(context.Context, humanverification.PolicyMutationInput) (humanverification.State, error)
	Rollback(context.Context, humanverification.StateMutationInput) (humanverification.State, error)
	Disable(context.Context, humanverification.StateMutationInput) (humanverification.State, error)
	Enable(context.Context, humanverification.StateMutationInput) (humanverification.State, error)
	CandidateVerifier(context.Context, uuid.UUID) (humanverification.Version, humanverification.Verifier, error)
	Load(context.Context) error
	PublicChallenge(string, int) humanverification.PublicChallenge
	Verify(context.Context, humanverification.VerifyInput, int) error
	Status() humanverification.RuntimeStatus
	StartSynchronization(context.Context)
}

type humanVerificationSettingsResponse struct {
	humanverification.State
	Active            *humanverification.Version      `json:"active"`
	Candidate         *humanverification.Version      `json:"candidate"`
	Previous          *humanverification.Version      `json:"previous"`
	CandidateLastTest *humanverification.TestRecord   `json:"candidate_last_test"`
	Runtime           humanverification.RuntimeStatus `json:"runtime"`
}

type saveHumanVerificationCandidateRequest struct {
	ExpectedRevision int64   `json:"expected_revision"`
	Provider         string  `json:"provider"`
	SiteKey          string  `json:"site_key"`
	WidgetMode       string  `json:"widget_mode"`
	Secret           *string `json:"secret,omitempty"`
}

type testHumanVerificationCandidateRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	VersionID        string `json:"version_id"`
	Token            string `json:"token"`
	IdempotencyKey   string `json:"idempotency_key"`
}

type activateHumanVerificationRequest struct {
	ExpectedRevision int64                    `json:"expected_revision"`
	VersionID        string                   `json:"version_id"`
	Policy           humanverification.Policy `json:"policy"`
}

type updateHumanVerificationPolicyRequest struct {
	ExpectedRevision int64                    `json:"expected_revision"`
	Policy           humanverification.Policy `json:"policy"`
}

type humanVerificationStateMutationRequest struct {
	ExpectedRevision int64 `json:"expected_revision"`
}

func (s *Server) handleGetHumanVerification(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	if !humanverification.ValidAction(action) || action == humanverification.ActionAdminTest {
		writeAPIError(w, http.StatusBadRequest, "unsupported human verification action")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if s.humanVerification == nil {
		writeJSON(w, http.StatusOK, humanverification.PublicChallenge{Action: action})
		return
	}
	writeJSON(w, http.StatusOK, s.humanVerification.PublicChallenge(action, 0))
}

func (s *Server) handleGetHumanVerificationSettings(w http.ResponseWriter, r *http.Request) {
	response, err := s.loadHumanVerificationSettings(r)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "human verification settings are unavailable")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleSaveHumanVerificationCandidate(w http.ResponseWriter, r *http.Request) {
	_, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request saveHumanVerificationCandidateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := s.humanVerification.CreateCandidate(r.Context(), humanverification.CreateCandidateInput{
		ExpectedRevision: request.ExpectedRevision,
		Settings:         humanverification.Settings{Provider: request.Provider, SiteKey: request.SiteKey, WidgetMode: request.WidgetMode},
		Secret:           request.Secret, Audit: mutation,
	})
	if err != nil {
		s.writeHumanVerificationMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleTestHumanVerificationCandidate(w http.ResponseWriter, r *http.Request) {
	_, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request testHumanVerificationCandidateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	versionID, err := uuid.Parse(request.VersionID)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid human verification version")
		return
	}
	_, verifier, err := s.humanVerification.CandidateVerifier(r.Context(), versionID)
	if err != nil {
		s.writeHumanVerificationMutationError(w, err)
		return
	}
	started := time.Now()
	result, verifyErr := verifier.Verify(r.Context(), humanverification.VerifyInput{
		Token: request.Token, RemoteIP: requestIP(r), Action: humanverification.ActionAdminTest,
		IdempotencyKey: request.IdempotencyKey,
	})
	metricResult, metricReason := "success", "none"
	if errors.Is(verifyErr, humanverification.ErrVerificationRejected) {
		metricResult, metricReason = "rejected", "provider_rejected"
	} else if verifyErr != nil {
		metricResult, metricReason = "unavailable", "provider_unavailable"
	}
	s.telemetry.RecordHumanVerification(r.Context(), humanverification.ProviderTurnstile, humanverification.ActionAdminTest, metricResult, metricReason, time.Since(started))
	testResult := humanverification.TestSuccess
	var errorCode *string
	if verifyErr != nil {
		testResult = humanverification.TestFailure
		code := humanverification.VerificationErrorCode(verifyErr, result)
		errorCode = &code
	}
	recorded, recordErr := s.humanVerification.RecordTest(r.Context(), humanverification.RecordTestInput{
		ExpectedRevision: request.ExpectedRevision, VersionID: versionID,
		Result: testResult, ErrorCode: errorCode, Audit: mutation,
	})
	if recordErr != nil {
		s.writeHumanVerificationMutationError(w, recordErr)
		return
	}
	if verifyErr != nil {
		status := http.StatusUnprocessableEntity
		message := "human verification test was rejected"
		if errors.Is(verifyErr, humanverification.ErrVerificationUnavailable) {
			status = http.StatusServiceUnavailable
			message = "human verification provider is unavailable"
		}
		writeJSON(w, status, map[string]any{
			"error": message, "code": apiErrorCodeForMessage(message), "test": recorded,
		})
		return
	}
	writeJSON(w, http.StatusOK, recorded)
}

func (s *Server) handleActivateHumanVerification(w http.ResponseWriter, r *http.Request) {
	_, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request activateHumanVerificationRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	versionID, err := uuid.Parse(request.VersionID)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid human verification version")
		return
	}
	state, err := s.humanVerification.Activate(r.Context(), humanverification.ActivateInput{
		ExpectedRevision: request.ExpectedRevision, VersionID: versionID, Policy: request.Policy, Audit: mutation,
	})
	if err != nil {
		s.writeHumanVerificationMutationError(w, err)
		return
	}
	if err := s.humanVerification.Load(r.Context()); err != nil {
		slog.ErrorContext(r.Context(), "activated human verification configuration could not be loaded", "error", err)
		writeAPIError(w, http.StatusServiceUnavailable, "human verification configuration was activated but is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) handleUpdateHumanVerificationPolicy(w http.ResponseWriter, r *http.Request) {
	_, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request updateHumanVerificationPolicyRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	state, err := s.humanVerification.UpdatePolicy(r.Context(), humanverification.PolicyMutationInput{
		ExpectedRevision: request.ExpectedRevision, Policy: request.Policy, Audit: mutation,
	})
	if err != nil {
		s.writeHumanVerificationMutationError(w, err)
		return
	}
	_ = s.humanVerification.Load(r.Context())
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) handleRollbackHumanVerification(w http.ResponseWriter, r *http.Request) {
	s.handleHumanVerificationStateMutation(w, r, s.humanVerification.Rollback)
}

func (s *Server) handleDisableHumanVerification(w http.ResponseWriter, r *http.Request) {
	s.handleHumanVerificationStateMutation(w, r, s.humanVerification.Disable)
}

func (s *Server) handleEnableHumanVerification(w http.ResponseWriter, r *http.Request) {
	s.handleHumanVerificationStateMutation(w, r, s.humanVerification.Enable)
}

func (s *Server) handleHumanVerificationStateMutation(
	w http.ResponseWriter, r *http.Request,
	mutate func(context.Context, humanverification.StateMutationInput) (humanverification.State, error),
) {
	_, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request humanVerificationStateMutationRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	state, err := mutate(r.Context(), humanverification.StateMutationInput{ExpectedRevision: request.ExpectedRevision, Audit: mutation})
	if err != nil {
		s.writeHumanVerificationMutationError(w, err)
		return
	}
	_ = s.humanVerification.Load(r.Context())
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) loadHumanVerificationSettings(r *http.Request) (humanVerificationSettingsResponse, error) {
	state, err := s.humanVerification.LoadState(r.Context())
	if err != nil {
		return humanVerificationSettingsResponse{}, err
	}
	response := humanVerificationSettingsResponse{State: state, Runtime: s.humanVerification.Status()}
	load := func(id *uuid.UUID) (*humanverification.Version, error) {
		if id == nil {
			return nil, nil
		}
		value, err := s.humanVerification.LoadVersion(r.Context(), *id)
		return &value, err
	}
	if response.Active, err = load(state.ActiveVersionID); err != nil {
		return response, err
	}
	if response.Candidate, err = load(state.CandidateVersionID); err != nil {
		return response, err
	}
	if response.Previous, err = load(state.PreviousVersionID); err != nil {
		return response, err
	}
	if state.CandidateVersionID != nil {
		response.CandidateLastTest, err = s.humanVerification.LoadLatestTest(r.Context(), *state.CandidateVersionID)
	}
	return response, err
}

func (s *Server) requireHumanVerification(
	w http.ResponseWriter, r *http.Request, action string, loginAttempt int, proof *humanVerificationProof,
) bool {
	// Production construction always supplies the manager. Isolated handler
	// tests intentionally build a minimal Server and therefore inherit the
	// secure default policy where verification is disabled.
	if s.humanVerification == nil {
		return true
	}
	challenge := s.humanVerification.PublicChallenge(action, loginAttempt)
	if !challenge.Required {
		return true
	}
	if !challenge.Available {
		s.telemetry.RecordHumanVerification(r.Context(), challenge.Provider, action, "unavailable", "provider_unavailable", -1)
		writeAPIError(w, http.StatusServiceUnavailable, "human verification is temporarily unavailable")
		return false
	}
	if proof == nil || strings.TrimSpace(proof.Token) == "" || strings.TrimSpace(proof.IdempotencyKey) == "" {
		s.telemetry.RecordHumanVerification(r.Context(), challenge.Provider, action, "required", "missing_proof", -1)
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{
			"error": "human verification is required", "code": "human_verification.required", "challenge": challenge,
		})
		return false
	}
	started := time.Now()
	err := s.humanVerification.Verify(r.Context(), humanverification.VerifyInput{
		Token: proof.Token, RemoteIP: requestIP(r), Action: action, IdempotencyKey: proof.IdempotencyKey,
	}, loginAttempt)
	if err == nil {
		s.telemetry.RecordHumanVerification(r.Context(), challenge.Provider, action, "success", "none", time.Since(started))
		return true
	}
	if errors.Is(err, humanverification.ErrVerificationRejected) {
		s.telemetry.RecordHumanVerification(r.Context(), challenge.Provider, action, "rejected", "provider_rejected", time.Since(started))
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error": "human verification failed", "code": "human_verification.failed", "challenge": challenge,
		})
		return false
	}
	s.telemetry.RecordHumanVerification(r.Context(), challenge.Provider, action, "unavailable", "provider_unavailable", time.Since(started))
	slog.WarnContext(r.Context(), "human verification provider request failed", "action", action, "error_class", "provider_unavailable")
	writeAPIError(w, http.StatusServiceUnavailable, "human verification is temporarily unavailable")
	return false
}

func (s *Server) writeHumanVerificationMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, humanverification.ErrStateConflict):
		writeAPIError(w, http.StatusConflict, "human verification settings revision conflict")
	case errors.Is(err, humanverification.ErrCandidateNotFound), errors.Is(err, humanverification.ErrVersionNotFound):
		writeAPIError(w, http.StatusConflict, "human verification candidate changed")
	case errors.Is(err, humanverification.ErrSecretInheritance):
		writeAPIError(w, http.StatusBadRequest, "a human verification secret is required")
	case errors.Is(err, humanverification.ErrCandidateTestRequired):
		writeAPIError(w, http.StatusConflict, "a successful human verification candidate test is required")
	case errors.Is(err, humanverification.ErrCandidateTestExpired):
		writeAPIError(w, http.StatusConflict, "the successful human verification candidate test has expired")
	case errors.Is(err, humanverification.ErrNoPreviousVersion):
		writeAPIError(w, http.StatusConflict, "no previous human verification configuration is available")
	case errors.Is(err, humanverification.ErrNoActiveVersion):
		writeAPIError(w, http.StatusConflict, "no active human verification configuration is available")
	case errors.Is(err, humanverification.ErrAlreadyDisabled):
		writeAPIError(w, http.StatusConflict, "human verification is already disabled")
	case errors.Is(err, humanverification.ErrAlreadyEnabled):
		writeAPIError(w, http.StatusConflict, "human verification is already enabled")
	case errors.Is(err, humanverification.ErrInvalidConfig):
		writeAPIError(w, http.StatusBadRequest, err.Error())
	default:
		slog.Error("human verification settings operation failed", "error", err)
		writeAPIError(w, http.StatusInternalServerError, "human verification settings operation failed")
	}
}
