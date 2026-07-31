package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/observabilityruntime"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/internal/telemetry"
)

type observabilitySettingsResponse struct {
	Revision          int64                    `json:"revision"`
	Observability     settings.Observability   `json:"observability"`
	EffectiveLogLevel string                   `json:"effective_log_level"`
	OTLP              otlpSettingsResponse     `json:"otlp"`
	Alerts            operationalAlertSnapshot `json:"alerts"`
}

type otlpConfigResponse struct {
	ID                      *uuid.UUID `json:"id,omitempty"`
	Revision                *int64     `json:"revision,omitempty"`
	Endpoint                string     `json:"endpoint"`
	ExportInterval          string     `json:"export_interval"`
	Timeout                 string     `json:"timeout"`
	AuthorizationConfigured bool       `json:"authorization_configured"`
	CreatedAt               *time.Time `json:"created_at,omitempty"`
}

type otlpSettingsResponse struct {
	Mode          string                     `json:"mode"`
	StateRevision int64                      `json:"state_revision"`
	Active        *otlpConfigResponse        `json:"active,omitempty"`
	Candidate     *otlpConfigResponse        `json:"candidate,omitempty"`
	CandidateTest *otlpCandidateTestResponse `json:"candidate_test,omitempty"`
	Previous      *otlpConfigResponse        `json:"previous,omitempty"`
	Effective     *otlpConfigResponse        `json:"effective,omitempty"`
	Runtime       telemetry.OTLPStatus       `json:"runtime"`
}

type otlpCandidateTestResponse struct {
	Result             string     `json:"result"`
	ErrorCode          *string    `json:"error_code,omitempty"`
	TestedAt           time.Time  `json:"tested_at"`
	ValidUntil         *time.Time `json:"valid_until,omitempty"`
	ActivationEligible bool       `json:"activation_eligible"`
}

type updateObservabilitySettingsRequest struct {
	ExpectedRevision int64                  `json:"expected_revision"`
	Observability    settings.Observability `json:"observability"`
}

type saveOTLPCandidateRequest struct {
	ExpectedRevision int64   `json:"expected_revision"`
	Endpoint         string  `json:"endpoint"`
	Authorization    *string `json:"authorization"`
	ExportInterval   string  `json:"export_interval"`
	Timeout          string  `json:"timeout"`
}

type otlpVersionMutationRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	VersionID        string `json:"version_id"`
}

type otlpStateMutationRequest struct {
	ExpectedRevision int64 `json:"expected_revision"`
}

func (s *Server) handleGetObservabilitySettings(w http.ResponseWriter, r *http.Request) {
	if !s.requireRecentAuthentication(w, r) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	response, err := s.observabilitySettingsResponse(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "observability settings are temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleUpdateObservabilitySettings(w http.ResponseWriter, r *http.Request) {
	current, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request updateObservabilitySettingsRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	request.Observability.LogLevel = strings.ToLower(strings.TrimSpace(request.Observability.LogLevel))
	if request.Observability.DebugUntil != nil {
		utc := request.Observability.DebugUntil.UTC()
		request.Observability.DebugUntil = &utc
	}
	if err := settings.ValidateObservability(request.Observability); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	currentDebugUntil := s.settingsMgr.Observability().DebugUntil
	if request.Observability.DebugUntil != nil && !request.Observability.DebugUntil.After(now) {
		request.Observability.DebugUntil = nil
	}
	if !sameOptionalTime(currentDebugUntil, request.Observability.DebugUntil) {
		if err := settings.ValidateTemporaryDebug(request.Observability, now); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	revision, err := s.settingsMgr.SetObservability(r.Context(), request.Observability, request.ExpectedRevision, current.Username, mutation)
	if err != nil {
		if errors.Is(err, settings.ErrRevisionConflict) {
			writeAPIError(w, http.StatusConflict, "settings revision conflict")
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to store observability settings")
		}
		return
	}
	response, err := s.observabilitySettingsResponse(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"revision": revision, "observability": request.Observability})
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func sameOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func (s *Server) handleSaveOTLPCandidate(w http.ResponseWriter, r *http.Request) {
	_, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request saveOTLPCandidateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	exportInterval, err := time.ParseDuration(strings.TrimSpace(request.ExportInterval))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "export_interval must be a valid duration")
		return
	}
	timeout, err := time.ParseDuration(strings.TrimSpace(request.Timeout))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "timeout must be a valid duration")
		return
	}
	value, err := observabilityruntime.ValidateSettings(observabilityruntime.Settings{Endpoint: request.Endpoint, ExportInterval: exportInterval, Timeout: timeout}, s.cfg.IsProduction())
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.Authorization != nil {
		trimmed := strings.TrimSpace(*request.Authorization)
		request.Authorization = &trimmed
		if err := observabilityruntime.ValidateAuthorization(trimmed); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	result, err := s.observabilityManager.CreateCandidate(r.Context(), observabilityruntime.CreateCandidateInput{
		ExpectedRevision: request.ExpectedRevision, Settings: value, Authorization: request.Authorization, Audit: mutation,
	})
	if err != nil {
		s.writeOTLPMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"candidate": otlpResponseFromVersion(result.Version), "state_revision": result.State.Revision})
}

func (s *Server) handleTestOTLPCandidate(w http.ResponseWriter, r *http.Request) {
	_, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request otlpVersionMutationRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	versionID, err := uuid.Parse(strings.TrimSpace(request.VersionID))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "version_id is invalid")
		return
	}
	state, err := s.observabilityManager.LoadState(r.Context())
	if err != nil {
		s.writeOTLPMutationError(w, err)
		return
	}
	if state.Revision != request.ExpectedRevision {
		s.writeOTLPMutationError(w, observabilityruntime.ErrStateConflict)
		return
	}
	if state.CandidateVersionID == nil || *state.CandidateVersionID != versionID {
		s.writeOTLPMutationError(w, observabilityruntime.ErrCandidateChanged)
		return
	}
	_, config, err := s.observabilityManager.Store().LoadVersionConfig(r.Context(), versionID)
	if err != nil {
		s.writeOTLPMutationError(w, err)
		return
	}
	testCtx, cancel := context.WithTimeout(r.Context(), config.Timeout+2*time.Second)
	testErr := telemetry.TestOTLP(testCtx, telemetry.OTLPConfig{Endpoint: config.Endpoint, Authorization: config.Authorization, ExportInterval: config.ExportInterval, Timeout: config.Timeout})
	cancel()
	result := observabilityruntime.TestSuccess
	var errorCode *string
	if testErr != nil {
		code := classifyOTLPTestError(testErr)
		result, errorCode = observabilityruntime.TestFailure, &code
	}
	recorded, err := s.observabilityManager.RecordTest(r.Context(), observabilityruntime.RecordTestInput{
		ExpectedRevision: state.Revision, VersionID: versionID, Result: result, ErrorCode: errorCode, Audit: mutation,
	})
	if err != nil {
		s.writeOTLPMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": result, "error_code": errorCode, "state_revision": recorded.State.Revision, "tested_at": recorded.Record.CreatedAt})
}

func (s *Server) handleActivateOTLPCandidate(w http.ResponseWriter, r *http.Request) {
	_, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request otlpVersionMutationRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	versionID, err := uuid.Parse(strings.TrimSpace(request.VersionID))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "version_id is invalid")
		return
	}
	state, err := s.observabilityManager.Activate(r.Context(), observabilityruntime.VersionMutationInput{ExpectedRevision: request.ExpectedRevision, VersionID: versionID, Audit: mutation})
	if err != nil {
		s.writeOTLPMutationError(w, err)
		return
	}
	if err := s.observabilityManager.Load(r.Context()); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "OTLP configuration was activated but could not be applied on this instance")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state_revision": state.Revision, "mode": state.Mode})
}

func (s *Server) handleRollbackOTLP(w http.ResponseWriter, r *http.Request) {
	_, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request otlpStateMutationRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	state, err := s.observabilityManager.Rollback(r.Context(), observabilityruntime.StateMutationInput{ExpectedRevision: request.ExpectedRevision, Audit: mutation})
	if err != nil {
		s.writeOTLPMutationError(w, err)
		return
	}
	if err := s.observabilityManager.Load(r.Context()); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "OTLP rollback was stored but could not be applied on this instance")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state_revision": state.Revision, "mode": state.Mode})
}

func (s *Server) handleDisableOTLP(w http.ResponseWriter, r *http.Request) {
	_, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request otlpStateMutationRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	state, err := s.observabilityManager.Disable(r.Context(), observabilityruntime.StateMutationInput{ExpectedRevision: request.ExpectedRevision, Audit: mutation})
	if err != nil {
		s.writeOTLPMutationError(w, err)
		return
	}
	if err := s.observabilityManager.Load(r.Context()); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "OTLP disable was stored but could not be applied on this instance")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state_revision": state.Revision, "mode": state.Mode})
}

func (s *Server) observabilitySettingsResponse(ctx context.Context) (observabilitySettingsResponse, error) {
	snapshot := s.settingsMgr.ObservabilitySnapshot()
	state, err := s.observabilityManager.LoadState(ctx)
	if err != nil {
		return observabilitySettingsResponse{}, err
	}
	otlp := otlpSettingsResponse{Mode: state.Mode, StateRevision: state.Revision, Runtime: s.telemetry.OTLPStatus()}
	load := func(id *uuid.UUID) (*otlpConfigResponse, error) {
		if id == nil {
			return nil, nil
		}
		version, err := s.observabilityManager.LoadVersion(ctx, *id)
		if err != nil {
			return nil, err
		}
		response := otlpResponseFromVersion(version)
		return &response, nil
	}
	if otlp.Active, err = load(state.ActiveVersionID); err != nil {
		return observabilitySettingsResponse{}, err
	}
	if otlp.Candidate, err = load(state.CandidateVersionID); err != nil {
		return observabilitySettingsResponse{}, err
	}
	if state.CandidateVersionID != nil {
		record, loadErr := s.observabilityManager.LoadLatestTest(ctx, *state.CandidateVersionID)
		if loadErr != nil {
			return observabilitySettingsResponse{}, loadErr
		}
		if record != nil {
			now := time.Now().UTC()
			response := otlpCandidateTestResponse{Result: record.Result, ErrorCode: record.ErrorCode, TestedAt: record.CreatedAt}
			if record.Result == observabilityruntime.TestSuccess {
				validUntil := record.CreatedAt.Add(observabilityruntime.CandidateTestValidity)
				response.ValidUntil = &validUntil
				response.ActivationEligible = !record.CreatedAt.After(now) && !validUntil.Before(now)
			}
			otlp.CandidateTest = &response
		}
	}
	if otlp.Previous, err = load(state.PreviousVersionID); err != nil {
		return observabilitySettingsResponse{}, err
	}
	effective := s.observabilityManager.Effective()
	if effective.Config != nil {
		response := otlpConfigResponse{Endpoint: effective.Config.Endpoint, ExportInterval: effective.Config.ExportInterval.String(), Timeout: effective.Config.Timeout.String(), AuthorizationConfigured: effective.Config.Authorization != ""}
		if effective.VersionID != nil {
			response.ID = effective.VersionID
		}
		otlp.Effective = &response
	}
	effectiveLogLevel := snapshot.Value.LogLevel
	if snapshot.Value.DebugUntil != nil && snapshot.Value.DebugUntil.After(time.Now()) {
		effectiveLogLevel = "debug"
	}
	alerts := operationalAlertSnapshot{Status: "unavailable", Active: []operationalAlert{}}
	if s.operationalAlerts != nil {
		alerts = s.operationalAlerts.Snapshot()
	}
	return observabilitySettingsResponse{Revision: snapshot.Revision, Observability: snapshot.Value, EffectiveLogLevel: effectiveLogLevel, OTLP: otlp, Alerts: alerts}, nil
}

func otlpResponseFromVersion(version observabilityruntime.Version) otlpConfigResponse {
	id, revision, createdAt := version.ID, version.Revision, version.CreatedAt
	return otlpConfigResponse{ID: &id, Revision: &revision, Endpoint: version.Endpoint, ExportInterval: version.ExportInterval.String(), Timeout: version.Timeout.String(), AuthorizationConfigured: version.AuthorizationConfigured, CreatedAt: &createdAt}
}

func classifyOTLPTestError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return observabilityruntime.TestErrorTimeout
	}
	return observabilityruntime.TestErrorConnectionOrCollectorRejected
}

func (s *Server) writeOTLPMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, observabilityruntime.ErrStateConflict):
		writeAPIError(w, http.StatusConflict, "OTLP settings revision conflict")
	case errors.Is(err, observabilityruntime.ErrCandidateNotFound), errors.Is(err, observabilityruntime.ErrCandidateChanged):
		writeAPIError(w, http.StatusConflict, "OTLP candidate changed; reload settings")
	case errors.Is(err, observabilityruntime.ErrCandidateTestRequired):
		writeAPIError(w, http.StatusConflict, "a recent successful OTLP candidate test is required")
	case errors.Is(err, observabilityruntime.ErrCandidateTestExpired):
		writeAPIError(w, http.StatusConflict, "the successful OTLP candidate test has expired")
	case errors.Is(err, observabilityruntime.ErrNoPreviousVersion):
		writeAPIError(w, http.StatusConflict, "no previous OTLP configuration is available")
	case errors.Is(err, observabilityruntime.ErrAlreadyDisabled):
		writeAPIError(w, http.StatusConflict, "OTLP export is already disabled")
	case errors.Is(err, observabilityruntime.ErrAuthorizationInheritance), errors.Is(err, observabilityruntime.ErrInvalidConfig):
		writeAPIError(w, http.StatusBadRequest, err.Error())
	default:
		writeAPIError(w, http.StatusServiceUnavailable, "OTLP settings are temporarily unavailable")
	}
}
