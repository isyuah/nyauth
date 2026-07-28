package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/servicecontrol"
)

const (
	serviceStatusEventsPath     = "/api/service-status/events"
	serviceStatusEventName      = "service-status"
	serviceStatusKeepalive      = 10 * time.Second
	maxServiceStatusConnections = int64(256)
)

type publicServiceStatusResponse struct {
	Status             string                      `json:"status"`
	PausedCapabilities []servicecontrol.Capability `json:"paused_capabilities"`
	PublicMessage      string                      `json:"public_message"`
	ExpiresAt          *time.Time                  `json:"expires_at"`
	RetryAfterSeconds  int64                       `json:"retry_after_seconds"`
}

type serviceControlInstanceResponse struct {
	InstanceID      string    `json:"instance_id"`
	Version         string    `json:"version"`
	StartedAt       time.Time `json:"started_at"`
	HeartbeatAt     time.Time `json:"heartbeat_at"`
	LoadedRevision  int64     `json:"loaded_revision"`
	AppliedRevision int64     `json:"applied_revision"`
}

type operationsSettingsResponse struct {
	publicServiceStatusResponse
	Revision          int64                            `json:"revision"`
	InternalReason    string                           `json:"internal_reason"`
	UpdatedAt         time.Time                        `json:"updated_at"`
	UpdatedBy         *string                          `json:"updated_by"`
	ApplicationStatus string                           `json:"application_status"`
	ActiveInstances   int                              `json:"active_instances"`
	AppliedInstances  int                              `json:"applied_instances"`
	Instances         []serviceControlInstanceResponse `json:"instances"`
}

type updateOperationsSettingsRequest struct {
	ExpectedRevision int64 `json:"expected_revision"`
	servicecontrol.UpdateRequest
}

type serviceControlRuntime interface {
	Start(context.Context) error
	Acquire(...servicecontrol.Capability) (func(), error)
	Snapshot() servicecontrol.Snapshot
	Changes() <-chan struct{}
	FailClosed() bool
	Status(context.Context) (servicecontrol.State, error)
	Update(context.Context, int64, servicecontrol.UpdateRequest, audit.MutationAudit) (servicecontrol.State, error)
}

func (s *Server) capabilityMiddleware(capabilities ...servicecontrol.Capability) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			release, err := s.acquireCapabilities(capabilities...)
			if err != nil {
				s.writeCapabilityPaused(w, err)
				return
			}
			defer release()
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) acquireCapabilities(capabilities ...servicecontrol.Capability) (func(), error) {
	if s.serviceControl == nil {
		return nil, &servicecontrol.PausedError{
			Capabilities: capabilities, RetryAfter: time.Minute, FailClosed: true,
		}
	}
	return s.serviceControl.Acquire(capabilities...)
}

func (s *Server) capabilityAvailable(capability servicecontrol.Capability) bool {
	if s.serviceControl == nil || s.serviceControl.FailClosed() {
		return false
	}
	for _, paused := range s.serviceControl.Snapshot().PausedCapabilities {
		if paused == capability {
			return false
		}
	}
	return true
}

func (s *Server) acquireWorkerCapability(capability servicecontrol.Capability) func() (func(), bool) {
	return func() (func(), bool) {
		release, err := s.acquireCapabilities(capability)
		if err != nil {
			return nil, false
		}
		return release, true
	}
}

func (s *Server) acquireMFAIssuance(w http.ResponseWriter, purpose string) (func(), bool) {
	if purpose == mfaPurposeReauthentication {
		return func() {}, true
	}
	release, err := s.acquireCapabilities(servicecontrol.CapabilityAuthIssuance)
	if err != nil {
		s.writeCapabilityPaused(w, err)
		return nil, false
	}
	return release, true
}

func (s *Server) writeCapabilityPaused(w http.ResponseWriter, err error) {
	retryAfter := int64(60)
	var paused *servicecontrol.PausedError
	if errors.As(err, &paused) {
		retryAfter = durationSecondsCeil(paused.RetryAfter)
	}
	w.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
	writeAPIError(w, http.StatusServiceUnavailable, "service capability is paused")
}

func durationSecondsCeil(value time.Duration) int64 {
	if value <= 0 {
		return 1
	}
	seconds := int64((value + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func (s *Server) handleServiceStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.currentPublicServiceStatus())
}

func (s *Server) currentPublicServiceStatus() publicServiceStatusResponse {
	snapshot := servicecontrol.Snapshot{PausedCapabilities: []servicecontrol.Capability{}}
	failClosed := true
	if s.serviceControl != nil {
		snapshot = s.serviceControl.Snapshot()
		failClosed = s.serviceControl.FailClosed()
	}
	return publicServiceStatus(snapshot, failClosed)
}

func (s *Server) handleServiceStatusEvents(w http.ResponseWriter, r *http.Request) {
	if !s.acquireServiceStatusStream() {
		w.Header().Set("Retry-After", "5")
		writeAPIError(w, http.StatusServiceUnavailable, "too many service status streams")
		return
	}
	defer s.serviceStatusStreams.Add(-1)

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "streaming is unavailable")
		return
	}
	if err := http.NewResponseController(w).SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		writeAPIError(w, http.StatusInternalServerError, "streaming is unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	var lastPayload []byte
	keepalive := time.NewTicker(serviceStatusKeepalive)
	defer keepalive.Stop()
	for {
		var changes <-chan struct{}
		if s.serviceControl != nil {
			changes = s.serviceControl.Changes()
		}
		status := s.currentPublicServiceStatus()
		payload, err := json.Marshal(status)
		if err != nil {
			return
		}
		if !bytes.Equal(payload, lastPayload) {
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", serviceStatusEventName, payload); err != nil {
				return
			}
			flusher.Flush()
			lastPayload = append(lastPayload[:0], payload...)
		}

		var expiry <-chan time.Time
		var expiryTimer *time.Timer
		if status.ExpiresAt != nil {
			// RetryAfterSeconds is derived from the controller's calibrated
			// PostgreSQL clock, so host clock skew cannot delay local recovery.
			delay := time.Duration(status.RetryAfterSeconds) * time.Second
			expiryTimer = time.NewTimer(delay)
			expiry = expiryTimer.C
		}

		select {
		case <-r.Context().Done():
			if expiryTimer != nil {
				expiryTimer.Stop()
			}
			return
		case <-changes:
		case <-expiry:
		case <-keepalive.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				if expiryTimer != nil {
					expiryTimer.Stop()
				}
				return
			}
			flusher.Flush()
		}
		if expiryTimer != nil {
			expiryTimer.Stop()
		}
	}
}

func (s *Server) acquireServiceStatusStream() bool {
	for {
		current := s.serviceStatusStreams.Load()
		if current >= maxServiceStatusConnections {
			return false
		}
		if s.serviceStatusStreams.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func publicServiceStatus(snapshot servicecontrol.Snapshot, failClosed bool) publicServiceStatusResponse {
	paused := append([]servicecontrol.Capability(nil), snapshot.PausedCapabilities...)
	message := snapshot.PublicMessage
	expiresAt := snapshot.ExpiresAt
	if failClosed {
		paused = servicecontrol.AllCapabilities()
		message = "服务运行状态同步暂时不可用，受控操作已暂停。"
		expiresAt = nil
	}
	if paused == nil {
		paused = []servicecontrol.Capability{}
	}
	retryAfter := int64(0)
	if len(paused) > 0 {
		retryAfter = 60
		if expiresAt != nil {
			now := time.Now().UTC()
			if !snapshot.DatabaseNow.IsZero() && !snapshot.ObservedAt.IsZero() {
				now = snapshot.DatabaseNow.Add(now.Sub(snapshot.ObservedAt))
			}
			retryAfter = durationSecondsCeil(expiresAt.Sub(now))
		}
	}
	return publicServiceStatusResponse{
		Status: derivedOperatingState(paused), PausedCapabilities: paused,
		PublicMessage: message, ExpiresAt: expiresAt, RetryAfterSeconds: retryAfter,
	}
}

func derivedOperatingState(paused []servicecontrol.Capability) string {
	if len(paused) == 0 {
		return "normal"
	}
	if len(paused) == len(servicecontrol.AllCapabilities()) {
		return "full_pause"
	}
	for _, capability := range paused {
		if capability == servicecontrol.CapabilityAuthIssuance {
			return "authentication_paused"
		}
	}
	return "restricted"
}

func (s *Server) handleGetOperationsSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.serviceControl == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service control is temporarily unavailable")
		return
	}
	state, err := s.serviceControl.Status(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service control is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, operationsSettingsFromState(state, s.serviceControl.FailClosed()))
}

func (s *Server) handleUpdateOperationsSettings(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !s.requireRecentAuthentication(w, r) {
		return
	}
	if s.operationsSettingsLimiter == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service control is temporarily unavailable")
		return
	}
	allowed, retry, err := s.operationsSettingsLimiter.Reserve(r.Context(), requestIP(r), current.ID.String())
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service control is temporarily unavailable")
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", strconv.FormatInt(durationSecondsCeil(retry), 10))
		writeAPIError(w, http.StatusTooManyRequests, "too many service control operations")
		return
	}
	var request updateOperationsSettingsRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	state, err := s.serviceControl.Update(r.Context(), request.ExpectedRevision, request.UpdateRequest, mutation)
	if err != nil {
		switch {
		case errors.Is(err, servicecontrol.ErrRevisionConflict):
			writeAPIError(w, http.StatusConflict, "service control revision conflict")
		case errors.Is(err, servicecontrol.ErrDependencyViolation):
			writeAPIError(w, http.StatusConflict, "service control dependency violation")
		case errors.Is(err, servicecontrol.ErrInvalidState), errors.Is(err, servicecontrol.ErrUnknownCapability):
			writeAPIError(w, http.StatusBadRequest, "invalid service control settings")
		default:
			writeAPIError(w, http.StatusServiceUnavailable, "service control is temporarily unavailable")
		}
		return
	}
	status := http.StatusOK
	if !state.Applied {
		status = http.StatusAccepted
	}
	writeJSON(w, status, operationsSettingsFromState(state, s.serviceControl.FailClosed()))
}

func operationsSettingsFromState(state servicecontrol.State, failClosed bool) operationsSettingsResponse {
	instances := make([]serviceControlInstanceResponse, 0, len(state.Instances))
	for _, instance := range state.Instances {
		instances = append(instances, serviceControlInstanceResponse{
			InstanceID: instance.ID.String(), Version: instance.Version,
			StartedAt: instance.StartedAt, HeartbeatAt: instance.HeartbeatAt,
			LoadedRevision: instance.LoadedRevision, AppliedRevision: instance.AppliedRevision,
		})
	}
	applicationStatus := "applying"
	if state.Applied {
		applicationStatus = "applied"
	}
	return operationsSettingsResponse{
		publicServiceStatusResponse: publicServiceStatus(state.Snapshot, failClosed),
		Revision:                    state.Snapshot.Revision, InternalReason: state.Snapshot.InternalReason,
		UpdatedAt: state.Snapshot.UpdatedAt, UpdatedBy: state.Snapshot.UpdatedByName,
		ApplicationStatus: applicationStatus, ActiveInstances: state.ActiveInstances,
		AppliedInstances: state.AppliedInstances, Instances: instances,
	}
}
