package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/avatar"
	"github.com/nyasharp/nyauth/internal/mediaruntime"
	"github.com/nyasharp/nyauth/internal/servicecontrol"
	"github.com/nyasharp/nyauth/pkg/models"
)

type saveMediaCandidateRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	Endpoint         string `json:"endpoint"`
	Region           string `json:"region"`
	Bucket           string `json:"bucket"`
	Prefix           string `json:"prefix"`
	PathStyle        bool   `json:"path_style"`
	AccessKeyID      string `json:"access_key_id"`
	SecretAccessKey  string `json:"secret_access_key"`
	SessionToken     string `json:"session_token"`
}

type mediaProfileRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	ProfileID        string `json:"profile_id"`
}

func (s *Server) handleGetMediaSettings(w http.ResponseWriter, r *http.Request) {
	if !s.requireRecentAuthentication(w, r) {
		return
	}
	if s.mediaManager == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "media settings are temporarily unavailable")
		return
	}
	status, err := s.mediaManager.Status(r.Context())
	if err != nil {
		slog.ErrorContext(r.Context(), "loading media settings failed", "error", err)
		writeAPIError(w, http.StatusServiceUnavailable, "media settings are temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleSaveMediaCandidate(w http.ResponseWriter, r *http.Request) {
	mutation, ok := s.authorizeMediaMutation(w, r)
	if !ok {
		return
	}
	var request saveMediaCandidateRequest
	if decodeJSON(w, r, &request) != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	profile, state, err := s.mediaManager.CreateCandidate(r.Context(), mediaruntime.CreateCandidateInput{ExpectedRevision: request.ExpectedRevision, Settings: mediaruntime.ProfileSettings{Endpoint: request.Endpoint, Region: request.Region, Bucket: request.Bucket, Prefix: request.Prefix, PathStyle: request.PathStyle}, Credentials: mediaruntime.Credentials{AccessKeyID: request.AccessKeyID, SecretAccessKey: request.SecretAccessKey, SessionToken: request.SessionToken}, Audit: mutation})
	if err != nil {
		s.writeMediaMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"candidate": profile, "revision": state.Revision})
}

func (s *Server) handleTestMediaCandidate(w http.ResponseWriter, r *http.Request) {
	mutation, ok := s.authorizeMediaMutation(w, r)
	if !ok {
		return
	}
	request, id, ok := decodeMediaProfileRequest(w, r)
	if !ok {
		return
	}
	profile, state, err := s.mediaManager.TestCandidate(r.Context(), mediaruntime.TestCandidateInput{ExpectedRevision: request.ExpectedRevision, ProfileID: id, Audit: mutation})
	if err != nil {
		s.writeMediaMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"candidate": profile, "revision": state.Revision, "result": profile.TestResult})
}

func (s *Server) handleStartMediaMigration(w http.ResponseWriter, r *http.Request) {
	mutation, ok := s.authorizeMediaMutation(w, r)
	if !ok {
		return
	}
	request, profileID, ok := decodeMediaProfileRequest(w, r)
	if !ok {
		return
	}
	current, err := s.mediaManager.Current(r.Context())
	if err != nil {
		s.writeMediaMutationError(w, err)
		return
	}
	controlState, err := s.serviceControl.Status(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service control is temporarily unavailable")
		return
	}
	previous := serviceControlSnapshotForMedia(controlState.Snapshot)
	autoAdded := !containsCapability(controlState.Snapshot.PausedCapabilities, servicecontrol.CapabilityMediaWrites)
	controlRevision := controlState.Snapshot.Revision
	if autoAdded {
		if controlState.Snapshot.ExpiresAt != nil {
			writeAPIError(w, http.StatusConflict, "clear the current maintenance expiry before starting media migration")
			return
		}
		paused := append([]servicecontrol.Capability(nil), controlState.Snapshot.PausedCapabilities...)
		paused = append(paused, servicecontrol.CapabilityMediaWrites)
		sort.Slice(paused, func(i, j int) bool { return paused[i] < paused[j] })
		reason := strings.TrimSpace(controlState.Snapshot.InternalReason)
		if reason == "" {
			reason = "media storage migration"
		}
		controlAudit := mutation
		controlAudit.Event = models.AuditServiceControlUpdated
		updated, updateErr := s.serviceControl.Update(r.Context(), controlRevision, servicecontrol.UpdateRequest{PausedCapabilities: paused, PublicMessage: controlState.Snapshot.PublicMessage, InternalReason: reason, ExpiresAt: controlState.Snapshot.ExpiresAt}, controlAudit)
		if updateErr != nil {
			s.writeMediaMutationError(w, updateErr)
			return
		}
		controlRevision = updated.Snapshot.Revision
		if !updated.Applied {
			s.tryRestoreMediaControl(r.Context(), controlRevision, previous, mutation)
			writeAPIError(w, http.StatusConflict, "media writes are still draining; retry after service control is applied")
			return
		}
	} else if !controlState.Applied {
		writeAPIError(w, http.StatusConflict, "media writes are still draining; retry after service control is applied")
		return
	}
	previous["auto_added_media_writes"] = autoAdded
	migration, state, startErr := s.mediaManager.StartMigration(r.Context(), mediaruntime.StartMigrationInput{ExpectedRevision: request.ExpectedRevision, ProfileID: profileID, SourceBackend: string(current.Store.Backend()), ServiceControlRevision: controlRevision, ServiceControlPrevious: previous, Audit: mutation})
	if startErr != nil {
		if autoAdded {
			s.tryRestoreMediaControl(r.Context(), controlRevision, previous, mutation)
		}
		s.writeMediaMutationError(w, startErr)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"migration": migration, "revision": state.Revision})
}

func (s *Server) handleRetryMediaMigration(w http.ResponseWriter, r *http.Request) {
	mutation, ok := s.authorizeMediaMutation(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(chiURLParam(r, "id")))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "migration id is invalid")
		return
	}
	controlState, err := s.serviceControl.Status(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service control is temporarily unavailable")
		return
	}
	if !containsCapability(controlState.Snapshot.PausedCapabilities, servicecontrol.CapabilityMediaWrites) {
		writeAPIError(w, http.StatusConflict, "media writes must be paused before migration")
		return
	}
	if !controlState.Applied {
		writeAPIError(w, http.StatusConflict, "media writes are still draining; retry after service control is applied")
		return
	}
	previous := serviceControlSnapshotForMedia(controlState.Snapshot)
	previous["auto_added_media_writes"] = false
	migration, err := s.mediaManager.RetryMigration(r.Context(), mediaruntime.RetryMigrationInput{MigrationID: id, ServiceControlRevision: controlState.Snapshot.Revision, ServiceControlPrevious: previous, Audit: mutation})
	if err != nil {
		s.writeMediaMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"migration": migration})
}

func decodeMediaProfileRequest(w http.ResponseWriter, r *http.Request) (mediaProfileRequest, uuid.UUID, bool) {
	var request mediaProfileRequest
	if decodeJSON(w, r, &request) != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return request, uuid.Nil, false
	}
	id, err := uuid.Parse(strings.TrimSpace(request.ProfileID))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "profile id is invalid")
		return request, uuid.Nil, false
	}
	return request, id, true
}

func (s *Server) authorizeMediaMutation(w http.ResponseWriter, r *http.Request) (audit.MutationAudit, bool) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return audit.MutationAudit{}, false
	}
	if !s.requireRecentAuthentication(w, r) {
		return audit.MutationAudit{}, false
	}
	if s.operationsSettingsLimiter == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "media settings are temporarily unavailable")
		return audit.MutationAudit{}, false
	}
	allowed, retry, err := s.operationsSettingsLimiter.Reserve(r.Context(), requestIP(r), current.ID.String())
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "media settings are temporarily unavailable")
		return audit.MutationAudit{}, false
	}
	if !allowed {
		w.Header().Set("Retry-After", retryAfterSeconds(retry))
		writeAPIError(w, http.StatusTooManyRequests, "too many media settings operations")
		return audit.MutationAudit{}, false
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return audit.MutationAudit{}, false
	}
	return mutation, true
}

func (s *Server) writeMediaMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, mediaruntime.ErrInvalidConfig):
		writeAPIError(w, http.StatusBadRequest, "media storage configuration is invalid")
	case errors.Is(err, mediaruntime.ErrStateConflict), errors.Is(err, mediaruntime.ErrCandidateChanged), errors.Is(err, servicecontrol.ErrRevisionConflict):
		writeAPIError(w, http.StatusConflict, "media settings changed; reload and try again")
	case errors.Is(err, mediaruntime.ErrCandidateNotFound):
		writeAPIError(w, http.StatusNotFound, "media storage candidate was not found")
	case errors.Is(err, mediaruntime.ErrCandidateTestRequired):
		writeAPIError(w, http.StatusConflict, "a recent successful media storage test is required")
	case errors.Is(err, mediaruntime.ErrMigrationActive):
		writeAPIError(w, http.StatusConflict, "a media storage migration is already active")
	case errors.Is(err, mediaruntime.ErrMigrationNotPaused):
		writeAPIError(w, http.StatusConflict, "media writes must be paused before migration")
	case errors.Is(err, mediaruntime.ErrInstancesNotReady):
		writeAPIError(w, http.StatusConflict, "active instances are still preparing the media storage candidate")
	case errors.Is(err, mediaruntime.ErrMigrationNotFound):
		writeAPIError(w, http.StatusNotFound, "media storage migration was not found")
	default:
		writeAPIError(w, http.StatusServiceUnavailable, "media settings are temporarily unavailable")
	}
}

func serviceControlSnapshotForMedia(value servicecontrol.Snapshot) map[string]any {
	return map[string]any{"paused_capabilities": value.PausedCapabilities, "public_message": value.PublicMessage, "internal_reason": value.InternalReason, "expires_at": value.ExpiresAt}
}
func containsCapability(values []servicecontrol.Capability, target servicecontrol.Capability) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (s *Server) restoreMediaWritesAfterMigration(ctx context.Context, migration mediaruntime.Migration) error {
	if migration.ServiceControlRevision == nil || migration.CreatedBy == nil {
		return nil
	}
	autoAdded, _ := migration.ServiceControlPrevious["auto_added_media_writes"].(bool)
	if !autoAdded {
		return nil
	}
	mutation := audit.MutationAudit{Event: models.AuditServiceControlUpdated, ActorID: *migration.CreatedBy, ActorName: migration.CreatedByName, RiskLevel: "critical"}
	return s.restoreMediaControl(ctx, *migration.ServiceControlRevision, migration.ServiceControlPrevious, mutation)
}
func (s *Server) tryRestoreMediaControl(ctx context.Context, revision int64, previous map[string]any, mutation audit.MutationAudit) {
	mutation.Event = models.AuditServiceControlUpdated
	if err := s.restoreMediaControl(ctx, revision, previous, mutation); err != nil {
		slog.ErrorContext(ctx, "failed to restore service control after media migration start failure", "error", err)
	}
}
func (s *Server) restoreMediaControl(ctx context.Context, revision int64, previous map[string]any, mutation audit.MutationAudit) error {
	snapshot := s.serviceControl.Snapshot()
	if snapshot.Revision != revision {
		return errors.New("service control changed after media migration pause")
	}
	paused := make([]servicecontrol.Capability, 0)
	if raw, ok := previous["paused_capabilities"].([]any); ok {
		for _, value := range raw {
			if text, ok := value.(string); ok {
				paused = append(paused, servicecontrol.Capability(text))
			}
		}
	} else if typed, ok := previous["paused_capabilities"].([]servicecontrol.Capability); ok {
		paused = append(paused, typed...)
	}
	publicMessage, _ := previous["public_message"].(string)
	internalReason, _ := previous["internal_reason"].(string)
	var expiresAt *time.Time
	if raw, ok := previous["expires_at"].(string); ok && raw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err == nil {
			expiresAt = &parsed
		}
	}
	_, err := s.serviceControl.Update(ctx, revision, servicecontrol.UpdateRequest{PausedCapabilities: paused, PublicMessage: publicMessage, InternalReason: internalReason, ExpiresAt: expiresAt}, mutation)
	return err
}

// chiURLParam is isolated for tests that exercise the handler with a route context.
func chiURLParam(r *http.Request, name string) string { return chi.URLParam(r, name) }

var _ avatar.StoreResolver = (*mediaruntime.Manager)(nil)
