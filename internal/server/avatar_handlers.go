package server

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/avatar"
)

const avatarMultipartOverhead = 1 << 20

func (s *Server) handleUploadMyAvatar(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	s.handleAvatarUpload(w, r, current.ID, false)
}

func (s *Server) handleUploadUserAvatar(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	s.handleAvatarUpload(w, r, userID, true)
}

func (s *Server) handleAvatarUpload(w http.ResponseWriter, r *http.Request, userID uuid.UUID, admin bool) {
	started := time.Now()
	if !s.reserveAvatarOperation(w, r, "upload", userID) {
		return
	}
	releaseProcessing, ok := s.reserveAvatarProcessing(w, r)
	if !ok {
		return
	}
	defer releaseProcessing()
	contents, err := readSingleAvatarPart(w, r)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.Is(err, avatar.ErrImageTooLarge) || errors.As(err, &maxBytesErr) {
			s.telemetry.RecordAvatarOperation(r.Context(), "upload", "rejected", "too_large", time.Since(started))
			writeAPIError(w, http.StatusRequestEntityTooLarge, avatar.ErrImageTooLarge.Error())
			return
		}
		s.telemetry.RecordAvatarOperation(r.Context(), "upload", "rejected", "invalid_image", time.Since(started))
		writeAPIError(w, http.StatusBadRequest, "request must contain exactly one avatar file")
		return
	}
	if admin {
		_, err = s.avatarService.UploadAdminAvatar(r.Context(), userID, bytes.NewReader(contents), time.Now().UTC())
	} else {
		_, err = s.avatarService.UploadUserAvatar(r.Context(), userID, bytes.NewReader(contents), time.Now().UTC())
	}
	if err != nil {
		result := "failure"
		if avatarInputError(err) || errors.Is(err, avatar.ErrNotFound) {
			result = "rejected"
		} else {
			s.telemetry.RecordAvatarStorageError(r.Context(), string(s.avatarStore.Backend()), "put")
		}
		s.telemetry.RecordAvatarOperation(r.Context(), "upload", result, avatarMetricReason(err), time.Since(started))
		writeAvatarOperationError(w, err)
		return
	}
	s.telemetry.RecordAvatarOperation(r.Context(), "upload", "success", "none", time.Since(started))
	updated, err := s.userService.GetByID(r.Context(), userID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "avatar was updated but the user could not be reloaded")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) reserveAvatarProcessing(w http.ResponseWriter, r *http.Request) (func(), bool) {
	if s.avatarProcessing == nil {
		return func() {}, true
	}
	select {
	case s.avatarProcessing <- struct{}{}:
		return func() { <-s.avatarProcessing }, true
	default:
		w.Header().Set("Retry-After", "2")
		s.telemetry.RecordAvatarOperation(r.Context(), "upload", "rejected", "processor_busy", -1)
		writeAPIError(w, http.StatusServiceUnavailable, "avatar operation is temporarily unavailable")
		return nil, false
	}
}

func readSingleAvatarPart(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, avatar.MaxUploadBytes+avatarMultipartOverhead)
	reader, err := r.MultipartReader()
	if err != nil {
		return nil, err
	}
	var contents []byte
	found := false
	for {
		part, nextErr := reader.NextPart()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nil, nextErr
		}
		if found || part.FormName() != "avatar" || strings.TrimSpace(part.FileName()) == "" {
			_ = part.Close()
			return nil, errors.New("unexpected multipart part")
		}
		contents, err = io.ReadAll(io.LimitReader(part, avatar.MaxUploadBytes+1))
		_ = part.Close()
		if err != nil {
			return nil, err
		}
		if len(contents) > avatar.MaxUploadBytes {
			return nil, avatar.ErrImageTooLarge
		}
		found = true
	}
	if !found || len(contents) == 0 {
		return nil, errors.New("avatar file is required")
	}
	return contents, nil
}

func writeAvatarOperationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, avatar.ErrImageTooLarge):
		writeAPIError(w, http.StatusRequestEntityTooLarge, err.Error())
	case errors.Is(err, avatar.ErrUnsupportedMedia),
		errors.Is(err, avatar.ErrAnimatedWebP),
		errors.Is(err, avatar.ErrInvalidDimensions),
		errors.Is(err, avatar.ErrUserImageNotSquare):
		writeAPIError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, avatar.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "user not found")
	default:
		writeAPIError(w, http.StatusServiceUnavailable, "avatar storage is temporarily unavailable")
	}
}

func avatarInputError(err error) bool {
	return errors.Is(err, avatar.ErrImageTooLarge) || errors.Is(err, avatar.ErrUnsupportedMedia) ||
		errors.Is(err, avatar.ErrAnimatedWebP) || errors.Is(err, avatar.ErrInvalidDimensions) ||
		errors.Is(err, avatar.ErrUserImageNotSquare)
}

func avatarMetricReason(err error) string {
	switch {
	case errors.Is(err, avatar.ErrImageTooLarge):
		return "too_large"
	case errors.Is(err, avatar.ErrUnsupportedMedia):
		return "unsupported_media"
	case errors.Is(err, avatar.ErrAnimatedWebP):
		return "animated"
	case errors.Is(err, avatar.ErrInvalidDimensions):
		return "invalid_dimensions"
	case errors.Is(err, avatar.ErrUserImageNotSquare):
		return "not_square"
	case errors.Is(err, avatar.ErrNotFound):
		return "not_found"
	default:
		return "storage_unavailable"
	}
}

func (s *Server) handleDeleteMyAvatar(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	s.handleAvatarDelete(w, r, current.ID)
}

func (s *Server) handleDeleteUserAvatar(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	s.handleAvatarDelete(w, r, userID)
}

func (s *Server) handleAvatarDelete(w http.ResponseWriter, r *http.Request, userID uuid.UUID) {
	started := time.Now()
	if !s.reserveAvatarOperation(w, r, "delete", userID) {
		return
	}
	cleanupDeferred, err := s.avatarService.DeleteUserAvatar(r.Context(), userID, time.Now().UTC())
	if err != nil {
		s.telemetry.RecordAvatarOperation(r.Context(), "delete", "failure", avatarMetricReason(err), time.Since(started))
		if !errors.Is(err, avatar.ErrNotFound) {
			s.telemetry.RecordAvatarStorageError(r.Context(), string(s.avatarStore.Backend()), "delete")
		}
		writeAvatarOperationError(w, err)
		return
	}
	reason := "none"
	if cleanupDeferred {
		reason = "cleanup_deferred"
		s.telemetry.RecordAvatarStorageError(r.Context(), string(s.avatarStore.Backend()), "delete")
	}
	s.telemetry.RecordAvatarOperation(r.Context(), "delete", "success", reason, time.Since(started))
	updated, err := s.userService.GetByID(r.Context(), userID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "avatar was removed but the user could not be reloaded")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) reserveAvatarOperation(w http.ResponseWriter, r *http.Request, action string, userID uuid.UUID) bool {
	allowed, retry, err := s.avatarLimiter.Reserve(r.Context(), action, requestIP(r), userID.String())
	if err != nil {
		s.telemetry.RecordRateLimit(r.Context(), "avatar", action, "error")
		s.telemetry.RecordAvatarOperation(r.Context(), action, "failure", "dependency_unavailable", -1)
		writeAPIError(w, http.StatusServiceUnavailable, "avatar operation is temporarily unavailable")
		return false
	}
	if !allowed {
		s.telemetry.RecordRateLimit(r.Context(), "avatar", action, "rejected")
		s.telemetry.RecordAvatarOperation(r.Context(), action, "rejected", "rate_limited", -1)
		seconds := int64((retry + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeAPIError(w, http.StatusTooManyRequests, "too many avatar operations")
		return false
	}
	s.telemetry.RecordRateLimit(r.Context(), "avatar", action, "allowed")
	return true
}

func (s *Server) handleAvatarMedia(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	avatarID, err := uuid.Parse(chi.URLParam(r, "avatar_id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	size, err := strconv.Atoi(chi.URLParam(r, "size"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	object, err := s.avatarService.OpenActiveVariant(r.Context(), avatarID, size)
	if err != nil {
		if errors.Is(err, avatar.ErrNotFound) {
			s.telemetry.RecordAvatarOperation(r.Context(), "read", "rejected", "not_found", time.Since(started))
			http.NotFound(w, r)
			return
		}
		s.telemetry.RecordAvatarOperation(r.Context(), "read", "failure", "storage_unavailable", time.Since(started))
		s.telemetry.RecordAvatarStorageError(r.Context(), string(s.avatarStore.Backend()), "get")
		slog.WarnContext(r.Context(), "avatar media read failed", "avatar_id", avatarID, "size", size, "error", err)
		writeAPIError(w, http.StatusServiceUnavailable, "avatar media is temporarily unavailable")
		return
	}
	s.telemetry.RecordAvatarOperation(r.Context(), "read", "success", "none", time.Since(started))
	defer object.Body.Close()
	w.Header().Set("Content-Type", avatar.ContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	if object.Size >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(object.Size, 10))
	}
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, object.Body); err != nil && !errors.Is(err, r.Context().Err()) {
		slog.WarnContext(r.Context(), "avatar media response interrupted", "avatar_id", avatarID, "size", size, "error", err)
	}
}
