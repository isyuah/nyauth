package server

import (
	"bytes"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/avatar"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/securityaction"
	"github.com/nyasharp/nyauth/pkg/models"
)

func (s *Server) handleUpdateMyClient(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var request models.UpdateClientRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	updated, err := s.clientService.UpdateOwned(r.Context(), chi.URLParam(r, "id"), current.ID.String(), request, mutation)
	if err != nil {
		writeOwnedClientUpdateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func writeOwnedClientUpdateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, client.ErrClientOwnerUnavailable), errors.Is(err, pgx.ErrNoRows):
		writeAPIError(w, http.StatusNotFound, "application not found")
	case errors.Is(err, client.ErrOAuthPolicyChanged):
		writeAPIError(w, http.StatusConflict, "OAuth client policy changed; reload and retry")
	case client.IsInvalidClient(err):
		writeAPIError(w, http.StatusBadRequest, err.Error())
	default:
		writeAPIError(w, http.StatusInternalServerError, "failed to update application")
	}
}

func (s *Server) handleUploadMyClientLogo(w http.ResponseWriter, r *http.Request) {
	s.handleClientLogoUpload(w, r, false)
}

func (s *Server) handleUploadAdminClientLogo(w http.ResponseWriter, r *http.Request) {
	s.handleClientLogoUpload(w, r, true)
}

func (s *Server) handleClientLogoUpload(w http.ResponseWriter, r *http.Request, administrator bool) {
	clientID := chi.URLParam(r, "id")
	if !s.clientLogoAccessAllowed(w, r, clientID, administrator) {
		return
	}
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !s.reserveMediaOperation(w, r, securityaction.MediaClientLogoUpload, current.ID) {
		return
	}
	release, ok := s.reserveAvatarProcessing(w, r)
	if !ok {
		return
	}
	defer release()
	contents, err := readSingleImagePart(w, r, "logo")
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.Is(err, avatar.ErrImageTooLarge) || errors.As(err, &maxBytesErr) {
			writeAPIError(w, http.StatusRequestEntityTooLarge, avatar.ErrImageTooLarge.Error())
		} else {
			writeAPIError(w, http.StatusBadRequest, "request must contain exactly one logo file")
		}
		return
	}
	if _, err := s.avatarService.UploadClientLogo(r.Context(), clientID, bytes.NewReader(contents), time.Now().UTC()); err != nil {
		writeAvatarOperationError(w, err)
		return
	}
	updated, err := s.clientService.GetByID(r.Context(), clientID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "logo was updated but the application could not be reloaded")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteMyClientLogo(w http.ResponseWriter, r *http.Request) {
	s.handleClientLogoDelete(w, r, false)
}

func (s *Server) handleDeleteAdminClientLogo(w http.ResponseWriter, r *http.Request) {
	s.handleClientLogoDelete(w, r, true)
}

func (s *Server) handleClientLogoDelete(w http.ResponseWriter, r *http.Request, administrator bool) {
	clientID := chi.URLParam(r, "id")
	if !s.clientLogoAccessAllowed(w, r, clientID, administrator) {
		return
	}
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !s.reserveMediaOperation(w, r, securityaction.MediaClientLogoDelete, current.ID) {
		return
	}
	if _, err := s.avatarService.DeleteClientLogo(r.Context(), clientID, time.Now().UTC()); err != nil {
		writeAvatarOperationError(w, err)
		return
	}
	updated, err := s.clientService.GetByID(r.Context(), clientID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "logo was removed but the application could not be reloaded")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) clientLogoAccessAllowed(w http.ResponseWriter, r *http.Request, clientID string, administrator bool) bool {
	registered, err := s.clientService.GetByID(r.Context(), clientID)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "application not found")
		return false
	}
	if administrator {
		return true
	}
	current := currentUserFromContext(r)
	if current == nil || registered.OwnerID == nil || *registered.OwnerID != current.ID.String() {
		writeAPIError(w, http.StatusNotFound, "application not found")
		return false
	}
	return true
}
