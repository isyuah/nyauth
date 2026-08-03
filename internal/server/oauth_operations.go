package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/nyasharp/nyauth/internal/oauthops"
	"github.com/nyasharp/nyauth/pkg/models"
)

func (s *Server) handleGetMyClient(w http.ResponseWriter, r *http.Request) {
	registered, ok := s.ownedClient(w, r)
	if !ok {
		return
	}
	setSessionNoStoreHeaders(w)
	writeJSON(w, http.StatusOK, registered)
}

func (s *Server) handleAdminClientInsights(w http.ResponseWriter, r *http.Request) {
	s.handleClientInsights(w, r, true)
}

func (s *Server) handleMyClientInsights(w http.ResponseWriter, r *http.Request) {
	s.handleClientInsights(w, r, false)
}

func (s *Server) handleClientInsights(w http.ResponseWriter, r *http.Request, administrator bool) {
	clientID, ok := s.authorizedClientID(w, r, administrator)
	if !ok {
		return
	}
	days := 30
	if raw := strings.TrimSpace(r.URL.Query().Get("days")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 90 {
			writeAPIError(w, http.StatusBadRequest, "days must be between 1 and 90")
			return
		}
		days = parsed
	}
	result, err := s.oauthOperations.GetInsights(r.Context(), clientID, days)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeAPIError(w, http.StatusNotFound, "application not found")
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to load application insights")
		}
		return
	}
	setSessionNoStoreHeaders(w)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAdminClientDiagnostics(w http.ResponseWriter, r *http.Request) {
	s.handleClientDiagnostics(w, r, true)
}

func (s *Server) handleMyClientDiagnostics(w http.ResponseWriter, r *http.Request) {
	s.handleClientDiagnostics(w, r, false)
}

func (s *Server) handleClientDiagnostics(w http.ResponseWriter, r *http.Request, administrator bool) {
	clientID, ok := s.authorizedClientID(w, r, administrator)
	if !ok {
		return
	}
	query := r.URL.Query()
	page, _ := strconv.Atoi(query.Get("page"))
	pageSize, _ := strconv.Atoi(query.Get("page_size"))
	filter := oauthops.DiagnosticFilter{
		ClientID: clientID, Flow: query.Get("flow"), Stage: query.Get("stage"), Reason: query.Get("reason"),
		Page: page, PageSize: pageSize,
	}
	if (filter.Flow != "" && !oauthops.ValidFlow(filter.Flow)) ||
		(filter.Stage != "" && !oauthops.ValidStage(filter.Stage)) ||
		(filter.Reason != "" && !oauthops.ValidReason(filter.Reason)) {
		writeAPIError(w, http.StatusBadRequest, "invalid application diagnostic filter")
		return
	}
	result, err := s.oauthOperations.ListDiagnostics(r.Context(), filter)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load application diagnostics")
		return
	}
	setSessionNoStoreHeaders(w)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) authorizedClientID(w http.ResponseWriter, r *http.Request, administrator bool) (string, bool) {
	clientID := strings.TrimSpace(chi.URLParam(r, "id"))
	if administrator {
		if _, err := s.clientService.GetByID(r.Context(), clientID); err != nil {
			writeAPIError(w, http.StatusNotFound, "application not found")
			return "", false
		}
		return clientID, true
	}
	registered, ok := s.ownedClient(w, r)
	if !ok {
		return "", false
	}
	return registered.ID, true
}

func (s *Server) ownedClient(w http.ResponseWriter, r *http.Request) (*models.OAuthClient, bool) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	registered, err := s.clientService.GetByID(r.Context(), strings.TrimSpace(chi.URLParam(r, "id")))
	if err != nil || registered.OwnerID == nil || *registered.OwnerID != current.ID.String() {
		writeAPIError(w, http.StatusNotFound, "application not found")
		return nil, false
	}
	return registered, true
}
