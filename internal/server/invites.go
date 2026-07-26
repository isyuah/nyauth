package server

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/invite"
	"github.com/nyasharp/nyauth/pkg/models"
)

func (s *Server) handleListInvites(w http.ResponseWriter, r *http.Request) {
	invites, err := s.inviteStore.List(r.Context(), 200)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to list invites")
		return
	}
	now := time.Now().UTC()
	for index := range invites {
		invites[index].Status = invites[index].StatusAt(now)
	}
	writeJSON(w, http.StatusOK, invites)
}

func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !s.requireRecentAuthentication(w, r) {
		return
	}
	var request models.CreateInviteRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	reg := s.settingsMgr.Registration()

	note := strings.TrimSpace(request.Note)
	if utf8.RuneCountInString(note) > registrationNoteLimit {
		writeAPIError(w, http.StatusBadRequest, "note is too long")
		return
	}
	maxUses := request.MaxUses
	if maxUses == 0 {
		maxUses = reg.InviteDefaultMaxUses
	}
	if maxUses < 1 || maxUses > inviteMaxUsesLimit {
		writeAPIError(w, http.StatusBadRequest, "max_uses must be between 1 and 1000")
		return
	}
	ttlRaw := strings.TrimSpace(request.TTL)
	if ttlRaw == "" {
		ttlRaw = reg.InviteDefaultTTL
	}
	ttl, err := time.ParseDuration(ttlRaw)
	if err != nil || ttl < inviteMinTTL || ttl > inviteMaxTTL {
		writeAPIError(w, http.StatusBadRequest, "ttl must be a duration between 1h and 8760h")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}

	code, err := invite.GenerateCode()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to generate invite code")
		return
	}
	now := time.Now().UTC()
	createdBy := current.ID
	inv := &models.Invite{
		ID: uuid.New(), CodeHash: invite.HashCode(code), CreatedBy: &createdBy,
		Note: note, MaxUses: maxUses, ExpiresAt: now.Add(ttl), CreatedAt: now,
		Status: "active",
	}
	if err := s.inviteStore.Create(r.Context(), inv, mutation); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to create invite")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, models.CreateInviteResponse{
		Invite:      *inv,
		Code:        code,
		RegisterURL: strings.TrimRight(s.cfg.Auth.Issuer, "/") + "/register?invite=" + url.QueryEscape(code),
	})
}

func (s *Server) handleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid invite ID")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	if err := s.inviteStore.Revoke(r.Context(), id, mutation); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeAPIError(w, http.StatusNotFound, "invite not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "failed to revoke invite")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
