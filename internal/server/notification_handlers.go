package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/notification"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	notificationEventsPath      = "/api/notifications/events"
	notificationEventName       = "notifications"
	notificationEventRefresh    = 5 * time.Second
	notificationEventKeepalive  = 10 * time.Second
	notificationEventMaxAge     = 15 * time.Minute
	maxNotificationEventStreams = 100
)

type notificationUnreadResponse struct {
	UnreadCount       int64 `json:"unread_count"`
	NotificationCount int64 `json:"notification_count"`
	AnnouncementCount int64 `json:"announcement_count"`
}

type announcementMutationRequest struct {
	ExpectedRevision int64 `json:"expected_revision"`
	notification.AnnouncementInput
}

type announcementTransitionRequest struct {
	ExpectedRevision int64 `json:"expected_revision"`
}

func parsePagination(r *http.Request) (int, int) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	return page, pageSize
}

func parseMessageCenterTime(value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, err
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func (s *Server) handleListMessageCenter(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	page, pageSize := parsePagination(r)
	from, err := parseMessageCenterTime(r.URL.Query().Get("from"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "message start time must use RFC3339")
		return
	}
	to, err := parseMessageCenterTime(r.URL.Query().Get("to"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "message end time must use RFC3339")
		return
	}
	result, err := s.notificationStore.ListMessageCenter(r.Context(), current.ID, current.Role == "admin", notification.MessageCenterOptions{
		Page: page, PageSize: pageSize,
		Kind:     notification.MessageKind(strings.TrimSpace(r.URL.Query().Get("kind"))),
		Read:     notification.MessageReadState(strings.TrimSpace(r.URL.Query().Get("read"))),
		Severity: strings.TrimSpace(r.URL.Query().Get("severity")),
		Query:    r.URL.Query().Get("q"), From: from, To: to,
	})
	if errors.Is(err, notification.ErrInvalidInput) {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load message center")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleMarkAllMessagesRead(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	kind := notification.MessageKind(strings.TrimSpace(r.URL.Query().Get("kind")))
	if err := s.notificationStore.MarkAllMessagesRead(r.Context(), current.ID, current.Role == "admin", kind); errors.Is(err, notification.ErrInvalidInput) {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	} else if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to mark messages read")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListAnnouncements(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	page, pageSize := parsePagination(r)
	result, err := s.notificationStore.ListForUser(r.Context(), current.ID, current.Role == "admin", notification.ListOptions{Page: page, PageSize: pageSize})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load announcements")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetAnnouncement(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid announcement ID")
		return
	}
	item, err := s.notificationStore.GetForUser(r.Context(), id, current.ID, current.Role == "admin")
	if errors.Is(err, notification.ErrNotFound) {
		writeAPIError(w, http.StatusNotFound, "announcement not found")
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load announcement")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleMarkAnnouncementRead(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid announcement ID")
		return
	}
	if err := s.notificationStore.MarkAnnouncementRead(r.Context(), id, current.ID, current.Role == "admin"); errors.Is(err, notification.ErrNotFound) {
		writeAPIError(w, http.StatusNotFound, "announcement not found")
		return
	} else if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to mark announcement read")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListNotifications(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	page, pageSize := parsePagination(r)
	unreadOnly := r.URL.Query().Get("unread") == "true"
	result, err := s.notificationStore.ListNotifications(r.Context(), current.ID, unreadOnly, page, pageSize)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load notifications")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) notificationUnreadResponse(ctx context.Context, current *models.User) (notificationUnreadResponse, error) {
	notificationCount, err := s.notificationStore.UnreadCount(ctx, current.ID)
	if err != nil {
		return notificationUnreadResponse{}, err
	}
	announcementCount, err := s.notificationStore.UnreadAnnouncementCount(ctx, current.ID, current.Role == "admin")
	if err != nil {
		return notificationUnreadResponse{}, err
	}
	return notificationUnreadResponse{UnreadCount: notificationCount + announcementCount, NotificationCount: notificationCount, AnnouncementCount: announcementCount}, nil
}

func (s *Server) handleNotificationUnreadCount(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	result, err := s.notificationUnreadResponse(r.Context(), current)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load notification count")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleMarkNotificationRead(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid notification ID")
		return
	}
	if err := s.notificationStore.MarkNotificationRead(r.Context(), id, current.ID); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to mark notification read")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMarkAllNotificationsRead(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if err := s.notificationStore.MarkAllNotificationsRead(r.Context(), current.ID); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to mark notifications read")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) claimNotificationStream() bool {
	for {
		current := s.notificationStreams.Load()
		if current >= maxNotificationEventStreams {
			return false
		}
		if s.notificationStreams.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (s *Server) handleNotificationEvents(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !s.claimNotificationStream() {
		w.Header().Set("Retry-After", "30")
		writeAPIError(w, http.StatusTooManyRequests, "too many notification streams")
		return
	}
	defer s.notificationStreams.Add(-1)
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "streaming is unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	last := ""
	send := func() error {
		value, err := s.notificationUnreadResponse(r.Context(), current)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		payload := string(encoded)
		if payload == last {
			return nil
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", notificationEventName, payload); err != nil {
			return err
		}
		last = payload
		flusher.Flush()
		return nil
	}
	if err := send(); err != nil {
		return
	}
	refresh := time.NewTicker(notificationEventRefresh)
	keepalive := time.NewTicker(notificationEventKeepalive)
	maxAge := time.NewTimer(notificationEventMaxAge)
	defer refresh.Stop()
	defer keepalive.Stop()
	defer maxAge.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-maxAge.C:
			return
		case <-refresh.C:
			if err := send(); err != nil {
				return
			}
		case <-keepalive.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleAdminListAnnouncements(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePagination(r)
	q := r.URL.Query()
	result, err := s.notificationStore.ListAdmin(r.Context(), notification.ListOptions{Page: page, PageSize: pageSize, Query: q.Get("q"), Status: q.Get("status"), Audience: q.Get("audience"), Severity: q.Get("severity")})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load announcements")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAdminGetAnnouncement(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid announcement ID")
		return
	}
	item, err := s.notificationStore.GetAdmin(r.Context(), id)
	if errors.Is(err, notification.ErrNotFound) {
		writeAPIError(w, http.StatusNotFound, "announcement not found")
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load announcement")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) announcementMutation(w http.ResponseWriter, r *http.Request) (uuid.UUID, audit.MutationAudit, bool) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return uuid.Nil, audit.MutationAudit{}, false
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return uuid.Nil, audit.MutationAudit{}, false
	}
	if raw := chi.URLParam(r, "id"); raw != "" {
		if _, err := uuid.Parse(raw); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid announcement ID")
			return uuid.Nil, audit.MutationAudit{}, false
		}
	}
	return current.ID, mutation, true
}

func (s *Server) handleAdminCreateAnnouncement(w http.ResponseWriter, r *http.Request) {
	actor, mutation, ok := s.announcementMutation(w, r)
	if !ok {
		return
	}
	var input notification.AnnouncementInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	item, err := s.notificationStore.CreateAnnouncement(r.Context(), input, actor, mutation)
	if err != nil {
		if errors.Is(err, notification.ErrInvalidInput) {
			writeAPIError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), notification.ErrInvalidInput.Error()+": "))
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to create announcement")
		}
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) handleAdminUpdateAnnouncement(w http.ResponseWriter, r *http.Request) {
	actor, mutation, ok := s.announcementMutation(w, r)
	if !ok {
		return
	}
	id, _ := uuid.Parse(chi.URLParam(r, "id"))
	var request announcementMutationRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	item, err := s.notificationStore.UpdateAnnouncement(r.Context(), id, request.AnnouncementInput, request.ExpectedRevision, actor, mutation)
	if errors.Is(err, notification.ErrNotFound) {
		writeAPIError(w, http.StatusNotFound, "announcement not found")
		return
	}
	if errors.Is(err, notification.ErrRevisionConflict) {
		writeAPIError(w, http.StatusConflict, "announcement revision conflict")
		return
	}
	if err != nil {
		if errors.Is(err, notification.ErrInvalidInput) {
			writeAPIError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), notification.ErrInvalidInput.Error()+": "))
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to update announcement")
		}
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleAdminPublishAnnouncement(w http.ResponseWriter, r *http.Request) {
	actor, mutation, ok := s.announcementMutation(w, r)
	if !ok {
		return
	}
	id, _ := uuid.Parse(chi.URLParam(r, "id"))
	var request announcementTransitionRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	item, err := s.notificationStore.PublishAnnouncement(r.Context(), id, request.ExpectedRevision, actor, mutation)
	if errors.Is(err, notification.ErrNotFound) {
		writeAPIError(w, http.StatusNotFound, "announcement not found")
		return
	}
	if errors.Is(err, notification.ErrRevisionConflict) {
		writeAPIError(w, http.StatusConflict, "announcement revision conflict")
		return
	}
	if err != nil {
		if errors.Is(err, notification.ErrInvalidTransition) {
			writeAPIError(w, http.StatusConflict, err.Error())
		} else if errors.Is(err, notification.ErrInvalidInput) {
			writeAPIError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), notification.ErrInvalidInput.Error()+": "))
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to publish announcement")
		}
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleAdminArchiveAnnouncement(w http.ResponseWriter, r *http.Request) {
	actor, mutation, ok := s.announcementMutation(w, r)
	if !ok {
		return
	}
	id, _ := uuid.Parse(chi.URLParam(r, "id"))
	var request announcementTransitionRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	item, err := s.notificationStore.ArchiveAnnouncement(r.Context(), id, request.ExpectedRevision, actor, mutation)
	if errors.Is(err, notification.ErrNotFound) {
		writeAPIError(w, http.StatusNotFound, "announcement not found")
		return
	}
	if errors.Is(err, notification.ErrRevisionConflict) {
		writeAPIError(w, http.StatusConflict, "announcement revision conflict")
		return
	}
	if err != nil {
		if errors.Is(err, notification.ErrInvalidTransition) {
			writeAPIError(w, http.StatusConflict, err.Error())
		} else if errors.Is(err, notification.ErrInvalidInput) {
			writeAPIError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), notification.ErrInvalidInput.Error()+": "))
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to archive announcement")
		}
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleAdminPreviewAnnouncement(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input struct {
		BodyMarkdown string `json:"body_markdown"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	html, err := settings.RenderSiteBannerMarkdown(strings.TrimSpace(input.BodyMarkdown))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"body_html": html})
}
